package main

import (
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

const (
	kcpDataShards   = 10
	kcpParityShards = 3
	kcpMTU          = 1350
	kcpSndWnd       = 512
	kcpRcvWnd       = 512
	kcpNoDelay      = 1
	kcpInterval     = 20
	kcpResend       = 2
	kcpNoCongestion = 1
)

func applyKCP(conn *kcp.UDPSession) {
	conn.SetStreamMode(true)
	conn.SetWriteDelay(false)
	conn.SetNoDelay(kcpNoDelay, kcpInterval, kcpResend, kcpNoCongestion)
	conn.SetWindowSize(kcpSndWnd, kcpRcvWnd)
	conn.SetMtu(kcpMTU)
	conn.SetACKNoDelay(true)
}

func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveInterval = 8 * time.Second
	c.KeepAliveTimeout = 24 * time.Second
	c.MaxFrameSize = 32768
	c.MaxReceiveBuffer = 8 * 1024 * 1024
	c.MaxStreamBuffer = 4 * 1024 * 1024
	return c
}

func pipe(a, b io.ReadWriteCloser) {
	var once sync.Once
	closeBoth := func() { a.Close(); b.Close() }

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		once.Do(closeBoth)
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		once.Do(closeBoth)
	}()
	wg.Wait()
}

func main() {
	mode := flag.String("mode", "", "server | client")
	listen := flag.String("listen", "", "آدرس listen محلی")
	target := flag.String("target", "", "[server] مقصد نهایی، مثلا 127.0.0.1:443")
	remote := flag.String("remote", "", "[client] آدرس سرور تونل، مثلا IRAN_IP:4000")
	key := flag.String("key", "", "کلید مشترک (PSK) — دو طرف باید یکی باشه")

	transport := flag.String("transport", "udp", "udp | raw | tls")
	iface := flag.String("iface", "", "[raw] اینترفیس شبکه (خالی = خودکار)")
	srcMAC := flag.String("srcmac", "", "[raw] MAC ما (خالی = خودکار)")
	gwMAC := flag.String("gwmac", "", "[raw] MAC gateway (خالی = خودکار)")
	srcIP := flag.String("srcip", "", "[raw] آی‌پی ما (خالی = خودکار)")
	dstIP := flag.String("dstip", "", "[raw] آی‌پی طرف مقابل")
	srcPort := flag.Int("srcport", 0, "[raw] پورت ما")
	dstPort := flag.Int("dstport", 0, "[raw] پورت طرف مقابل")
	noAutoIPT := flag.Bool("no-auto-iptables", false, "[raw] قوانین iptables رو خودکار اضافه نکن")
	sni := flag.String("sni", "www.cloudflare.com", "[tls] دامنه‌ی SNI برای شبیه‌سازی HTTPS")
	remotes := flag.String("remotes", "", "[tls multi-path] چند سرور با کاما جدا، مثلا ip1:443,ip2:443")
	wsPath := flag.String("ws-path", "/", "[ws] مسیر WebSocket (باید با CDN یکی باشه)")
	wsHost := flag.String("ws-host", "", "[ws client] هدر Host / دامنه‌ی پشت CDN")
	wsTLS := flag.Bool("ws-tls", true, "[ws] استفاده از TLS (wss). برای پشت Cloudflare/Arvan روشن باشه")
	flag.Parse()

	if *key == "" {
		log.Fatal("[!] -key الزامیه (دو طرف باید یکسان باشه)")
	}

	block, err := kcp.NewAESBlockCrypt(pad32([]byte(*key)))
	if err != nil {
		log.Fatalf("[!] خطا در ساخت crypt: %v", err)
	}

	if *transport == "raw" {
		if *dstIP == "" {
			log.Fatal("[!] حالت raw نیاز به -dstip (آی‌پی طرف مقابل) داره")
		}
		if *srcMAC == "" || *gwMAC == "" || *srcIP == "" || *iface == "" {
			log.Printf("[*] کشف خودکار پارامترهای شبکه به سمت %s ...", *dstIP)
			ni, err := AutoDiscover(*dstIP)
			if err != nil {
				log.Fatalf("[!] کشف خودکار شکست خورد: %v\n    می‌تونی دستی بدی: -iface -srcmac -gwmac -srcip", err)
			}
			if *iface == "" {
				*iface = ni.Iface
			}
			if *srcMAC == "" {
				*srcMAC = ni.LocalMAC
			}
			if *gwMAC == "" {
				*gwMAC = ni.GatewayMAC
			}
			if *srcIP == "" {
				*srcIP = ni.LocalIP
			}
			log.Printf("[+] کشف شد: iface=%s ip=%s mac=%s gw_mac=%s",
				*iface, *srcIP, *srcMAC, *gwMAC)
		}
	}

	rp := RawParams{
		Iface:   *iface,
		SrcMAC:  *srcMAC,
		GwMAC:   *gwMAC,
		SrcIP:   *srcIP,
		DstIP:   *dstIP,
		SrcPort: uint16(*srcPort),
		DstPort: uint16(*dstPort),
	}

	rawValid := func() bool {
		return *srcMAC != "" && *gwMAC != "" && *srcIP != "" && *dstIP != "" && *srcPort != 0 && *dstPort != 0
	}

	var ipt *IPTablesManager
	if *transport == "raw" && !*noAutoIPT && *srcPort != 0 {
		ipt = NewIPTablesManager(uint16(*srcPort))
		if err := ipt.Apply(); err != nil {
			log.Printf("[!] هشدار: نتونستم iptables رو خودکار تنظیم کنم: %v", err)
			log.Printf("    شاید لازم باشه دستی بزنی یا با sudo اجرا کنی")
		} else {
			log.Printf("[+] قوانین iptables برای پورت %d اضافه شد", *srcPort)
		}
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			log.Printf("[*] دریافت سیگنال خروج، پاک کردن iptables...")
			if ipt != nil {
				ipt.Cleanup()
				log.Printf("[*] قوانین iptables پاک شد")
			}
			os.Exit(0)
		}()
	}

	switch *mode {
	case "server":
		if *target == "" {
			log.Fatal("[!] server نیاز به -target داره")
		}
		switch *transport {
		case "raw":
			if !rawValid() {
				log.Fatal("[!] حالت raw نیاز به -srcmac -gwmac -srcip -dstip -srcport -dstport داره")
			}
			runServerRaw(*target, block, rp)
		case "tls":
			if *listen == "" {
				log.Fatal("[!] server (tls) نیاز به -listen داره")
			}
			runServerTLS(*listen, *target, *sni)
		case "ws":
			if *listen == "" {
				log.Fatal("[!] server (ws) نیاز به -listen داره")
			}
			runServerWS(*listen, *target, *wsPath, *sni, *wsTLS)
		default:
			if *listen == "" {
				log.Fatal("[!] server (udp) نیاز به -listen داره")
			}
			runServer(*listen, *target, block)
		}
	case "client":
		if *listen == "" {
			log.Fatal("[!] client نیاز به -listen داره")
		}
		switch *transport {
		case "raw":
			if !rawValid() {
				log.Fatal("[!] حالت raw نیاز به -srcmac -gwmac -srcip -dstip -srcport -dstport داره")
			}
			runClientRaw(*listen, block, rp)
		case "tls":
			if *remotes != "" {
				addrs := strings.Split(*remotes, ",")
				var servers []*ServerEndpoint
				for _, a := range addrs {
					a = strings.TrimSpace(a)
					if a == "" {
						continue
					}
					servers = append(servers, &ServerEndpoint{Address: a, SNI: *sni})
				}
				if len(servers) == 0 {
					log.Fatal("[!] -remotes خالیه")
				}
				mp := NewMultiPathClient(*listen, servers)
				mp.Run()
			} else {
				if *remote == "" {
					log.Fatal("[!] client (tls) نیاز به -remote یا -remotes داره")
				}
				runClientTLS(*listen, *remote, *sni)
			}
		case "ws":
			if *remotes != "" {
				addrs := strings.Split(*remotes, ",")
				var servers []*ServerEndpoint
				for _, a := range addrs {
					a = strings.TrimSpace(a)
					if a == "" {
						continue
					}
					servers = append(servers, &ServerEndpoint{
						Address: a, SNI: *sni, Transport: "ws",
						WSPath: *wsPath, WSHost: *wsHost, WSTLS: *wsTLS,
					})
				}
				if len(servers) == 0 {
					log.Fatal("[!] -remotes خالیه")
				}
				mp := NewMultiPathClient(*listen, servers)
				mp.Run()
			} else {
				if *remote == "" {
					log.Fatal("[!] client (ws) نیاز به -remote یا -remotes داره")
				}
				runClientWS(*listen, *remote, *wsHost, *wsPath, *sni, *wsTLS)
			}
		default:
			if *remote == "" {
				log.Fatal("[!] client (udp) نیاز به -remote داره")
			}
			runClient(*listen, *remote, block)
		}
	default:
		log.Fatal("[!] -mode باید server یا client باشه")
	}
}

func pad32(k []byte) []byte {
	out := make([]byte, 32)
	copy(out, k)
	return out
}

func runServer(listen, target string, block kcp.BlockCrypt) {
	lis, err := kcp.ListenWithOptions(listen, block, kcpDataShards, kcpParityShards)
	if err != nil {
		log.Fatalf("[!] خطا در listen: %v", err)
	}
	log.Printf("[+] T2HASH server روی %s — مقصد: %s", listen, target)

	for {
		conn, err := lis.AcceptKCP()
		if err != nil {
			log.Printf("[!] accept error: %v", err)
			continue
		}
		applyKCP(conn)
		go handleServerSession(conn, target)
	}
}

func handleServerSession(conn *kcp.UDPSession, target string) {
	defer conn.Close()
	log.Printf("[+] session جدید از %s", conn.RemoteAddr())

	obfsed := WrapObfs(conn, DefaultObfsConfig())

	session, err := smux.Server(obfsed, smuxConfig())
	if err != nil {
		log.Printf("[!] smux server error: %v", err)
		return
	}
	defer session.Close()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		go func(s *smux.Stream) {
			defer s.Close()
			out, err := dialTCP(target)
			if err != nil {
				log.Printf("[!] خطا در اتصال به target: %v", err)
				return
			}
			pipe(s, out)
		}(stream)
	}
}

func runClient(listen, remote string, block kcp.BlockCrypt) {
	local, err := listenTCP(listen)
	if err != nil {
		log.Fatalf("[!] خطا در listen محلی: %v", err)
	}
	log.Printf("[+] T2HASH client روی %s — سرور: %s", listen, remote)

	var (
		session *smux.Session
		mu      sync.Mutex
	)

	getSession := func() (*smux.Session, error) {
		mu.Lock()
		defer mu.Unlock()
		if session != nil && !session.IsClosed() {
			return session, nil
		}
		conn, err := kcp.DialWithOptions(remote, block, kcpDataShards, kcpParityShards)
		if err != nil {
			return nil, err
		}
		applyKCP(conn)
		obfsed := WrapObfs(conn, DefaultObfsConfig())
		s, err := smux.Client(obfsed, smuxConfig())
		if err != nil {
			conn.Close()
			return nil, err
		}
		session = s
		log.Printf("[+] اتصال KCP به سرور برقرار شد")
		return session, nil
	}

	for {
		c, err := local.Accept()
		if err != nil {
			log.Printf("[!] accept محلی error: %v", err)
			continue
		}
		go func(client io.ReadWriteCloser) {
			s, err := getSession()
			if err != nil {
				log.Printf("[!] خطا در session: %v", err)
				client.Close()
				return
			}
			stream, err := s.OpenStream()
			if err != nil {
				log.Printf("[!] خطا در باز کردن stream: %v", err)
				client.Close()
				return
			}
			pipe(client, stream)
		}(c)
	}
}
