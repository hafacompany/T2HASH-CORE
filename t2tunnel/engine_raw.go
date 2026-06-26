package main

import (
	"log"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

type RawParams struct {
	Iface   string
	SrcMAC  string
	GwMAC   string
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

func runServerRaw(target string, block kcp.BlockCrypt, rp RawParams) {
	pconn, err := NewRawPacketConn(rp.Iface, rp.SrcMAC, rp.GwMAC, rp.SrcIP, rp.DstIP, rp.SrcPort, rp.DstPort)
	if err != nil {
		log.Fatalf("[!] خطا در ساخت raw PacketConn: %v", err)
	}
	defer pconn.Close()

	lis, err := kcp.ServeConn(block, kcpDataShards, kcpParityShards, pconn)
	if err != nil {
		log.Fatalf("[!] خطا در KCP serve: %v", err)
	}
	log.Printf("[+] T2HASH server (RAW/QuantumMux) — مقصد: %s", target)
	log.Printf("    کانال خام: %s:%d ← %s:%d", rp.SrcIP, rp.SrcPort, rp.DstIP, rp.DstPort)

	for {
		conn, err := lis.AcceptKCP()
		if err != nil {
			log.Printf("[!] accept error: %v", err)
			return
		}
		applyKCP(conn)
		go handleServerSession(conn, target)
	}
}

func runClientRaw(listen string, block kcp.BlockCrypt, rp RawParams) {
	local, err := listenTCP(listen)
	if err != nil {
		log.Fatalf("[!] خطا در listen محلی: %v", err)
	}
	log.Printf("[+] T2HASH client (RAW/QuantumMux) روی %s", listen)
	log.Printf("    کانال خام: %s:%d → %s:%d", rp.SrcIP, rp.SrcPort, rp.DstIP, rp.DstPort)

	peer := &rawAddr{ip: net.ParseIP(rp.DstIP).To4(), port: rp.DstPort}

	var session *smux.Session

	getSession := func() (*smux.Session, error) {
		if session != nil && !session.IsClosed() {
			return session, nil
		}
		
		pconn, err := NewRawPacketConn(rp.Iface, rp.SrcMAC, rp.GwMAC, rp.SrcIP, rp.DstIP, rp.SrcPort, rp.DstPort)
		if err != nil {
			return nil, err
		}
		conn, err := kcp.NewConn3(1, peer, block, kcpDataShards, kcpParityShards, pconn)
		if err != nil {
			pconn.Close()
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
		log.Printf("[+] اتصال KCP (RAW) به سرور برقرار شد")
		return session, nil
	}

	for {
		c, err := local.Accept()
		if err != nil {
			log.Printf("[!] accept محلی error: %v", err)
			continue
		}
		go func(client net.Conn) {
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
