package main

import (
	"log"
	"net"
	"sync"

	"github.com/xtaci/smux"
)

func runServerWS(listen, target, path, sni string, useTLS bool) {
	ln, err := NewWSListener(listen, path, sni, useTLS)
	if err != nil {
		log.Fatalf("[!] خطا در WS listener: %v", err)
	}
	scheme := "ws"
	if useTLS {
		scheme = "wss"
	}
	log.Printf("[+] T2HASH server (WS/%s) روی %s%s — مقصد: %s", scheme, listen, path, target)
	log.Printf("    آماده‌ی عبور از CDN (Cloudflare / ArvanCloud)")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[!] accept error: %v", err)
			return
		}
		go handleTLSServerSession(conn, target)
	}
}

func runClientWS(listen, remote, host, path, sni string, useTLS bool) {
	local, err := listenTCP(listen)
	if err != nil {
		log.Fatalf("[!] خطا در listen محلی: %v", err)
	}
	log.Printf("[+] T2HASH client (WS) روی %s — سرور: %s%s", listen, remote, path)
	if host != "" {
		log.Printf("    Host: %s  SNI: %s", host, sni)
	}

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
		conn, err := dialWS(remote, host, path, sni, useTLS)
		if err != nil {
			return nil, err
		}
		obfsed := WrapObfs(conn, DefaultObfsConfig())
		s, err := smux.Client(obfsed, smuxConfig())
		if err != nil {
			conn.Close()
			return nil, err
		}
		session = s
		log.Printf("[+] اتصال WS به سرور برقرار شد")
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
