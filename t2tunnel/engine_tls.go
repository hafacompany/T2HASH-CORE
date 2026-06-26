package main

import (
	"log"
	"net"
	"sync"

	"github.com/xtaci/smux"
)

func runServerTLS(listen, target, sni string) {
	ln, err := NewTLSListener(listen, sni)
	if err != nil {
		log.Fatalf("[!] خطا در TLS listener: %v", err)
	}
	log.Printf("[+] T2HASH server (TLS/Mimicry) روی %s — مقصد: %s", listen, target)
	log.Printf("    SNI: %s (شبیه HTTPS به این دامنه)", sni)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[!] accept error: %v", err)
			continue
		}
		go handleTLSServerSession(conn, target)
	}
}

func handleTLSServerSession(conn net.Conn, target string) {
	defer conn.Close()
	log.Printf("[+] session TLS جدید از %s", conn.RemoteAddr())

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

func runClientTLS(listen, remote, sni string) {
	local, err := listenTCP(listen)
	if err != nil {
		log.Fatalf("[!] خطا در listen محلی: %v", err)
	}
	log.Printf("[+] T2HASH client (TLS/Mimicry) روی %s — سرور: %s", listen, remote)
	log.Printf("    SNI: %s", sni)

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
		conn, err := dialTLS(remote, sni)
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
		log.Printf("[+] اتصال TLS به سرور برقرار شد")
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
