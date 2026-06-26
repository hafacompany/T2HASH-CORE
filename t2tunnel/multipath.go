package main

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

type ServerEndpoint struct {
	Address   string
	SNI       string
	Transport string
	WSPath    string
	WSHost    string
	WSTLS     bool
	failCount int32
	lastFail  time.Time
}

type MultiPathClient struct {
	servers    []*ServerEndpoint
	current    int32
	listen     string
	session    *smux.Session
	sessionSrv *ServerEndpoint
	mu         sync.Mutex
}

func NewMultiPathClient(listen string, servers []*ServerEndpoint) *MultiPathClient {
	return &MultiPathClient{
		servers: servers,
		listen:  listen,
	}
}

func (m *MultiPathClient) Run() {
	local, err := listenTCP(m.listen)
	if err != nil {
		log.Fatalf("[!] خطا در listen محلی: %v", err)
	}
	log.Printf("[+] T2HASH Multi-Path client روی %s", m.listen)
	log.Printf("    تعداد سرورها: %d (failover خودکار)", len(m.servers))
	for i, s := range m.servers {
		log.Printf("    سرور %d: %s (SNI: %s)", i+1, s.Address, s.SNI)
	}

	for {
		c, err := local.Accept()
		if err != nil {
			log.Printf("[!] accept محلی error: %v", err)
			continue
		}
		go m.handleConn(c)
	}
}

func (m *MultiPathClient) handleConn(client net.Conn) {
	s, srv, err := m.getSession()
	if err != nil {
		log.Printf("[!] هیچ سروری در دسترس نیست: %v", err)
		client.Close()
		return
	}

	stream, err := s.OpenStream()
	if err != nil {
		log.Printf("[!] stream از سرور %s باز نشد، failover...", srv.Address)
		m.markFailed(srv)
		client.Close()
		return
	}
	pipe(client, stream)
}

func (m *MultiPathClient) getSession() (*smux.Session, *ServerEndpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.session != nil && !m.session.IsClosed() {
		return m.session, m.sessionSrv, nil
	}

	n := len(m.servers)
	start := int(atomic.LoadInt32(&m.current))

	for i := 0; i < n; i++ {
		idx := (start + i) % n
		srv := m.servers[idx]

		if time.Since(srv.lastFail) < 30*time.Second && atomic.LoadInt32(&srv.failCount) >= 3 {
			continue
		}

		log.Printf("[*] تلاش برای اتصال به سرور %d: %s", idx+1, srv.Address)
		var conn net.Conn
		var err error
		if srv.Transport == "ws" {
			conn, err = dialWS(srv.Address, srv.WSHost, srv.WSPath, srv.SNI, srv.WSTLS)
		} else {
			conn, err = dialTLS(srv.Address, srv.SNI)
		}
		if err != nil {
			log.Printf("[!] اتصال به %s شکست خورد: %v", srv.Address, err)
			m.markFailedLocked(srv)
			continue
		}

		obfsed := WrapObfs(conn, DefaultObfsConfig())
		sess, err := smux.Client(obfsed, smuxConfig())
		if err != nil {
			conn.Close()
			m.markFailedLocked(srv)
			continue
		}

		m.session = sess
		m.sessionSrv = srv
		atomic.StoreInt32(&m.current, int32(idx))
		atomic.StoreInt32(&srv.failCount, 0)
		log.Printf("[+] متصل شد به سرور %d: %s", idx+1, srv.Address)
		return sess, srv, nil
	}

	return nil, nil, errAllServersDown
}

func (m *MultiPathClient) markFailed(srv *ServerEndpoint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.markFailedLocked(srv)
	if m.session != nil {
		m.session.Close()
		m.session = nil
	}
}

func (m *MultiPathClient) markFailedLocked(srv *ServerEndpoint) {
	atomic.AddInt32(&srv.failCount, 1)
	srv.lastFail = time.Now()
}

var errAllServersDown = &simpleError{"همه‌ی سرورها از دسترس خارجن"}

type simpleError struct{ msg string }

func (e *simpleError) Error() string { return e.msg }
