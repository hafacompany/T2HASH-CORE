package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type wsConn struct {
	c   *websocket.Conn
	r   io.Reader
	wmu sync.Mutex
}

func newWSConn(c *websocket.Conn) *wsConn { return &wsConn{c: c} }

func (w *wsConn) Read(p []byte) (int, error) {
	for {
		if w.r == nil {
			mt, r, err := w.c.NextReader()
			if err != nil {
				return 0, err
			}
			if mt != websocket.BinaryMessage {
				continue
			}
			w.r = r
		}
		n, err := w.r.Read(p)
		if err == io.EOF {
			w.r = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (w *wsConn) Write(p []byte) (int, error) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if err := w.c.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) Close() error                       { return w.c.Close() }
func (w *wsConn) LocalAddr() net.Addr                { return w.c.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr               { return w.c.RemoteAddr() }
func (w *wsConn) SetDeadline(t time.Time) error      { _ = w.c.SetReadDeadline(t); return w.c.SetWriteDeadline(t) }
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }

type WSListener struct {
	accept chan net.Conn
	closer chan struct{}
	once   sync.Once
	srv    *http.Server
	addr   net.Addr
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:   32 * 1024,
	WriteBufferSize:  32 * 1024,
	HandshakeTimeout: 12 * time.Second,
	CheckOrigin:      func(*http.Request) bool { return true },
}

const fakePage = "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is working.</p></body></html>"

func NewWSListener(addr, path, sni string, useTLS bool) (*WSListener, error) {
	if path == "" {
		path = "/"
	}
	l := &WSListener{
		accept: make(chan net.Conn, 64),
		closer: make(chan struct{}),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path && websocket.IsWebSocketUpgrade(r) {
			c, err := wsUpgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			select {
			case l.accept <- newWSConn(c):
			case <-l.closer:
				c.Close()
			}
			return
		}
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", strconv.Itoa(len(fakePage)))
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, fakePage)
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l.addr = ln.Addr()
	l.srv = &http.Server{
		Handler:      handler,
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  90 * time.Second,
	}

	if useTLS {
		cert, err := generateSelfSignedCert(sni)
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("خطا در ساخت سرت: %v", err)
		}
		l.srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
		}
		go func() {
			if err := l.srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
				log.Printf("[!] WS(TLS) serve متوقف شد: %v", err)
			}
		}()
	} else {
		go func() {
			if err := l.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("[!] WS serve متوقف شد: %v", err)
			}
		}()
	}

	return l, nil
}

func (l *WSListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closer:
		return nil, net.ErrClosed
	}
}

func (l *WSListener) Close() error {
	l.once.Do(func() {
		close(l.closer)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		l.srv.Shutdown(ctx)
	})
	return nil
}

func (l *WSListener) Addr() net.Addr { return l.addr }

func dialWS(remote, host, path, sni string, useTLS bool) (net.Conn, error) {
	if path == "" {
		path = "/"
	}
	scheme := "ws"
	if useTLS {
		scheme = "wss"
	}
	u := url.URL{Scheme: scheme, Host: remote, Path: path}

	d := websocket.Dialer{
		HandshakeTimeout: 12 * time.Second,
		NetDial: func(network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}).Dial(network, addr)
		},
	}
	if useTLS {
		d.TLSClientConfig = &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
		}
		// when uTLS/frag are enabled, do the TLS handshake ourselves so the
		// CDN sees a real Chrome fingerprint (and optionally a fragmented hello)
		if useUTLS || fragSize > 0 {
			d.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialTLS(addr, sni)
			}
		}
	}

	hdr := http.Header{}
	if host != "" {
		hdr.Set("Host", host)
	}

	c, _, err := d.Dial(u.String(), hdr)
	if err != nil {
		return nil, err
	}
	return newWSConn(c), nil
}
