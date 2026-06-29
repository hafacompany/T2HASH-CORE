package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

var (
	useUTLS  = false
	fragSize = 0
)

type fragConn struct {
	net.Conn
	firstDone bool
	chunk     int
}

func (c *fragConn) Write(b []byte) (int, error) {
	if c.firstDone || c.chunk <= 0 {
		return c.Conn.Write(b)
	}
	c.firstDone = true
	total := 0
	for i := 0; i < len(b); i += c.chunk {
		end := i + c.chunk
		if end > len(b) {
			end = len(b)
		}
		n, err := c.Conn.Write(b[i:end])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func generateSelfSignedCert(sni string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: sni,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{sni},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

type TLSListener struct {
	net.Listener
}

func NewTLSListener(addr, sni string) (*TLSListener, error) {
	cert, err := generateSelfSignedCert(sni)
	if err != nil {
		return nil, fmt.Errorf("خطا در ساخت سرت: %v", err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
	ln, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	return &TLSListener{Listener: ln}, nil
}

func dialTLS(addr, sni string) (net.Conn, error) {
	if !useUTLS && fragSize <= 0 {
		config := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(15 * time.Second)
	}
	var under net.Conn = raw
	if fragSize > 0 {
		under = &fragConn{Conn: raw, chunk: fragSize}
	}
	if useUTLS {
		uconn := utls.UClient(under, &utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		}, utls.HelloChrome_Auto)
		if err := uconn.Handshake(); err != nil {
			raw.Close()
			return nil, fmt.Errorf("uTLS handshake: %v", err)
		}
		return uconn, nil
	}
	tconn := tls.Client(under, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	})
	if err := tconn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return tconn, nil
}
