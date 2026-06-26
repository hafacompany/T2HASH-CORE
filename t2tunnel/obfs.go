package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"time"
)

type ObfsConfig struct {
	Enabled    bool
	MinPadding int
	MaxPadding int
	MinDelay   time.Duration
	MaxDelay   time.Duration
}

func DefaultObfsConfig() ObfsConfig {
	return ObfsConfig{
		Enabled:    true,
		MinPadding: 16,
		MaxPadding: 256,
		MinDelay:   0,
		MaxDelay:   3 * time.Millisecond,
	}
}

type obfsConn struct {
	net.Conn
	cfg     ObfsConfig
	readBuf []byte
}

func WrapObfs(c net.Conn, cfg ObfsConfig) net.Conn {
	if !cfg.Enabled {
		return c
	}
	return &obfsConn{Conn: c, cfg: cfg}
}

func (o *obfsConn) Write(p []byte) (int, error) {
	padLen := 0
	if o.cfg.MaxPadding > o.cfg.MinPadding {
		padLen = o.cfg.MinPadding + mathrand.Intn(o.cfg.MaxPadding-o.cfg.MinPadding)
	} else {
		padLen = o.cfg.MinPadding
	}

	pad := make([]byte, padLen)
	rand.Read(pad)

	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(p)))
	binary.BigEndian.PutUint16(header[2:4], uint16(padLen))

	frame := make([]byte, 0, 4+len(p)+padLen)
	frame = append(frame, header...)
	frame = append(frame, p...)
	frame = append(frame, pad...)

	o.applyJitter()

	if _, err := o.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (o *obfsConn) Read(p []byte) (int, error) {
	if len(o.readBuf) > 0 {
		n := copy(p, o.readBuf)
		o.readBuf = o.readBuf[n:]
		return n, nil
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(o.Conn, header); err != nil {
		return 0, err
	}
	dataLen := binary.BigEndian.Uint16(header[0:2])
	padLen := binary.BigEndian.Uint16(header[2:4])

	data := make([]byte, dataLen)
	if _, err := io.ReadFull(o.Conn, data); err != nil {
		return 0, err
	}

	if padLen > 0 {
		pad := make([]byte, padLen)
		if _, err := io.ReadFull(o.Conn, pad); err != nil {
			return 0, err
		}
	}

	n := copy(p, data)
	if n < len(data) {
		o.readBuf = data[n:]
	}
	return n, nil
}

func (o *obfsConn) applyJitter() {
	if o.cfg.MaxDelay <= 0 {
		return
	}
	delta := o.cfg.MaxDelay - o.cfg.MinDelay
	if delta <= 0 {
		time.Sleep(o.cfg.MinDelay)
		return
	}
	jitter := o.cfg.MinDelay + time.Duration(mathrand.Int63n(int64(delta)))
	time.Sleep(jitter)
}

func (o *obfsConn) String() string {
	return fmt.Sprintf("obfsConn(pad=%d-%d, delay=%v-%v)",
		o.cfg.MinPadding, o.cfg.MaxPadding, o.cfg.MinDelay, o.cfg.MaxDelay)
}
