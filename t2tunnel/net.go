package main

import (
	"net"
	"time"
)

func dialTCP(addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 15 * time.Second,
	}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}
	return conn, nil
}

func listenTCP(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
