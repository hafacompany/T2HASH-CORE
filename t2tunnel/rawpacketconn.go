package main

import (
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type rawAddr struct {
	ip   net.IP
	port uint16
}

func (a *rawAddr) Network() string { return "raw" }
func (a *rawAddr) String() string {
	return a.ip.String() + ":" + itoa(int(a.port))
}

type rawPacketConn struct {
	handle  *pcap.Handle
	srcMAC  net.HardwareAddr
	dstMAC  net.HardwareAddr
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16

	peerAddr *rawAddr
	recvCh   chan []byte
	closeCh  chan struct{}
	closeOnce sync.Once

	readDeadline  time.Time
	writeMu       sync.Mutex
	seqNum        uint32
}

func NewRawPacketConn(iface, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16) (*rawPacketConn, error) {
	sMAC, err := net.ParseMAC(srcMAC)
	if err != nil {
		return nil, err
	}
	dMAC, err := net.ParseMAC(dstMAC)
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	filter := "tcp and src host " + dstIP + " and src port " + itoa(int(dstPort)) +
		" and dst port " + itoa(int(srcPort))
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, err
	}

	c := &rawPacketConn{
		handle:  handle,
		srcMAC:  sMAC,
		dstMAC:  dMAC,
		srcIP:   net.ParseIP(srcIP).To4(),
		dstIP:   net.ParseIP(dstIP).To4(),
		srcPort: srcPort,
		dstPort: dstPort,
		peerAddr: &rawAddr{ip: net.ParseIP(dstIP).To4(), port: dstPort},
		recvCh:  make(chan []byte, 1024),
		closeCh: make(chan struct{}),
		seqNum:  1000,
	}

	go c.readLoop()

	return c, nil
}

func (c *rawPacketConn) readLoop() {
	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	for {
		select {
		case <-c.closeCh:
			return
		case packet, ok := <-src.Packets():
			if !ok {
				return
			}
			app := packet.ApplicationLayer()
			if app == nil || len(app.Payload()) == 0 {
				continue
			}
			data := make([]byte, len(app.Payload()))
			copy(data, app.Payload())
			select {
			case c.recvCh <- data:
			case <-c.closeCh:
				return
			default:
			}
		}
	}
}

func (c *rawPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var timeout <-chan time.Time
	if !c.readDeadline.IsZero() {
		d := time.Until(c.readDeadline)
		if d <= 0 {
			return 0, nil, &timeoutErr{}
		}
		timeout = time.After(d)
	}

	select {
	case <-c.closeCh:
		return 0, nil, net.ErrClosed
	case data := <-c.recvCh:
		n := copy(p, data)
		return n, c.peerAddr, nil
	case <-timeout:
		return 0, nil, &timeoutErr{}
	}
}

func (c *rawPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	eth := layers.Ethernet{
		SrcMAC:       c.srcMAC,
		DstMAC:       c.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    c.srcIP,
		DstIP:    c.dstIP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(c.srcPort),
		DstPort: layers.TCPPort(c.dstPort),
		PSH:     true,
		ACK:     true,
		Window:  64240,
		Seq:     c.seqNum,
		Ack:     1,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(p)); err != nil {
		return 0, err
	}

	c.seqNum += uint32(len(p))

	if err := c.handle.WritePacketData(buf.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *rawPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		c.handle.Close()
	})
	return nil
}

func (c *rawPacketConn) LocalAddr() net.Addr {
	return &rawAddr{ip: c.srcIP, port: c.srcPort}
}

func (c *rawPacketConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *rawPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *rawPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type timeoutErr struct{}

func (e *timeoutErr) Error() string   { return "i/o timeout" }
func (e *timeoutErr) Timeout() bool   { return true }
func (e *timeoutErr) Temporary() bool { return true }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
