package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

type AutoNetInfo struct {
	Iface      string
	LocalIP    string
	LocalMAC   string
	GatewayIP  string
	GatewayMAC string
}

func AutoDiscover(towardIP string) (*AutoNetInfo, error) {
	info := &AutoNetInfo{}

	out, err := exec.Command("ip", "route", "get", towardIP).Output()
	if err != nil {
		return nil, fmt.Errorf("خطا در ip route get: %v", err)
	}
	
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "via":
			if i+1 < len(fields) {
				info.GatewayIP = fields[i+1]
			}
		case "dev":
			if i+1 < len(fields) {
				info.Iface = fields[i+1]
			}
		case "src":
			if i+1 < len(fields) {
				info.LocalIP = fields[i+1]
			}
		}
	}
	if info.Iface == "" || info.LocalIP == "" {
		return nil, fmt.Errorf("نتونستم اینترفیس یا آی‌پی محلی رو پیدا کنم")
	}

	if info.GatewayIP == "" {
		return nil, fmt.Errorf("gateway پیدا نشد (مقصد ممکنه محلی باشه)")
	}

	iface, err := net.InterfaceByName(info.Iface)
	if err != nil {
		return nil, fmt.Errorf("خطا در یافتن اینترفیس %s: %v", info.Iface, err)
	}
	info.LocalMAC = iface.HardwareAddr.String()

	gwMAC, err := findGatewayMAC(info.GatewayIP, info.Iface)
	if err != nil {
		return nil, fmt.Errorf("خطا در یافتن MAC gateway: %v", err)
	}
	info.GatewayMAC = gwMAC

	return info, nil
}

func findGatewayMAC(gwIP, iface string) (string, error) {
	if mac := readNeighMAC(gwIP); mac != "" {
		return mac, nil
	}

	exec.Command("ping", "-c", "1", "-W", "1", gwIP).Run()

	if mac := readNeighMAC(gwIP); mac != "" {
		return mac, nil
	}

	return "", fmt.Errorf("MAC برای gateway %s پیدا نشد", gwIP)
}

func readNeighMAC(ip string) string {
	out, err := exec.Command("ip", "neigh", "show", ip).Output()
	if err == nil {
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "lladdr" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}

	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Scan() 
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == ip {
			mac := fields[3]
			if mac != "00:00:00:00:00:00" {
				return mac
			}
		}
	}
	return ""
}
