package main

import (
	"fmt"
	"os/exec"
)

type iptablesRule struct {
	table string
	args  []string
}

type IPTablesManager struct {
	rules []iptablesRule
}

func NewIPTablesManager(port uint16) *IPTablesManager {
	p := fmt.Sprintf("%d", port)
	return &IPTablesManager{
		rules: []iptablesRule{
			{table: "filter", args: []string{"OUTPUT", "-p", "tcp", "--sport", p, "--tcp-flags", "RST", "RST", "-j", "DROP"}},
			{table: "raw", args: []string{"OUTPUT", "-p", "tcp", "--sport", p, "-j", "NOTRACK"}},
			{table: "raw", args: []string{"PREROUTING", "-p", "tcp", "--dport", p, "-j", "NOTRACK"}},
		},
	}
}

func (m *IPTablesManager) Apply() error {
	for _, r := range m.rules {
		checkArgs := append([]string{"-t", r.table, "-C"}, r.args...)
		if exec.Command("iptables", checkArgs...).Run() == nil {
			continue
		}
		addArgs := append([]string{"-t", r.table, "-A"}, r.args...)
		if out, err := exec.Command("iptables", addArgs...).CombinedOutput(); err != nil {
			return fmt.Errorf("خطا در افزودن قانون iptables: %v (%s)", err, string(out))
		}
	}
	return nil
}

func (m *IPTablesManager) Cleanup() {
	for _, r := range m.rules {
		delArgs := append([]string{"-t", r.table, "-D"}, r.args...)
		exec.Command("iptables", delArgs...).Run()
	}
}
