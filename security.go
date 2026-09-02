package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Probing firewall rulesets usually needs root, so Known=false is common.
type firewallState struct {
	Known   bool
	Enabled bool
	Detail  string
}

func printSecurityNotes(infos []PortInfo) {
	if len(infos) == 0 {
		return
	}
	fw := detectFirewall()
	stats := collectSecurityStats(infos)

	fmt.Println()
	fmt.Println("Security overview")
	fmt.Printf("  Exposure: %d public · %d interface · %d local · %d unknown\n", stats.Public, stats.Interface, stats.Local, stats.UnknownBind)
	fmt.Printf("  Processes: %d identified · %d unknown\n", stats.KnownProcess, stats.UnknownProcess)
	fmt.Printf("  Firewall: %s — %s\n", firewallLabel(fw), fw.Detail)
	for _, finding := range securityFindings(infos, fw, stats) {
		fmt.Printf("  %s\n", finding)
	}
	if stats.UnknownProcess > 0 && os.Geteuid() != 0 {
		fmt.Printf("  Tip: sudo `which portwhat` can identify the %d unknown process(es)\n", stats.UnknownProcess)
	}
}

type securityStats struct {
	Public         int
	Interface      int
	Local          int
	UnknownBind    int
	KnownProcess   int
	UnknownProcess int
}

func collectSecurityStats(infos []PortInfo) securityStats {
	var stats securityStats
	for _, info := range infos {
		switch displayBind(info.Bind) {
		case "public":
			stats.Public++
		case "local":
			stats.Local++
		case "unknown":
			stats.UnknownBind++
		default:
			stats.Interface++
		}
		if displayProcess(info.Process) == "unknown" {
			stats.UnknownProcess++
		} else {
			stats.KnownProcess++
		}
	}
	return stats
}

func scanMode() string {
	if os.Geteuid() == 0 {
		return "privileged (root)"
	}
	return "unprivileged — other users' sockets may lack process details"
}

func firewallLabel(fw firewallState) string {
	if !fw.Known {
		return "unknown"
	}
	if fw.Enabled {
		return "enabled"
	}
	return "disabled"
}

func securityFindings(infos []PortInfo, fw firewallState, stats securityStats) []string {
	var findings []string
	for _, info := range infos {
		if finding, ok := privilegedPortFinding(info); ok {
			findings = append(findings, finding)
		}
	}
	if exposed := stats.Public + stats.Interface; exposed > 0 && fw.Known && !fw.Enabled {
		findings = append(findings, fmt.Sprintf("! %d network-bound endpoint(s) with the host firewall disabled", exposed))
	}
	return findings
}

// RFC 7605: system ports SHOULD require privilege to bind, so a plain-user
// owner is suspect. macOS 10.14+ lets any user bind <1024, which makes the
// mismatch easy to create — and easy to abuse for service impersonation.
func privilegedPortFinding(info PortInfo) (string, bool) {
	if info.Port >= userPortStart {
		return "", false
	}
	owner := strings.TrimSpace(info.Owner)
	if owner == "" || owner == "unknown" || isSystemUser(owner) {
		return "", false
	}
	return fmt.Sprintf("! %d/%s (%s) is a system-range port but the process runs as %q, not a system account — unusual for a system service",
		info.Port, info.Proto, displayProcess(info.Process), owner), true
}

func isSystemUser(owner string) bool {
	owner = strings.ToLower(owner)
	if owner == "root" {
		return true
	}
	// Dedicated service accounts (_www, _mdnsresponder on macOS; daemon,
	// systemd-* on Linux) are deliberate privilege separation, not a finding.
	return strings.HasPrefix(owner, "_") || owner == "daemon" || strings.HasPrefix(owner, "systemd-")
}

func detectFirewall() firewallState {
	switch runtime.GOOS {
	case "darwin":
		return detectFirewallDarwin()
	case "linux":
		return detectFirewallLinux()
	default:
		return firewallState{Detail: "no firewall probe for " + runtime.GOOS}
	}
}

func detectFirewallDarwin() firewallState {
	// The application firewall state is readable without root.
	if out, err := runQuick("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); err == nil {
		lower := strings.ToLower(out)
		if strings.Contains(lower, "enabled") {
			return firewallState{Known: true, Enabled: true, Detail: "the macOS application firewall is enabled"}
		}
		if strings.Contains(lower, "disabled") {
			// pf may still filter, but reading its rules needs root.
			return firewallState{Known: true, Enabled: false, Detail: "the macOS application firewall is disabled (pf state needs root to check)"}
		}
	}
	if out, err := runQuick("pfctl", "-s", "info"); err == nil && strings.Contains(out, "Status: Enabled") {
		return firewallState{Known: true, Enabled: true, Detail: "pf is enabled"}
	}
	return firewallState{Detail: "could not query socketfilterfw or pfctl"}
}

func detectFirewallLinux() firewallState {
	if out, err := runQuick("ufw", "status"); err == nil {
		if strings.Contains(out, "Status: active") {
			return firewallState{Known: true, Enabled: true, Detail: "ufw is active"}
		}
		if strings.Contains(out, "Status: inactive") {
			return firewallState{Known: true, Enabled: false, Detail: "ufw is inactive"}
		}
	}
	if out, err := runQuick("firewall-cmd", "--state"); err == nil && strings.Contains(out, "running") {
		return firewallState{Known: true, Enabled: true, Detail: "firewalld is running"}
	}
	if out, err := runQuick("nft", "list", "ruleset"); err == nil {
		if strings.TrimSpace(out) != "" {
			return firewallState{Known: true, Enabled: true, Detail: "an nftables ruleset is loaded"}
		}
		return firewallState{Known: true, Enabled: false, Detail: "the nftables ruleset is empty"}
	}
	return firewallState{Detail: "ufw/firewalld/nft not available or need root"}
}

func runQuick(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
