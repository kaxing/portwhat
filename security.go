package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// firewallState is the best-effort answer to "does a host firewall stand
// between 'public' binds and the network?". Probing rulesets usually needs
// root, so "unknown" is a common and honest answer.
type firewallState struct {
	Known   bool
	Enabled bool
	Detail  string
}

func printSecurityNotes(infos []PortInfo) {
	notes := securityNotes(infos, detectFirewall())
	if len(notes) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("Security notes")
	for _, note := range notes {
		fmt.Printf("  %s\n", note)
	}
}

func securityNotes(infos []PortInfo, fw firewallState) []string {
	notes := []string{}

	for _, info := range infos {
		if finding, ok := privilegedPortFinding(info); ok {
			notes = append(notes, finding)
		}
	}

	if public := publicPortCount(infos); public > 0 {
		switch {
		case fw.Known && fw.Enabled:
			notes = append(notes, fmt.Sprintf("· %d port(s) bound publicly, but %s — they may not actually be reachable from other hosts", public, fw.Detail))
		case fw.Known && !fw.Enabled:
			notes = append(notes, fmt.Sprintf("! %d port(s) bound publicly and %s — anything on your network can reach them", public, fw.Detail))
		default:
			notes = append(notes, fmt.Sprintf("· %d port(s) bound publicly; firewall state unknown (%s)", public, fw.Detail))
		}
	}

	return notes
}

// privilegedPortFinding flags a listener on a privileged port (<1024) whose
// process is not owned by root. On most systems only root (or a capability
// like CAP_NET_BIND_SERVICE) can bind these, so a plain-user owner is worth a
// look. macOS 10.14+ lets any user bind <1024, which makes the mismatch
// easier to create — and easier to abuse for service impersonation.
func privilegedPortFinding(info PortInfo) (string, bool) {
	if info.Port >= 1024 {
		return "", false
	}
	owner := strings.TrimSpace(info.Owner)
	if owner == "" || owner == "unknown" || isSystemUser(owner) {
		return "", false
	}
	return fmt.Sprintf("! %d/%s (%s) is a privileged port but the process runs as %q, not a system account — unusual for a system service",
		info.Port, info.Proto, displayProcess(info.Process), owner), true
}

func isSystemUser(owner string) bool {
	owner = strings.ToLower(owner)
	if owner == "root" || strings.HasSuffix(owner, "\\system") || owner == "system" {
		return true
	}
	// Dedicated service accounts (_www, _mdnsresponder on macOS; daemon,
	// systemd-* on Linux) are deliberate privilege separation, not a finding.
	return strings.HasPrefix(owner, "_") || owner == "daemon" || strings.HasPrefix(owner, "systemd-")
}

func publicPortCount(infos []PortInfo) int {
	count := 0
	for _, info := range infos {
		if displayBind(info.Bind) == "public" {
			count++
		}
	}
	return count
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
