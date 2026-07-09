package main

import (
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParsePortArgs(t *testing.T) {
	ports, ok := parsePortArgs([]string{"3000", "5432", "8504"})
	if !ok {
		t.Fatal("expected valid ports")
	}
	if len(ports) != 3 || ports[0] != 3000 || ports[1] != 5432 || ports[2] != 8504 {
		t.Fatalf("unexpected ports: %#v", ports)
	}

	for _, bad := range [][]string{{"abc"}, {"0"}, {"65536"}, {"-1"}, {"3000", "abc"}, {}} {
		if _, ok := parsePortArgs(bad); ok {
			t.Fatalf("expected %#v to be rejected", bad)
		}
	}
	if _, ok := parsePortArgs([]string{"1"}); !ok {
		t.Fatal("expected port 1 to be accepted")
	}
	if _, ok := parsePortArgs([]string{"65535"}); !ok {
		t.Fatal("expected port 65535 to be accepted")
	}
}

func TestHumanizeDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{-5 * time.Second, "0s"},
		{45 * time.Second, "45s"},
		{2*time.Minute + 18*time.Second, "2m"},
		{2*time.Hour + 23*time.Minute, "2h23m"},
		{3 * time.Hour, "3h"},
		{5*24*time.Hour + 56*time.Minute, "5d56m"},
		{27*24*time.Hour + 2*time.Hour + 1, "27d2h"},
		{10 * 24 * time.Hour, "10d"},
	}

	for _, c := range cases {
		if got := humanizeDuration(c.in); got != c.want {
			t.Fatalf("humanizeDuration(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDisplayBind(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"127.0.0.1", "local"},
		{"127.1.2.3", "local"},
		{"::1", "local"},
		{"localhost", "local"},
		{"0.0.0.0", "public"},
		{"::", "public"},
		{"*", "public"},
		{"[::]", "public"},
		{"192.168.1.5", "192.168.1.5"},
		{"", "unknown"},
		{"unknown", "unknown"},
	}
	for _, c := range cases {
		if got := displayBind(c.in); got != c.want {
			t.Fatalf("displayBind(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWrapText(t *testing.T) {
	cases := []struct {
		in    string
		width int
		want  []string
	}{
		{"", 10, []string{""}},
		{"short", 10, []string{"short"}},
		{"two words", 9, []string{"two words"}},
		{"two words", 5, []string{"two", "words"}},
		{"exact", 5, []string{"exact"}},
		{"overlong", 4, []string{"over", "long"}},
		{"a verylongword", 4, []string{"a", "very", "long", "word"}},
		{"anything", 0, []string{""}},
	}
	for _, c := range cases {
		got := wrapText(c.in, c.width)
		if len(got) != len(c.want) {
			t.Fatalf("wrapText(%q, %d) = %#v, want %#v", c.in, c.width, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("wrapText(%q, %d) = %#v, want %#v", c.in, c.width, got, c.want)
			}
		}
		for _, line := range got {
			if runeLen(line) > c.width && c.width > 0 {
				t.Fatalf("wrapText(%q, %d) produced overwide line %q", c.in, c.width, line)
			}
		}
	}
}

func TestPrintPortStatus(t *testing.T) {
	infos := []PortInfo{{
		Port:    8504,
		Proto:   "tcp",
		Process: "node",
		Bind:    "127.0.0.1",
		Age:     "2h23m",
		Purpose: "JavaScript app/dev server",
	}, {
		Port:    8504,
		Proto:   "udp",
		Process: "node",
		Bind:    "127.0.0.1",
		Age:     "2h23m",
		Purpose: "Unknown app/service",
	}}

	t.Setenv("COLUMNS", "100")
	out := captureStdout(t, func() {
		printPortStatus(infos, []int{3000, 8504})
	})

	for _, want := range []string{
		"Port status (2)",
		"PORT",
		"PROTO",
		"tcp",
		"udp",
		"STATUS",
		"PROCESS",
		"BIND",
		"AGE",
		"WHAT",
		"3000",
		"free",
		"8504",
		"used",
		"node",
		"local",
		"2h23m",
		"JavaScript app/dev server",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q\noutput:\n%s", want, out)
		}
	}
}

func TestPrintPortStatusNarrow(t *testing.T) {
	infos := []PortInfo{{
		Port:    8504,
		Proto:   "tcp",
		Process: "node",
		Bind:    "127.0.0.1",
		Age:     "2h23m",
		Purpose: "JavaScript app/dev server",
	}}

	t.Setenv("COLUMNS", "50")
	out := captureStdout(t, func() {
		printPortStatus(infos, []int{3000, 8504})
	})

	if strings.Contains(out, "STATUS") {
		t.Fatalf("narrow layout should not print table headers\noutput:\n%s", out)
	}
	for _, want := range []string{"free", "used", "8504", "JavaScript app/dev server", "local · 2h23m · node"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected narrow output to contain %q\noutput:\n%s", want, out)
		}
	}
}

func TestPrintHelp(t *testing.T) {
	out := captureStdout(t, func() {
		printHelp()
	})

	for _, want := range []string{
		"portwhat usage",
		"portwhat           overview + recommended next port",
		"portwhat next      print only the recommended port number",
		"portwhat 3000 80   show status for specific ports",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected help to contain %q\noutput:\n%s", want, out)
		}
	}
}

func TestPrintNextPortIsIntegerOnly(t *testing.T) {
	infos := []PortInfo{{Port: 3000}, {Port: 5173}, {Port: 8000}}
	out := captureStdout(t, func() {
		printNextPort(infos)
	})
	out = strings.TrimSpace(out)
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(out) {
		t.Fatalf("expected integer-only output, got %q", out)
	}
}

func TestSuggestPortPrefersCommonDevPorts(t *testing.T) {
	preferred := map[int]bool{3000: true, 3001: true, 3002: true, 5173: true, 8000: true, 8080: true, 9000: true}
	for i := 0; i < 20; i++ {
		port, reason := suggestPort(nil, map[int]bool{})
		if !preferred[port] {
			t.Fatalf("expected a preferred dev port with nothing in use, got %d", port)
		}
		if reason == "" {
			t.Fatal("expected a non-empty reason")
		}
	}

	used := map[int]bool{}
	for port := range preferred {
		used[port] = true
	}
	delete(used, 5173)
	for i := 0; i < 20; i++ {
		if port, _ := suggestPort(nil, used); port != 5173 {
			t.Fatalf("expected 5173 as the only free preferred port, got %d", port)
		}
	}
}

func TestSuggestPortNeverReturnsUsedPort(t *testing.T) {
	used := map[int]bool{3000: true, 3001: true, 3002: true, 5173: true, 8000: true, 8080: true, 9000: true}
	for i := 0; i < 50; i++ {
		port, _ := suggestPort([]int{3000, 3001, 3002}, used)
		if port == 0 || used[port] {
			t.Fatalf("suggestPort returned unusable port %d", port)
		}
	}
}

func TestIsGoodCandidatePort(t *testing.T) {
	used := map[int]bool{4000: true}
	cases := map[int]bool{
		80:   false, // privileged + well-known
		443:  false, // well-known service
		4000: false, // in use
		6000: false, // reserved (X11)
		4001: true,
	}
	for port, want := range cases {
		if got := isGoodCandidatePort(port, used); got != want {
			t.Fatalf("isGoodCandidatePort(%d) = %v, want %v", port, got, want)
		}
	}
}

func TestExplainPort(t *testing.T) {
	cases := []struct {
		port    int
		proto   string
		process string
		want    string
	}{
		{5432, "tcp", "anything", "PostgreSQL"},
		{4100, "tcp", "node", "JavaScript app/dev server"},
		{4100, "tcp", "python3.12", "Python app/server"},
		{4100, "tcp", "go", "Go app/server"},
		{27017, "tcp", "mongod", "Unknown app/service"},
		{4100, "tcp", "django-admin", "Unknown app/service"},
		{3123, "tcp", "myapp", "Likely local development server"},
		{5353, "udp", "mDNSResponder", "mDNS / Bonjour"},
		{51820, "udp", "wireguard-go", "WireGuard"},
		{5353, "tcp", "someapp", "Unknown app/service"},
	}
	for _, c := range cases {
		if got := explainPort(c.port, c.proto, c.process); got != c.want {
			t.Fatalf("explainPort(%d, %q, %q) = %q, want %q", c.port, c.proto, c.process, got, c.want)
		}
	}
}

func TestDedupeKeepsProtocolsSeparate(t *testing.T) {
	infos := dedupeAndSort([]PortInfo{
		{Port: 53, Proto: "udp", Process: "dnsmasq", Bind: "127.0.0.1"},
		{Port: 53, Proto: "tcp", Process: "dnsmasq", Bind: "127.0.0.1"},
		{Port: 53, Proto: "udp", Process: "unknown", Bind: "::"},
	})
	if len(infos) != 2 {
		t.Fatalf("expected tcp and udp rows for port 53, got %#v", infos)
	}
	if infos[0].Proto != "tcp" || infos[1].Proto != "udp" {
		t.Fatalf("expected tcp before udp, got %q then %q", infos[0].Proto, infos[1].Proto)
	}
	if infos[1].Process != "dnsmasq" || displayBind(infos[1].Bind) != "public" {
		t.Fatalf("expected merged udp row to keep known process and public bind, got %#v", infos[1])
	}
}

func TestMergePortInfoPrefersKnownProcessAndPublicBind(t *testing.T) {
	a := PortInfo{Port: 8080, Process: "unknown", Bind: "::", Purpose: "HTTP alt / app server"}
	b := PortInfo{Port: 8080, Process: "node", Bind: "127.0.0.1", Age: "2h", Purpose: "HTTP alt / app server"}

	merged := mergePortInfo(a, b)
	if merged.Process != "node" {
		t.Fatalf("expected known process to win, got %q", merged.Process)
	}
	if displayBind(merged.Bind) != "public" {
		t.Fatalf("expected most exposed bind to win, got %q", merged.Bind)
	}
}

func TestPrivilegedPortFinding(t *testing.T) {
	cases := []struct {
		info PortInfo
		want bool
	}{
		{PortInfo{Port: 80, Proto: "tcp", Process: "nginx", Owner: "kaxing"}, true},
		{PortInfo{Port: 80, Proto: "tcp", Process: "nginx", Owner: "root"}, false},
		{PortInfo{Port: 53, Proto: "udp", Process: "mDNSResponder", Owner: "_mdnsresponder"}, false},
		{PortInfo{Port: 631, Proto: "tcp", Process: "cupsd", Owner: "daemon"}, false},
		{PortInfo{Port: 8080, Proto: "tcp", Process: "node", Owner: "kaxing"}, false},
		{PortInfo{Port: 443, Proto: "tcp", Process: "mystery", Owner: "unknown"}, false},
	}
	for _, c := range cases {
		finding, got := privilegedPortFinding(c.info)
		if got != c.want {
			t.Fatalf("privilegedPortFinding(%d/%s owner=%q) = %v, want %v", c.info.Port, c.info.Proto, c.info.Owner, got, c.want)
		}
		if got && !strings.Contains(finding, strconv.Itoa(c.info.Port)) {
			t.Fatalf("finding should mention the port: %q", finding)
		}
	}
}

func TestSecurityNotesFirewallReconciliation(t *testing.T) {
	public := []PortInfo{{Port: 6379, Proto: "tcp", Process: "redis-server", Owner: "kaxing", Bind: "0.0.0.0"}}
	local := []PortInfo{{Port: 6379, Proto: "tcp", Process: "redis-server", Owner: "kaxing", Bind: "127.0.0.1"}}

	notes := securityNotes(public, firewallState{Known: true, Enabled: false, Detail: "ufw is inactive"})
	if len(notes) != 1 || !strings.Contains(notes[0], "anything on your network can reach them") {
		t.Fatalf("expected a warning for public bind with firewall off, got %#v", notes)
	}

	notes = securityNotes(public, firewallState{Known: true, Enabled: true, Detail: "ufw is active"})
	if len(notes) != 1 || !strings.Contains(notes[0], "may not actually be reachable") {
		t.Fatalf("expected a softened note for public bind with firewall on, got %#v", notes)
	}

	notes = securityNotes(public, firewallState{Detail: "could not query socketfilterfw or pfctl"})
	if len(notes) != 1 || !strings.Contains(notes[0], "firewall state unknown") {
		t.Fatalf("expected an unknown-state note for public bind, got %#v", notes)
	}

	if notes = securityNotes(local, firewallState{Known: true, Enabled: false, Detail: "ufw is inactive"}); len(notes) != 0 {
		t.Fatalf("expected no notes for local-only binds, got %#v", notes)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = old
		_ = w.Close()
	}()

	fn()

	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(out)
}
