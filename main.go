package main

import (
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	gnet "github.com/shirou/gopsutil/v4/net"
	gprocess "github.com/shirou/gopsutil/v4/process"
	"golang.org/x/term"
)

type PortInfo struct {
	Port    int
	Proto   string
	Process string
	Owner   string
	Bind    string
	Age     string
	Purpose string
}

// RFC 6335/7605 ranges: System below 1024, User below 49152, Dynamic above.
const (
	userPortStart    = 1024
	dynamicPortStart = 49152
)

func availabilityNote(port int) string {
	switch {
	case port < userPortStart:
		return "Available (system range — binding usually needs root/privilege)"
	case port >= dynamicPortStart:
		return "Available (dynamic range — the OS hands these to client sockets)"
	default:
		return "Available"
	}
}

var processNameCache = map[int]string{}
var processOwnerCache = map[int]string{}
var processAgeCache = map[int]string{}
var processCmdlineCache = map[int]string{}

var commonPorts = map[int]string{
	22:   "SSH",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	465:  "SMTPS",
	587:  "SMTP submission",
	993:  "IMAPS",
	995:  "POP3S",
	3306: "MySQL",
	5432: "PostgreSQL",
	6379: "Redis",
	8000: "Common dev server",
	8080: "HTTP alt / app server",
	9000: "App / debug server",
}

var udpCommonPorts = map[int]string{
	53:    "DNS",
	67:    "DHCP server",
	68:    "DHCP client",
	69:    "TFTP",
	123:   "NTP",
	161:   "SNMP",
	514:   "Syslog",
	1900:  "SSDP / UPnP",
	4500:  "IPsec NAT-T",
	5353:  "mDNS / Bonjour",
	51820: "WireGuard",
}

func main() {
	args := os.Args[1:]
	infos, err := discoverPorts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	switch firstArg(args) {
	case "":
		printPorts(infos)
		printSecurityNotes(infos)
		fmt.Println()
		printSuggestion(infos)
	case "next":
		printNextPort(infos)
	case "usage", "help", "-h", "--help":
		printHelp()
	default:
		ports, ok := parsePortArgs(args)
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
			printHelp()
			os.Exit(2)
		}
		printPortStatus(infos, ports)
	}
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func printHelp() {
	fmt.Println("portwhat usage")
	fmt.Println("  portwhat           overview + recommended next port")
	fmt.Println("  portwhat next      print only the recommended port number")
	fmt.Println("  portwhat 3000 80   show status for specific ports")
}

func printPorts(infos []PortInfo) {
	if len(infos) == 0 {
		fmt.Println("No listening TCP ports or bound UDP sockets found.")
		return
	}
	var tcp, udp []PortInfo
	for _, info := range infos {
		if info.Proto == "udp" {
			udp = append(udp, info)
		} else {
			tcp = append(tcp, info)
		}
	}
	var groups []portGroup
	if len(tcp) > 0 {
		groups = append(groups, portGroup{"Listening TCP ports", tcp})
	}
	if len(udp) > 0 {
		groups = append(groups, portGroup{"Bound UDP sockets", udp})
	}
	printGroupedTable(groups)
}

type portGroup struct {
	title string
	infos []PortInfo
}

func printGroupedTable(groups []portGroup) {
	var all []PortInfo
	for _, group := range groups {
		sortByRisk(group.infos)
		all = append(all, group.infos...)
	}

	width := terminalWidth()

	if width < 60 {
		line := divider(width)
		for _, group := range groups {
			fmt.Printf("%s (%d)\n", group.title, len(group.infos))
			fmt.Println(line)
			for _, info := range group.infos {
				fmt.Printf("  %5d  %s\n", info.Port, info.Purpose)
				if meta := compactMeta(info); meta != "" {
					fmt.Printf("         %s\n", meta)
				}
			}
		}
		return
	}

	portWidth := maxInt(runeLen("PORT"), maxPortWidth(all))
	processWidth := min(24, maxInt(runeLen("PROCESS"), maxFieldWidth(all, func(info PortInfo) string { return displayProcess(info.Process) })))
	bindWidth := min(18, maxInt(runeLen("BIND"), maxFieldWidth(all, func(info PortInfo) string { return displayBind(info.Bind) })))
	ageWidth := min(10, maxInt(runeLen("AGE"), maxFieldWidth(all, func(info PortInfo) string { return displayAge(info.Age) })))
	purposeWidth := min(48, maxInt(runeLen("WHAT"), maxFieldWidth(all, func(info PortInfo) string { return info.Purpose })))

shrink:
	for tableWidth(portWidth, processWidth, bindWidth, ageWidth, purposeWidth) > width {
		switch {
		case purposeWidth > 12:
			purposeWidth--
		case processWidth > 10:
			processWidth--
		case bindWidth > 8:
			bindWidth--
		default:
			break shrink
		}
	}

	fmt.Printf("   %-*s   %-*s   %-*s   %-*s   %s\n", portWidth, "PORT", processWidth, "PROCESS", bindWidth, "BIND", ageWidth, "AGE", "WHAT")
	fmt.Println(divider(width))
	for _, group := range groups {
		fmt.Printf("%s (%d)\n", group.title, len(group.infos))
		for _, info := range group.infos {
			processLines := wrapText(displayProcess(info.Process), processWidth)
			bindLines := wrapText(displayBind(info.Bind), bindWidth)
			purposeLines := wrapText(info.Purpose, purposeWidth)
			rows := maxInt(len(processLines), maxInt(len(bindLines), len(purposeLines)))
			for i := 0; i < rows; i++ {
				portCell, ageCell := "", ""
				if i == 0 {
					portCell = strconv.Itoa(info.Port)
					ageCell = displayAge(info.Age)
				}
				fmt.Printf("   %*s   %s   %s   %s   %s\n",
					portWidth, portCell,
					padRight(lineAt(processLines, i), processWidth),
					padRight(lineAt(bindLines, i), bindWidth),
					padRight(ageCell, ageWidth),
					lineAt(purposeLines, i),
				)
			}
		}
	}
}

func divider(width int) string {
	return strings.Repeat("─", maxInt(20, width))
}

func printSuggestion(infos []PortInfo) {
	port, reason := recommendedPort(infos)
	if port == 0 {
		fmt.Println("Could not find a free suggested port.")
		return
	}

	fmt.Printf("Recommended next port\n  %d (%s)\n", port, reason)
}

func printPortStatus(infos []PortInfo, ports []int) {
	byPort := map[int][]PortInfo{}
	for _, info := range infos {
		byPort[info.Port] = append(byPort[info.Port], info)
	}

	fmt.Printf("Port status (%d)\n", len(ports))

	width := terminalWidth()
	if width < 60 {
		line := divider(width)
		fmt.Println(line)
		for _, port := range ports {
			if port < 1 || port > 65535 {
				fmt.Printf("%5d       n/a    Not a port (valid range 1-65535)\n", port)
				continue
			}
			entries := byPort[port]
			if len(entries) == 0 {
				fmt.Printf("%5d       free   %s\n", port, availabilityNote(port))
				continue
			}
			for _, info := range entries {
				fmt.Printf("%5d  %-3s  used   %s\n", port, info.Proto, info.Purpose)
				if meta := compactMeta(info); meta != "" {
					fmt.Printf("       %s\n", meta)
				}
			}
		}
		return
	}

	portWidth := maxInt(runeLen("PORT"), maxIntInSlice(ports))
	protoWidth := runeLen("PROTO")
	statusWidth := runeLen("STATUS")
	processWidth := runeLen("PROCESS")
	bindWidth := runeLen("BIND")
	ageWidth := runeLen("AGE")
	for _, port := range ports {
		for _, info := range byPort[port] {
			processWidth = maxInt(processWidth, runeLen(displayProcess(info.Process)))
			bindWidth = maxInt(bindWidth, runeLen(displayBind(info.Bind)))
			ageWidth = maxInt(ageWidth, runeLen(displayAge(info.Age)))
		}
	}

	fmt.Printf("  %-*s   %-*s   %-*s   %-*s   %-*s   %-*s   %s\n", portWidth, "PORT", protoWidth, "PROTO", statusWidth, "STATUS", processWidth, "PROCESS", bindWidth, "BIND", ageWidth, "AGE", "WHAT")
	fmt.Println(divider(width))
	printRow := func(port int, proto, status, process, bind, age, purpose string) {
		fmt.Printf("  %*d   %s   %s   %s   %s   %s   %s\n",
			portWidth, port,
			padRight(proto, protoWidth),
			padRight(status, statusWidth),
			padRight(process, processWidth),
			padRight(bind, bindWidth),
			padRight(age, ageWidth),
			purpose,
		)
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			printRow(port, "", "n/a", "", "", "", "Not a port (valid range 1-65535)")
			continue
		}
		entries := byPort[port]
		if len(entries) == 0 {
			printRow(port, "", "free", "", "", "", availabilityNote(port))
			continue
		}
		for _, info := range entries {
			printRow(port, info.Proto, "used", displayProcess(info.Process), displayBind(info.Bind), displayAge(info.Age), info.Purpose)
		}
	}
}

func parsePortArgs(args []string) ([]int, bool) {
	if len(args) == 0 {
		return nil, false
	}
	ports := make([]int, 0, len(args))
	// Any integer is treated as a port query; range errors are reported per
	// port by printPortStatus instead of rejecting the whole command.
	for _, arg := range args {
		port, err := strconv.Atoi(arg)
		if err != nil {
			return nil, false
		}
		ports = append(ports, port)
	}
	return ports, true
}

func printNextPort(infos []PortInfo) {
	port, _ := recommendedPort(infos)
	if port == 0 {
		os.Exit(1)
	}
	fmt.Println(port)
}

func recommendedPort(infos []PortInfo) (int, string) {
	used := map[int]bool{}
	ports := make([]int, 0, len(infos))
	for _, info := range infos {
		used[info.Port] = true
		ports = append(ports, info.Port)
	}
	return suggestPort(ports, used)
}

func suggestPort(usedPorts []int, used map[int]bool) (int, string) {
	// Preferred well-known dev ports are allowed even when they appear in
	// commonPorts; they only need to be free right now. Pick randomly among
	// the free ones so repeated runs spread suggestions around.
	preferred := make([]int, 0, 7)
	for _, port := range []int{3000, 3001, 3002, 5173, 8000, 8080, 9000} {
		if !used[port] {
			preferred = append(preferred, port)
		}
	}
	if len(preferred) > 0 {
		port := preferred[rand.IntN(len(preferred))]
		return port, whySuggested(port)
	}

	if port, ok := suggestNearActiveDevCluster(usedPorts, used); ok {
		return port, "next to your active dev ports"
	}

	for _, rng := range [][2]int{{3000, 3999}, {5000, 5999}, {7000, 7999}, {10000, 19999}} {
		candidates := make([]int, 0, 32)
		for p := rng[0]; p <= rng[1]; p++ {
			if isGoodCandidatePort(p, used) {
				candidates = append(candidates, p)
				if len(candidates) == 32 {
					break
				}
			}
		}
		if len(candidates) > 0 {
			port := candidates[rand.IntN(len(candidates))]
			return port, whySuggested(port)
		}
	}

	return 0, ""
}

func suggestNearActiveDevCluster(usedPorts []int, used map[int]bool) (int, bool) {
	bestBase := 0
	bestScore := 0
	for _, port := range usedPorts {
		if !isDevLikePort(port) {
			continue
		}
		score := 1
		for _, neighbor := range []int{port - 2, port - 1, port + 1, port + 2} {
			if used[neighbor] {
				score++
			}
		}
		if score > bestScore || (score == bestScore && port > bestBase) {
			bestBase = port
			bestScore = score
		}
	}

	if bestBase == 0 || bestScore < 2 {
		return 0, false
	}

	for _, candidate := range []int{bestBase + 1, bestBase + 2, bestBase - 1, bestBase - 2, bestBase + 3} {
		if isGoodCandidatePort(candidate, used) {
			return candidate, true
		}
	}
	return 0, false
}

func isGoodCandidatePort(port int, used map[int]bool) bool {
	if port < userPortStart || used[port] || commonPorts[port] != "" {
		return false
	}
	for _, reserved := range []int{6000, 6666, 6667} {
		if port == reserved {
			return false
		}
	}
	return true
}

func isDevLikePort(port int) bool {
	return (port >= 3000 && port <= 3999) || (port >= 5000 && port <= 5999) || (port >= 7000 && port <= 9999)
}

func whySuggested(port int) string {
	switch port {
	case 3000:
		return "popular app/dev default"
	case 5173:
		return "Vite default"
	case 8000:
		return "common local server"
	case 8080:
		return "common alternate HTTP port"
	case 9000:
		return "common app/debug port"
	case 3001, 3002, 3003, 3004, 3005:
		return "close to the common 3000 dev range"
	default:
		if port >= 3000 && port <= 3999 {
			return "free port in the common dev range"
		}
		if port >= 5000 && port <= 5999 {
			return "free port in a clean app range"
		}
		if port >= 7000 && port <= 7999 {
			return "free port in a secondary app range"
		}
		return "high unclaimed app port"
	}
}

func sortByRisk(infos []PortInfo) {
	sort.SliceStable(infos, func(i, j int) bool {
		leftRisk, rightRisk := riskScore(infos[i]), riskScore(infos[j])
		if leftRisk != rightRisk {
			return leftRisk > rightRisk
		}
		return infos[i].Port < infos[j].Port
	})
}

// Exact matches only: substring matching would flag "mDNS / Bonjour" via "DNS".
var sensitivePurposes = map[string]bool{
	"SSH": true, "DNS": true, "SMTP": true, "SMTP submission": true, "SMTPS": true,
	"POP3": true, "POP3S": true, "IMAP": true, "IMAPS": true,
	"MySQL": true, "PostgreSQL": true, "Redis": true,
}

func riskScore(info PortInfo) int {
	risk := 0
	switch displayBind(info.Bind) {
	case "public":
		risk += 100
	case "unknown":
		risk += 40
	case "local":
	default:
		risk += 70
	}
	if _, unusual := privilegedPortFinding(info); unusual {
		risk += 80
	} else if info.Port < userPortStart {
		risk += 20
	}
	if displayProcess(info.Process) == "unknown" {
		risk += 20
	}
	if sensitivePurposes[info.Purpose] {
		risk += 30
	}
	if processAge, err := time.ParseDuration(info.Age); err == nil && processAge <= 10*time.Minute {
		risk += 10
	}
	return risk
}

func compactMeta(info PortInfo) string {
	parts := []string{}
	if bind := displayBind(info.Bind); bind != "unknown" {
		parts = append(parts, bind)
	}
	if age := displayAge(info.Age); age != "" {
		parts = append(parts, age)
	}
	if info.Process != "" && info.Process != "unknown" {
		parts = append(parts, info.Process)
	}
	return strings.Join(parts, " · ")
}

func lineAt(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return ""
}

func displayBind(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "unknown" {
		return "unknown"
	}
	s = strings.Trim(s, "[]")
	if strings.HasPrefix(s, "127.") || s == "localhost" || s == "::1" {
		return "local"
	}
	if s == "*" || s == "0.0.0.0" || s == "::" {
		return "public"
	}
	return s
}

func displayAge(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "unknown" {
		return ""
	}
	return s
}

func humanizeDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	mins := d / time.Minute
	d -= mins * time.Minute
	secs := d / time.Second

	if days > 0 {
		if hours > 0 {
			return fmt.Sprintf("%dd%dh", days, hours)
		}
		if mins > 0 {
			return fmt.Sprintf("%dd%dm", days, mins)
		}
		return fmt.Sprintf("%dd", days)
	}
	if hours > 0 {
		if mins > 0 {
			return fmt.Sprintf("%dh%dm", hours, mins)
		}
		return fmt.Sprintf("%dh", hours)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm", mins)
	}
	if secs > 0 {
		return fmt.Sprintf("%ds", secs)
	}
	return "0s"
}

func displayProcess(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	return s
}

func wrapText(s string, width int) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return []string{""}
	}
	if width <= 0 {
		return []string{""}
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{s}
	}
	lines := make([]string, 0, 2)
	line := ""
	for _, word := range words {
		if line == "" {
			for _, chunk := range breakWord(word, width) {
				if runeLen(chunk) == width {
					lines = append(lines, chunk)
				} else {
					line = chunk
				}
			}
			continue
		}
		if runeLen(line)+1+runeLen(word) <= width {
			line += " " + word
			continue
		}
		lines = append(lines, line)
		line = ""
		for _, chunk := range breakWord(word, width) {
			if runeLen(chunk) == width {
				lines = append(lines, chunk)
			} else {
				line = chunk
			}
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func breakWord(s string, width int) []string {
	if width <= 0 {
		return []string{""}
	}
	if runeLen(s) <= width {
		return []string{s}
	}
	var out []string
	var b strings.Builder
	count := 0
	for _, r := range s {
		b.WriteRune(r)
		count++
		if count == width {
			out = append(out, b.String())
			b.Reset()
			count = 0
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func runeLen(s string) int {
	return utf8.RuneCountInString(s)
}

func maxPortWidth(infos []PortInfo) int {
	maxWidth := 1
	for _, info := range infos {
		w := runeLen(strconv.Itoa(info.Port))
		if w > maxWidth {
			maxWidth = w
		}
	}
	return maxWidth
}

func maxIntInSlice(nums []int) int {
	maxWidth := 1
	for _, n := range nums {
		w := runeLen(strconv.Itoa(n))
		if w > maxWidth {
			maxWidth = w
		}
	}
	return maxWidth
}

func maxFieldWidth(infos []PortInfo, pick func(PortInfo) string) int {
	maxWidth := 1
	for _, info := range infos {
		w := runeLen(pick(info))
		if w > maxWidth {
			maxWidth = w
		}
	}
	return maxWidth
}

func tableWidth(widths ...int) int {
	total := 3 // leading indentation
	for i, width := range widths {
		total += width
		if i < len(widths)-1 {
			total += 3
		}
	}
	return total
}

func padRight(s string, width int) string {
	pad := width - utf8.RuneCountInString(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

func terminalWidth() int {
	if n := terminalWidthFromTTY(); n > 20 {
		return n
	}
	if n := terminalWidthFromEnv(); n > 20 {
		return n
	}
	return 100
}

func terminalWidthFromEnv() int {
	if cols := os.Getenv("COLUMNS"); cols != "" {
		if n, err := strconv.Atoi(cols); err == nil {
			return n
		}
	}
	return 0
}

func terminalWidthFromTTY() int {
	for _, f := range []*os.File{os.Stdout, os.Stderr, os.Stdin} {
		if f == nil {
			continue
		}
		if cols, _, err := term.GetSize(int(f.Fd())); err == nil && cols > 0 {
			return cols
		}
	}
	return 0
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func discoverPorts() ([]PortInfo, error) {
	// Single "inet" query: probing the TCP and UDP tables separately costs twice.
	conns, err := gnet.Connections("inet")
	if err != nil {
		return nil, fmt.Errorf("could not discover listening ports: %w", err)
	}

	infos := make([]PortInfo, 0, len(conns))
	for _, conn := range conns {
		port := int(conn.Laddr.Port)
		switch conn.Type {
		case syscall.SOCK_STREAM:
			if conn.Status != "LISTEN" || port == 0 {
				continue
			}
			infos = append(infos, buildPortInfo(conn, "tcp"))
		case syscall.SOCK_DGRAM:
			// UDP has no LISTEN state: any bound socket without a remote peer
			// counts, except unknown dynamic-range ones (short-lived clients).
			if port == 0 || conn.Raddr.Port != 0 || port >= dynamicPortStart && udpCommonPorts[port] == "" {
				continue
			}
			infos = append(infos, buildPortInfo(conn, "udp"))
		}
	}

	return dedupeAndSort(infos), nil
}

func buildPortInfo(conn gnet.ConnectionStat, proto string) PortInfo {
	pid := int(conn.Pid)
	process := resolveProcessName(pid, "unknown")
	port := int(conn.Laddr.Port)
	return PortInfo{
		Port:    port,
		Proto:   proto,
		Process: process,
		Owner:   resolveProcessOwner(pid),
		Bind:    conn.Laddr.IP,
		Age:     resolveProcessAge(pid),
		Purpose: explainPort(port, proto, process, pid),
	}
}

func resolveProcessOwner(pid int) string {
	if pid <= 0 {
		return "unknown"
	}
	if cached, ok := processOwnerCache[pid]; ok {
		return cached
	}
	owner := "unknown"
	if p, err := gprocess.NewProcess(int32(pid)); err == nil {
		if name, err := p.Username(); err == nil && name != "" {
			owner = name
		}
	}
	processOwnerCache[pid] = owner
	return owner
}

func resolveProcessName(pid int, fallback string) string {
	fallback = cleanProcessName(fallback)
	if pid <= 0 {
		if fallback == "" {
			return "unknown"
		}
		return fallback
	}
	if cached, ok := processNameCache[pid]; ok {
		return cached
	}
	p, err := gprocess.NewProcess(int32(pid))
	if err == nil {
		if name, err := p.Name(); err == nil {
			name = cleanProcessName(name)
			if name != "" {
				processNameCache[pid] = name
				return name
			}
		}
	}
	if fallback == "" {
		fallback = "unknown"
	}
	processNameCache[pid] = fallback
	return fallback
}

func resolveProcessAge(pid int) string {
	if pid <= 0 {
		return ""
	}
	if cached, ok := processAgeCache[pid]; ok {
		return cached
	}
	p, err := gprocess.NewProcess(int32(pid))
	if err == nil {
		if created, err := p.CreateTime(); err == nil && created > 0 {
			age := time.Since(time.UnixMilli(created))
			if age < 0 {
				age = 0
			}
			formatted := humanizeDuration(age)
			processAgeCache[pid] = formatted
			return formatted
		}
	}
	processAgeCache[pid] = ""
	return ""
}

func cleanProcessName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return s
	}
	name := parts[0]
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	return name
}

func explainPort(port int, proto, process string, pid int) string {
	if proto == "udp" {
		if purpose, ok := udpCommonPorts[port]; ok {
			return purpose
		}
	} else if purpose, ok := commonPorts[port]; ok {
		return purpose
	}

	if purpose := purposeFromCmdline(pid); purpose != "" {
		return purpose
	}

	name := strings.ToLower(process)
	switch {
	case strings.HasPrefix(name, "postgres"):
		return "PostgreSQL"
	case strings.HasPrefix(name, "redis"):
		return "Redis"
	case strings.Contains(name, "docker"):
		return "Docker / container service"
	case strings.HasPrefix(name, "node") || name == "bun" || name == "deno":
		return "JavaScript app/dev server"
	case strings.HasPrefix(name, "python"):
		return "Python app/server"
	case name == "go":
		return "Go app/server"
	case proto != "udp" && port >= 3000 && port <= 3999:
		return "Likely local development server"
	}

	// /etc/services is authoritative below 1024 but stale above it, so up there
	// it is consulted only when the process is unresolvable (no better evidence).
	if port < userPortStart || displayProcess(process) == "unknown" {
		if svc := serviceFromEtc(port, proto); svc != "" {
			return svc + " (/etc/services)"
		}
	}

	if port >= dynamicPortStart {
		return "Dynamic/private port (ephemeral)"
	}
	return "Unknown app/service"
}

var cmdlineHints = []struct{ needle, purpose string }{
	{"vite", "Vite dev server"},
	{"next dev", "Next.js dev server"},
	{"next-server", "Next.js server"},
	{"react-scripts", "React dev server"},
	{"webpack", "Webpack dev server"},
	{"storybook", "Storybook"},
	{"manage.py runserver", "Django dev server"},
	{"uvicorn", "Uvicorn ASGI server"},
	{"gunicorn", "Gunicorn WSGI server"},
	{"flask", "Flask dev server"},
	{"rails", "Rails server"},
	{"php artisan", "Laravel dev server"},
}

func purposeFromCmdline(pid int) string {
	cmdline := strings.ToLower(resolveProcessCmdline(pid))
	if cmdline == "" {
		return ""
	}
	for _, hint := range cmdlineHints {
		if strings.Contains(cmdline, hint.needle) {
			return hint.purpose
		}
	}
	return ""
}

func resolveProcessCmdline(pid int) string {
	if pid <= 0 {
		return ""
	}
	if cached, ok := processCmdlineCache[pid]; ok {
		return cached
	}
	cmdline := ""
	if p, err := gprocess.NewProcess(int32(pid)); err == nil {
		if line, err := p.Cmdline(); err == nil {
			cmdline = line
		}
	}
	processCmdlineCache[pid] = cmdline
	return cmdline
}

var etcServicesLoaded bool
var etcServicesMap map[string]string

func serviceFromEtc(port int, proto string) string {
	if !etcServicesLoaded {
		etcServicesLoaded = true
		etcServicesMap = loadServicesFile("/etc/services")
	}
	return etcServicesMap[strconv.Itoa(port)+"/"+proto]
}

func loadServicesFile(path string) map[string]string {
	services := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return services
	}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, ok := services[fields[1]]; !ok {
			services[fields[1]] = fields[0]
		}
	}
	return services
}

func dedupeAndSort(infos []PortInfo) []PortInfo {
	type portProto struct {
		port  int
		proto string
	}
	byKey := map[portProto]PortInfo{}
	for _, info := range infos {
		key := portProto{info.Port, info.Proto}
		existing, ok := byKey[key]
		if !ok {
			byKey[key] = info
			continue
		}
		byKey[key] = mergePortInfo(existing, info)
	}
	keys := make([]portProto, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].port != keys[j].port {
			return keys[i].port < keys[j].port
		}
		return keys[i].proto < keys[j].proto
	})
	out := make([]PortInfo, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out
}

// Merging IPv4/IPv6 twins keeps the most exposed bind so a service that is
// also reachable publicly is never shown as local.
func mergePortInfo(a, b PortInfo) PortInfo {
	out := a
	if a.Process == "unknown" && b.Process != "unknown" {
		out.Process = b.Process
		out.Owner = b.Owner
		out.Age = b.Age
		out.Purpose = b.Purpose
	}
	if bindExposure(b.Bind) > bindExposure(a.Bind) {
		out.Bind = b.Bind
	}
	return out
}

func bindExposure(bind string) int {
	switch displayBind(bind) {
	case "public":
		return 3
	case "local":
		return 1
	case "unknown":
		return 0
	default:
		return 2
	}
}
