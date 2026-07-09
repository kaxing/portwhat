package main

import (
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strconv"
	"strings"
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

var processNameCache = map[int]string{}
var processOwnerCache = map[int]string{}
var processAgeCache = map[int]string{}

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
		fmt.Println("No listening TCP ports found.")
		return
	}

	width := terminalWidth()
	fmt.Printf("Listening ports (%d)\n", len(infos))

	if width < 56 {
		line := strings.Repeat("─", maxInt(20, width))
		fmt.Println(line)
		for _, info := range infos {
			fmt.Printf("%5d  %-3s  %s\n", info.Port, info.Proto, info.Purpose)
			if meta := compactMeta(info); meta != "" {
				fmt.Printf("       %s\n", meta)
			}
		}
		fmt.Println(line)
		return
	}

	portWidth := maxInt(runeLen("PORT"), maxPortWidth(infos))
	protoWidth := maxInt(runeLen("PROTO"), maxFieldWidth(infos, func(info PortInfo) string { return info.Proto }))
	processWidth := maxInt(runeLen("PROCESS"), maxFieldWidth(infos, func(info PortInfo) string { return displayProcess(info.Process) }))
	bindWidth := maxInt(runeLen("BIND"), maxFieldWidth(infos, func(info PortInfo) string { return displayBind(info.Bind) }))
	ageWidth := maxInt(runeLen("AGE"), maxFieldWidth(infos, func(info PortInfo) string { return displayAge(info.Age) }))
	purposeWidth := maxInt(runeLen("WHAT"), maxFieldWidth(infos, func(info PortInfo) string { return info.Purpose }))

	minProcessWidth := 10
	minPurposeWidth := 12
	for tableWidth(portWidth, protoWidth, processWidth, bindWidth, ageWidth, purposeWidth) > width {
		changed := false
		if purposeWidth > minPurposeWidth {
			purposeWidth--
			changed = true
		}
		if tableWidth(portWidth, protoWidth, processWidth, bindWidth, ageWidth, purposeWidth) <= width {
			break
		}
		if processWidth > minProcessWidth {
			processWidth--
			changed = true
		}
		if !changed {
			break
		}
	}

	widths := []int{portWidth, protoWidth, processWidth, bindWidth, ageWidth, purposeWidth}
	fmt.Println(tableBorder(widths))
	fmt.Printf("  %-*s   %-*s   %-*s   %-*s   %-*s   %s\n", portWidth, "PORT", protoWidth, "PROTO", processWidth, "PROCESS", bindWidth, "BIND", ageWidth, "AGE", "WHAT")
	fmt.Println(tableBorder(widths))
	for _, info := range infos {
		processLines := wrapText(displayProcess(info.Process), processWidth)
		bindLines := wrapText(displayBind(info.Bind), bindWidth)
		purposeLines := wrapText(info.Purpose, purposeWidth)
		rows := maxInt(len(processLines), maxInt(len(bindLines), len(purposeLines)))
		for i := 0; i < rows; i++ {
			portCell, protoCell, ageCell := "", "", ""
			if i == 0 {
				portCell = strconv.Itoa(info.Port)
				protoCell = info.Proto
				ageCell = displayAge(info.Age)
			}
			fmt.Printf("  %*s   %s   %s   %s   %s   %s\n",
				portWidth, portCell,
				padRight(protoCell, protoWidth),
				padRight(lineAt(processLines, i), processWidth),
				padRight(lineAt(bindLines, i), bindWidth),
				padRight(ageCell, ageWidth),
				lineAt(purposeLines, i),
			)
		}
	}
	fmt.Println(tableBorder(widths))
}

func tableBorder(widths []int) string {
	return strings.Repeat("─", tableWidth(widths...))
}

func printSuggestion(infos []PortInfo) {
	port, reason := recommendedPort(infos)
	if port == 0 {
		fmt.Println("Could not find a free suggested port.")
		return
	}

	fmt.Printf("Recommended next port: %d (%s)\n", port, reason)
}

func printPortStatus(infos []PortInfo, ports []int) {
	byPort := map[int][]PortInfo{}
	for _, info := range infos {
		byPort[info.Port] = append(byPort[info.Port], info)
	}

	fmt.Printf("Port status (%d)\n", len(ports))

	if width := terminalWidth(); width < 56 {
		line := strings.Repeat("─", maxInt(20, width))
		fmt.Println(line)
		for _, port := range ports {
			entries := byPort[port]
			if len(entries) == 0 {
				fmt.Printf("%5d       free   Available\n", port)
				continue
			}
			for _, info := range entries {
				fmt.Printf("%5d  %-3s  used   %s\n", port, info.Proto, info.Purpose)
				if meta := compactMeta(info); meta != "" {
					fmt.Printf("       %s\n", meta)
				}
			}
		}
		fmt.Println(line)
		return
	}

	portWidth := maxInt(runeLen("PORT"), maxIntInSlice(ports))
	protoWidth := runeLen("PROTO")
	statusWidth := runeLen("STATUS")
	processWidth := runeLen("PROCESS")
	bindWidth := runeLen("BIND")
	ageWidth := runeLen("AGE")
	purposeWidth := maxInt(runeLen("WHAT"), runeLen("Available"))
	for _, port := range ports {
		for _, info := range byPort[port] {
			processWidth = maxInt(processWidth, runeLen(displayProcess(info.Process)))
			bindWidth = maxInt(bindWidth, runeLen(displayBind(info.Bind)))
			ageWidth = maxInt(ageWidth, runeLen(displayAge(info.Age)))
			purposeWidth = maxInt(purposeWidth, runeLen(info.Purpose))
		}
	}

	widths := []int{portWidth, protoWidth, statusWidth, processWidth, bindWidth, ageWidth, purposeWidth}
	fmt.Println(tableBorder(widths))
	fmt.Printf("  %-*s   %-*s   %-*s   %-*s   %-*s   %-*s   %s\n", portWidth, "PORT", protoWidth, "PROTO", statusWidth, "STATUS", processWidth, "PROCESS", bindWidth, "BIND", ageWidth, "AGE", "WHAT")
	fmt.Println(tableBorder(widths))
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
		entries := byPort[port]
		if len(entries) == 0 {
			printRow(port, "", "free", "", "", "", "Available")
			continue
		}
		for _, info := range entries {
			printRow(port, info.Proto, "used", displayProcess(info.Process), displayBind(info.Bind), displayAge(info.Age), info.Purpose)
		}
	}
	fmt.Println(tableBorder(widths))
}

func parsePortArgs(args []string) ([]int, bool) {
	if len(args) == 0 {
		return nil, false
	}
	ports := make([]int, 0, len(args))
	for _, arg := range args {
		port, err := strconv.Atoi(arg)
		if err != nil || port < 1 || port > 65535 {
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
	if port < 1024 || used[port] || commonPorts[port] != "" {
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
	// Each column costs its width plus "│ " and " "; the final "│" adds one.
	total := 1
	for _, w := range widths {
		total += w + 3
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
	if n := terminalWidthFromEnv(); n > 20 {
		return n
	}
	if n := terminalWidthFromTTY(); n > 20 {
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
	tcpConns, err := gnet.Connections("tcp")
	if err != nil {
		return nil, fmt.Errorf("could not discover listening ports: %w", err)
	}

	infos := make([]PortInfo, 0, len(tcpConns))
	for _, conn := range tcpConns {
		if conn.Status != "LISTEN" || conn.Laddr.Port == 0 {
			continue
		}
		infos = append(infos, buildPortInfo(conn, "tcp"))
	}

	// UDP is best-effort: it has no LISTEN state, so any bound socket without
	// a remote peer counts, and ephemeral-range ports are skipped because
	// they are almost always short-lived client sockets (QUIC, DNS lookups).
	if udpConns, err := gnet.Connections("udp"); err == nil {
		for _, conn := range udpConns {
			if conn.Laddr.Port == 0 || conn.Raddr.Port != 0 || int(conn.Laddr.Port) >= 49152 {
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
		Purpose: explainPort(port, proto, process),
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

func explainPort(port int, proto, process string) string {
	if proto == "udp" {
		if purpose, ok := udpCommonPorts[port]; ok {
			return purpose
		}
	} else if purpose, ok := commonPorts[port]; ok {
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
	case port >= 3000 && port <= 3999:
		return "Likely local development server"
	case port >= 49152:
		return "Ephemeral/high dynamic port"
	default:
		return "Unknown app/service"
	}
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

// mergePortInfo combines duplicate listeners on the same port (typically an
// IPv4 and an IPv6 socket): keep the known process details, and keep the most
// exposed bind so a service also reachable publicly is never shown as local.
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
