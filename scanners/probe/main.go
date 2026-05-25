// MAVERICK probe v0 — multi-fingerprint discovery.
//
// Two protocols supported:
//   tcp_http  — masscan SYN sweep then HTTP banner-grab + string match
//   udp_raw   — direct UDP payload send + response-prefix match (no masscan)
//
// One fingerprint per scan run, selected with --fingerprint. Output is JSONL,
// one observation per probed/responding host.
//
// Fingerprints are hardcoded in `fingerprints` below. The mirror YAML files
// under ../../fingerprints/ are documentation today; they become the source
// of truth when we start loading them dynamically.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Fingerprint struct {
	ID          string
	Vendor      string
	DeviceClass string
	Protocol    string // "tcp_http" or "udp_raw"
	Port        int

	// tcp_http
	HTTPProbes []HTTPProbe
	MatchAnyCI []string
	MatchAllCI [][]string

	// udp_raw
	UDPPayload     []byte
	UDPMatchPrefix []byte
	UDPMinLen      int
}

type HTTPProbe struct {
	Method string
	Path   string
}

var fingerprints = map[string]Fingerprint{
	"unitree_webrtc": {
		ID:          "unitree_webrtc",
		Vendor:      "unitree",
		DeviceClass: "quadruped_or_humanoid",
		Protocol:    "tcp_http",
		Port:        8081,
		HTTPProbes: []HTTPProbe{
			{Method: "GET", Path: "/"},
			{Method: "GET", Path: "/api"},
		},
		MatchAnyCI: []string{
			"unitree",
			"master_service",
		},
		MatchAllCI: [][]string{
			{"go2", "robot"},
			{"g1", "humanoid"},
		},
	},
	"xiaomi_miio": {
		ID:          "xiaomi_miio",
		Vendor:      "xiaomi",
		DeviceClass: "smarthome_iot", // includes Roborock vacuums + Mi air purifiers + humidifiers
		Protocol:    "udp_raw",
		Port:        54321,
		// miIO hello: magic(0x2131) + len(0x0020) + 28 bytes of 0xFF.
		// See OpenMiHome/mihome-binary-protocol.
		UDPPayload:     mustHex("21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		UDPMatchPrefix: mustHex("21310020"), // any reply that echoes the magic+length is miIO-speaking
		UDPMinLen:      32,
	},
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type Observation struct {
	Timestamp       string   `json:"ts"`
	IP              string   `json:"ip"`
	Port            int      `json:"port"`
	FingerprintID   string   `json:"fingerprint"`
	ProbePath       string   `json:"probe_path,omitempty"`
	Matched         bool     `json:"matched"`
	MatchedRules    []string `json:"matched_rules,omitempty"`
	HTTPStatus      int      `json:"http_status,omitempty"`
	ResponseSnippet string   `json:"response_snippet,omitempty"`
	ResponseHex     string   `json:"response_hex,omitempty"`
	Error           string   `json:"error,omitempty"`
}

const userAgent = "MAVERICK-research-scanner/0.1 (+https://github.com/atmksheldon/maverick)"

func main() {
	targetsFile := flag.String("targets", "", "file with one IP/CIDR per line (required)")
	rate := flag.Int("rate", 1000, "packets per second (masscan for tcp_http, direct send for udp_raw)")
	outFile := flag.String("out", "", "output JSONL file (default: stdout)")
	workers := flag.Int("workers", 10, "concurrent HTTP probes (tcp_http only)")
	skipMasscan := flag.Bool("skip-masscan", false, "tcp_http only: skip masscan; treat --targets as known-open IPs")
	fpName := flag.String("fingerprint", "unitree_webrtc", "fingerprint id (use --list to see options)")
	listFP := flag.Bool("list", false, "list available fingerprints and exit")
	flag.Parse()

	if *listFP {
		for _, name := range fpNames() {
			fp := fingerprints[name]
			fmt.Printf("%-20s %-12s %-7s port=%d\n", name, fp.Vendor, fp.Protocol, fp.Port)
		}
		return
	}

	if *targetsFile == "" {
		fmt.Fprintln(os.Stderr, "missing --targets")
		flag.Usage()
		os.Exit(2)
	}

	fp, ok := fingerprints[*fpName]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown fingerprint: %s (have: %s)\n", *fpName, strings.Join(fpNames(), ", "))
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "fingerprint: %s (%s, %s/%d)\n", fp.ID, fp.Vendor, fp.Protocol, fp.Port)

	out := io.Writer(os.Stdout)
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			die("open %s: %v", *outFile, err)
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	var written, matched int
	var mu sync.Mutex
	writeObs := func(obs Observation) {
		mu.Lock()
		defer mu.Unlock()
		if err := enc.Encode(obs); err != nil {
			fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		}
		written++
		if obs.Matched {
			matched++
		}
	}

	switch fp.Protocol {
	case "tcp_http":
		runHTTPScan(fp, *targetsFile, *rate, *workers, *skipMasscan, writeObs)
	case "udp_raw":
		runUDPScan(fp, *targetsFile, *rate, writeObs)
	default:
		die("unknown protocol: %s", fp.Protocol)
	}

	fmt.Fprintf(os.Stderr, "done: %d observation(s), %d matched\n", written, matched)
}

func fpNames() []string {
	names := make([]string, 0, len(fingerprints))
	for k := range fingerprints {
		names = append(names, k)
	}
	return names
}

// ---------- tcp_http path ----------

func runHTTPScan(fp Fingerprint, targetsFile string, rate, workers int, skipMasscan bool, writeObs func(Observation)) {
	var openHosts []string
	if skipMasscan {
		hosts, err := readHostsFile(targetsFile)
		if err != nil {
			die("read targets: %v", err)
		}
		openHosts = hosts
		fmt.Fprintf(os.Stderr, "skip-masscan: probing %d host(s) directly\n", len(openHosts))
	} else {
		hosts, err := runMasscan(targetsFile, fp.Port, rate)
		if err != nil {
			die("masscan: %v", err)
		}
		openHosts = hosts
		fmt.Fprintf(os.Stderr, "masscan: %d host(s) with port %d open\n", len(openHosts), fp.Port)
	}

	if len(openHosts) == 0 {
		fmt.Fprintln(os.Stderr, "no open hosts; nothing to probe")
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	ch := make(chan string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ch {
				probeHostHTTP(client, ip, fp, writeObs)
			}
		}()
	}
	for _, h := range openHosts {
		ch <- h
	}
	close(ch)
	wg.Wait()
}

func runMasscan(targetsFile string, port, rate int) ([]string, error) {
	tmpf, err := os.CreateTemp("", "maverick-masscan-*.txt")
	if err != nil {
		return nil, err
	}
	tmpf.Close()
	defer os.Remove(tmpf.Name())

	cmd := exec.Command("masscan",
		"-p", fmt.Sprintf("%d", port),
		"--rate", fmt.Sprintf("%d", rate),
		"-iL", targetsFile,
		"-oG", tmpf.Name(),
		"--wait", "5",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return parseMasscanGreppable(tmpf.Name())
}

func parseMasscanGreppable(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var hosts []string
	seen := map[string]bool{}
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Host:") || !strings.Contains(line, "/open/") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[1]
		if !seen[ip] {
			seen[ip] = true
			hosts = append(hosts, ip)
		}
	}
	return hosts, sc.Err()
}

func readHostsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var hosts []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, line)
	}
	return hosts, sc.Err()
}

func probeHostHTTP(client *http.Client, ip string, fp Fingerprint, writeObs func(Observation)) {
	for _, p := range fp.HTTPProbes {
		url := fmt.Sprintf("http://%s:%d%s", ip, fp.Port, p.Path)
		req, err := http.NewRequest(p.Method, url, nil)
		if err != nil {
			writeObs(httpErrObs(ip, fp, p.Path, err))
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			writeObs(httpErrObs(ip, fp, p.Path, err))
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		matched, rules := matchHTTPFingerprint(fp, resp.Header, body)
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		writeObs(Observation{
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
			IP:              ip,
			Port:            fp.Port,
			FingerprintID:   fp.ID,
			ProbePath:       p.Path,
			Matched:         matched,
			MatchedRules:    rules,
			HTTPStatus:      resp.StatusCode,
			ResponseSnippet: snippet,
		})
		if matched {
			return
		}
	}
}

func httpErrObs(ip string, fp Fingerprint, path string, err error) Observation {
	return Observation{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		IP:            ip,
		Port:          fp.Port,
		FingerprintID: fp.ID,
		ProbePath:     path,
		Error:         err.Error(),
	}
}

func matchHTTPFingerprint(fp Fingerprint, headers http.Header, body []byte) (bool, []string) {
	var matched []string
	bodyL := strings.ToLower(string(body))
	var hdrL strings.Builder
	for k, v := range headers {
		hdrL.WriteString(strings.ToLower(k))
		hdrL.WriteString(": ")
		hdrL.WriteString(strings.ToLower(strings.Join(v, " ")))
		hdrL.WriteByte('\n')
	}
	hdrs := hdrL.String()

	for _, needle := range fp.MatchAnyCI {
		n := strings.ToLower(needle)
		if strings.Contains(bodyL, n) || strings.Contains(hdrs, n) {
			matched = append(matched, "any:"+needle)
		}
	}
	for _, group := range fp.MatchAllCI {
		all := true
		for _, n := range group {
			nl := strings.ToLower(n)
			if !strings.Contains(bodyL, nl) && !strings.Contains(hdrs, nl) {
				all = false
				break
			}
		}
		if all {
			matched = append(matched, "all:"+strings.Join(group, "+"))
		}
	}
	return len(matched) > 0, matched
}

// ---------- udp_raw path ----------

func runUDPScan(fp Fingerprint, targetsFile string, rate int, writeObs func(Observation)) {
	ips, err := expandTargets(targetsFile)
	if err != nil {
		die("expand targets: %v", err)
	}
	fmt.Fprintf(os.Stderr, "udp scan: %d IP(s) on port %d at %d pps\n", len(ips), fp.Port, rate)
	if len(ips) == 0 {
		return
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		die("udp listen: %v", err)
	}

	var listenerWG sync.WaitGroup
	listenerWG.Add(1)
	go func() {
		defer listenerWG.Done()
		buf := make([]byte, 4096)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // socket closed
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			processUDPResponse(fp, src.IP.String(), data, writeObs)
		}
	}()

	interval := time.Second / time.Duration(rate)
	if interval < time.Microsecond {
		interval = time.Microsecond
	}
	ticker := time.NewTicker(interval)
	sent := 0
	for _, ip := range ips {
		<-ticker.C
		if _, err := conn.WriteToUDP(fp.UDPPayload, &net.UDPAddr{IP: ip, Port: fp.Port}); err == nil {
			sent++
		}
	}
	ticker.Stop()
	fmt.Fprintf(os.Stderr, "sent %d/%d probes; waiting 3s for late responses\n", sent, len(ips))

	time.Sleep(3 * time.Second)
	conn.Close()
	listenerWG.Wait()
}

func processUDPResponse(fp Fingerprint, ip string, data []byte, writeObs func(Observation)) {
	matched := len(data) >= fp.UDPMinLen && bytes.HasPrefix(data, fp.UDPMatchPrefix)
	var rules []string
	if matched {
		rules = []string{fmt.Sprintf("udp_prefix:%s len>=%d", hex.EncodeToString(fp.UDPMatchPrefix), fp.UDPMinLen)}
	}
	snippet := hex.EncodeToString(data)
	if len(snippet) > 256 {
		snippet = snippet[:256]
	}
	writeObs(Observation{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		IP:            ip,
		Port:          fp.Port,
		FingerprintID: fp.ID,
		Matched:       matched,
		MatchedRules:  rules,
		ResponseHex:   snippet,
	})
}

func expandTargets(path string) ([]net.IP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ips []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			_, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "skip %q: %v\n", line, err)
				continue
			}
			for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
				ipCopy := make(net.IP, len(ip))
				copy(ipCopy, ip)
				ips = append(ips, ipCopy)
			}
		} else {
			ip := net.ParseIP(line)
			if ip == nil {
				fmt.Fprintf(os.Stderr, "skip %q: not a valid IP\n", line)
				continue
			}
			ips = append(ips, ip)
		}
	}
	return ips, sc.Err()
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			return
		}
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
