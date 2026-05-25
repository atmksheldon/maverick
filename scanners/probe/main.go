// MAVERICK probe v0 — humanoid (Unitree WebRTC) discovery.
//
// Two-stage flow:
//   1. masscan SYN sweep on the fingerprint port over the targets file
//   2. HTTP banner grab against each open hit, apply fingerprint match rules
//
// Output is JSONL, one observation per probe attempt.
//
// The v0 fingerprint (Unitree WebRTC on tcp/8081) is hardcoded below. When
// we have more than one fingerprint we'll switch to parsing the YAML files
// under ../../fingerprints/ instead. See unitree_webrtc.yaml for the spec
// that mirrors what's in this file.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Fingerprint struct {
	ID           string
	Vendor       string
	DeviceClass  string
	Port         int
	Probes       []Probe
	MatchAnyCI   []string
	MatchAllCI   [][]string
}

type Probe struct {
	Method string
	Path   string
}

var unitreeWebRTC = Fingerprint{
	ID:          "unitree_webrtc",
	Vendor:      "unitree",
	DeviceClass: "quadruped_or_humanoid",
	Port:        8081,
	Probes: []Probe{
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
	Error           string   `json:"error,omitempty"`
}

const userAgent = "MAVERICK-research-scanner/0.1 (+https://github.com/atmksheldon/maverick)"

func main() {
	targetsFile := flag.String("targets", "", "file with one IP/CIDR per line (required)")
	rate := flag.Int("rate", 1000, "masscan packets per second")
	outFile := flag.String("out", "", "output JSONL file (default: stdout)")
	workers := flag.Int("workers", 10, "concurrent HTTP probes")
	skipMasscan := flag.Bool("skip-masscan", false, "skip masscan; treat --targets as known-open IPs (one per line)")
	flag.Parse()

	if *targetsFile == "" {
		fmt.Fprintln(os.Stderr, "missing --targets")
		flag.Usage()
		os.Exit(2)
	}

	fp := unitreeWebRTC

	out := io.Writer(os.Stdout)
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			die("open %s: %v", *outFile, err)
		}
		defer f.Close()
		out = f
	}

	var openHosts []string
	if *skipMasscan {
		hosts, err := readHostsFile(*targetsFile)
		if err != nil {
			die("read targets: %v", err)
		}
		openHosts = hosts
		fmt.Fprintf(os.Stderr, "skip-masscan: probing %d host(s) directly\n", len(openHosts))
	} else {
		hosts, err := runMasscan(*targetsFile, fp.Port, *rate)
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

	results := make(chan Observation, *workers)
	ch := make(chan string, *workers)
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ch {
				probeHost(client, ip, fp, results)
			}
		}()
	}
	go func() {
		for _, h := range openHosts {
			ch <- h
		}
		close(ch)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	enc := json.NewEncoder(out)
	var matched int
	for obs := range results {
		if err := enc.Encode(obs); err != nil {
			fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		}
		if obs.Matched {
			matched++
		}
	}
	fmt.Fprintf(os.Stderr, "done: %d matched of %d open\n", matched, len(openHosts))
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
		// e.g. "Host: 1.2.3.4 ()	Ports: 8081/open/tcp//..."
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

func probeHost(client *http.Client, ip string, fp Fingerprint, out chan<- Observation) {
	for _, p := range fp.Probes {
		url := fmt.Sprintf("http://%s:%d%s", ip, fp.Port, p.Path)
		req, err := http.NewRequest(p.Method, url, nil)
		if err != nil {
			out <- errObs(ip, fp, p.Path, err)
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			out <- errObs(ip, fp, p.Path, err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		matched, rules := matchFingerprint(fp, resp.Header, body)
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		out <- Observation{
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
			IP:              ip,
			Port:            fp.Port,
			FingerprintID:   fp.ID,
			ProbePath:       p.Path,
			Matched:         matched,
			MatchedRules:    rules,
			HTTPStatus:      resp.StatusCode,
			ResponseSnippet: snippet,
		}
		if matched {
			return
		}
	}
}

func errObs(ip string, fp Fingerprint, path string, err error) Observation {
	return Observation{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		IP:            ip,
		Port:          fp.Port,
		FingerprintID: fp.ID,
		ProbePath:     path,
		Error:         err.Error(),
	}
}

func matchFingerprint(fp Fingerprint, headers http.Header, body []byte) (bool, []string) {
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

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
