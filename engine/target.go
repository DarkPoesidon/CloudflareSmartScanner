package engine

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Target represents a single scan end-point with an explicit port and scheme.
type Target struct {
	Label  string
	URL    string
	Host   string // Original hostname/domain (used for SNI / Host header spoofing)
	Port   int    // Explicit port to probe
	Scheme string // "https" or "http"
}

// ParseTargets reads domains.txt or Cache and parses them into Target slices.
// If scanAllPorts is true, each domain is expanded into 13 targets (one per CF port).
func ParseTargets(filePath string, scanAllPorts bool) ([]Target, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rawTargets []Target
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lbl := ""
		val := line

		if idx := strings.Index(line, "|"); idx != -1 {
			lbl = strings.TrimSpace(line[:idx])
			val = strings.TrimSpace(line[idx+1:])
		}

		val = strings.Trim(val, "'\"")

		// Handle CIDR blocks (e.g. 104.18.2.0/24)
		if strings.Contains(val, "/") && !strings.HasPrefix(val, "http") {
			ip, ipnet, err := net.ParseCIDR(val)
			if err == nil {
				for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
					ipStr := ip.String()
					if ipStr == ipnet.IP.String() {
						continue // skip network address
					}

					tLbl := ipStr
					if lbl != "" {
						tLbl = fmt.Sprintf("%s %s", lbl, ipStr)
					}
					rawTargets = append(rawTargets, Target{
						Label:  strings.TrimSpace(tLbl),
						URL:    "https://" + ipStr,
						Host:   ipStr,
						Port:   443,
						Scheme: "https",
					})
				}
				// Remove the last IP (broadcast address)
				if len(rawTargets) > 0 {
					rawTargets = rawTargets[:len(rawTargets)-1]
				}
				continue
			}
		}

		// Standard domain or single IP
		var host, scheme string
		if strings.HasPrefix(val, "http://") {
			scheme = "http"
			host = strings.TrimPrefix(val, "http://")
			host = strings.SplitN(host, "/", 2)[0]
		} else if strings.HasPrefix(val, "https://") {
			scheme = "https"
			host = strings.TrimPrefix(val, "https://")
			host = strings.SplitN(host, "/", 2)[0]
		} else {
			scheme = "https"
			host = val
		}

		finalLbl := lbl
		if finalLbl == "" {
			finalLbl = host
		}

		port := 443
		if scheme == "http" {
			port = 80
		}

		rawTargets = append(rawTargets, Target{
			Label:  finalLbl,
			URL:    scheme + "://" + host,
			Host:   host,
			Port:   port,
			Scheme: scheme,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// If ScanAllPorts is enabled, expand each unique host across all 13 CF ports.
	if scanAllPorts {
		return expandAllPorts(rawTargets), nil
	}

	return rawTargets, nil
}

// expandAllPorts takes a list of raw targets and for each unique host, creates
// one target per Cloudflare port (6 HTTPS + 7 HTTP = 13 per host).
func expandAllPorts(rawTargets []Target) []Target {
	var expanded []Target
	seen := make(map[string]struct{}) // track host to avoid double-expanding

	for _, t := range rawTargets {
		if _, exists := seen[t.Host]; exists {
			continue
		}
		seen[t.Host] = struct{}{}

		for _, port := range CFHTTPSPorts {
			expanded = append(expanded, Target{
				Label:  fmt.Sprintf("%s:%d", t.Label, port),
				URL:    fmt.Sprintf("https://%s:%d", t.Host, port),
				Host:   t.Host,
				Port:   port,
				Scheme: "https",
			})
		}
		for _, port := range CFHTTPPorts {
			expanded = append(expanded, Target{
				Label:  fmt.Sprintf("%s:%d", t.Label, port),
				URL:    fmt.Sprintf("http://%s:%d", t.Host, port),
				Host:   t.Host,
				Port:   port,
				Scheme: "http",
			})
		}
	}

	return expanded
}

// DeduplicateTargets returns a unique slice of targets, keeping the order of prioritized first.
func DeduplicateTargets(prioritized []Target, main []Target) []Target {
	seen := make(map[string]struct{})
	var result []Target

	for _, t := range prioritized {
		if _, exists := seen[t.URL]; !exists {
			seen[t.URL] = struct{}{}
			result = append(result, t)
		}
	}

	for _, t := range main {
		if _, exists := seen[t.URL]; !exists {
			seen[t.URL] = struct{}{}
			result = append(result, t)
		}
	}

	return result
}

// incIP increments an IP address.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
