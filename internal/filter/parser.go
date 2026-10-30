package filter

import (
	"bufio"
	"io"
	"net"
	"strings"
)

const maxLineSize = 1024 * 1024

// localNames are hostnames that never represent a blockable remote domain.
var localNames = map[string]struct{}{
	"localhost":             {},
	"localhost.localdomain": {},
	"broadcasthost":         {},
	"ip6-localhost":         {},
	"ip6-loopback":          {},
	"127.0.0.1":             {},
	"::1":                   {},
	"0.0.0.0":               {},
}

// Parse reads a blocklist in hosts, adblock/easylist or plain-text format and
// returns normalized, deduplicated domains in their original order.
func Parse(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxLineSize)

	var domains []string
	seen := make(map[string]struct{})

	for scanner.Scan() {
		lineDomains := parseLine(scanner.Text())
		for _, domain := range lineDomains {
			if domain == "" {
				continue
			}
			if _, ok := seen[domain]; ok {
				continue
			}
			seen[domain] = struct{}{}
			domains = append(domains, domain)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

func parseLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return nil
	}

	// Adblock/easylist: ||example.com^, ||example.com^$third-party, ...
	if strings.HasPrefix(line, "||") {
		line = strings.TrimPrefix(line, "||")
		if i := strings.IndexAny(line, "^$"); i >= 0 {
			line = line[:i]
		}
		if d := cleanDomain(line); d != "" {
			return []string{d}
		}
		return nil
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}

	// Hosts: "0.0.0.0 bad.com bad2.com" / "127.0.0.1 tracker.org".
	// Many hosts lists (like StevenBlack) group multiple domains per line.
	if len(fields) > 1 && net.ParseIP(fields[0]) != nil {
		var out []string
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "#") {
				break // inline comment in hosts file
			}
			if d := cleanDomain(f); d != "" {
				out = append(out, d)
			}
		}
		return out
	}

	// Plain text: one domain per line (an inline comment is ignored).
	if d := cleanDomain(fields[0]); d != "" {
		return []string{d}
	}
	return nil
}

func cleanDomain(domain string) string {
	d := normalize(domain)
	if d == "" {
		return ""
	}
	if _, local := localNames[d]; local {
		return ""
	}
	return d
}
