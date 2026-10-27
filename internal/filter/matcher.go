// Package filter provides fast domain matching and blocklist parsing for
// hosts, adblock/easylist and plain-text formats.
package filter

import (
	"strings"
	"sync"
)

// Matcher stores exact domains and matches both the domain itself and all of
// its parent domains. Lookups are map based, so matching cost is proportional
// to the number of labels in the queried name. It is safe for concurrent use:
// background blocklist refreshes add rules while the DNS path matches.
type Matcher struct {
	mu     sync.RWMutex
	rules  map[string]struct{}
	allows map[string]struct{}
}

// NewMatcher creates an empty Matcher.
func NewMatcher() *Matcher {
	return &Matcher{
		rules:  make(map[string]struct{}),
		allows: make(map[string]struct{}),
	}
}

// Add inserts domain into the matcher. Empty values are ignored and the
// domain is normalized to lower case without a trailing dot.
func (m *Matcher) Add(domain string) {
	d := normalize(domain)
	if d == "" {
		return
	}
	m.mu.Lock()
	m.rules[d] = struct{}{}
	m.mu.Unlock()
}

// AddAllow inserts domain into the allowlist. Allow rules take precedence over
// block rules for the domain itself and all of its subdomains.
func (m *Matcher) AddAllow(domain string) {
	d := normalize(domain)
	if d == "" {
		return
	}
	m.mu.Lock()
	m.allows[d] = struct{}{}
	m.mu.Unlock()
}

// RemoveRule removes domain from both the blocklist and the allowlist.
func (m *Matcher) RemoveRule(domain string) {
	d := normalize(domain)
	if d == "" {
		return
	}
	m.mu.Lock()
	delete(m.rules, d)
	delete(m.allows, d)
	m.mu.Unlock()
}

// Match reports whether domain, or any of its parent domains, was added to
// the matcher. Allow rules win: a matching allow entry makes Match false even
// if a block rule would otherwise match. Matching is case-insensitive and
// ignores a trailing dot.
func (m *Matcher) Match(domain string) bool {
	d := normalize(domain)
	if d == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if matchesAny(m.allows, d) {
		return false
	}
	return matchesAny(m.rules, d)
}

func matchesAny(set map[string]struct{}, domain string) bool {
	for {
		if _, ok := set[domain]; ok {
			return true
		}
		i := strings.IndexByte(domain, '.')
		if i < 0 {
			return false
		}
		domain = domain[i+1:]
	}
}

// Count returns the number of unique rules in the matcher.
func (m *Matcher) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rules)
}

func normalize(domain string) string {
	d := strings.TrimSpace(domain)
	d = strings.TrimSuffix(d, ".")
	return strings.ToLower(d)
}
