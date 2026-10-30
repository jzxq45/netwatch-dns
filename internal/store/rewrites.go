package store

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSRewrite is a local A/AAAA override: one domain mapped to one IP. Answers
// for rewritten domains are synthesized by the DNS engine without touching an
// upstream resolver (AdGuard Home style "DNS rewrites").
type DNSRewrite struct {
	Domain    string `json:"domain"`
	IP        string `json:"ip"`
	CreatedAt int64  `json:"created_at"`
}

// normalizeRewriteDomain lowercases, trims spaces and drops the trailing dot
// so the rewrite lookup is case-insensitive and FQDN-form agnostic.
func normalizeRewriteDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(domain, ".")
}

// ListRewrites returns every rewrite ordered by domain.
func (s *Store) ListRewrites(ctx context.Context) ([]DNSRewrite, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT domain, ip, created_at FROM dns_rewrites ORDER BY domain`)
	if err != nil {
		return nil, fmt.Errorf("list rewrites: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []DNSRewrite
	for rows.Next() {
		var r DNSRewrite
		if err := rows.Scan(&r.Domain, &r.IP, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan rewrite: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rewrites: %w", err)
	}
	return out, nil
}

// SetRewrite inserts or replaces the mapping for domain. The IP must parse
// (v4 or v6); the domain is stored normalized (lower-case, no trailing dot).
func (s *Store) SetRewrite(ctx context.Context, domain, ip string) error {
	domain = normalizeRewriteDomain(domain)
	if domain == "" {
		return fmt.Errorf("empty rewrite domain")
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid rewrite IP %q for %s", ip, domain)
	}
	_, err := s.write.ExecContext(ctx,
		`INSERT OR REPLACE INTO dns_rewrites (domain, ip, created_at) VALUES (?, ?, ?)`,
		domain, ip, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("set rewrite %s: %w", domain, err)
	}
	return nil
}

// DeleteRewrite removes the mapping for domain (no-op when absent).
func (s *Store) DeleteRewrite(ctx context.Context, domain string) error {
	_, err := s.write.ExecContext(ctx,
		`DELETE FROM dns_rewrites WHERE domain = ?`, normalizeRewriteDomain(domain))
	if err != nil {
		return fmt.Errorf("delete rewrite %s: %w", domain, err)
	}
	return nil
}
