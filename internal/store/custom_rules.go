package store

import (
	"context"
	"fmt"
	"time"
)

// CustomRule is a user-defined block/allow override for one domain.
type CustomRule struct {
	Domain    string
	Action    string // "block" or "allow"
	CreatedAt int64
}

const (
	RuleBlock = "block"
	RuleAllow = "allow"
)

// ListCustomRules returns every override, ordered by domain.
func (s *Store) ListCustomRules(ctx context.Context) ([]CustomRule, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT domain, action, created_at FROM custom_rules ORDER BY domain`)
	if err != nil {
		return nil, fmt.Errorf("list custom rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []CustomRule
	for rows.Next() {
		var r CustomRule
		if err := rows.Scan(&r.Domain, &r.Action, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan custom rule: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate custom rules: %w", err)
	}
	return out, nil
}

// SetCustomRule inserts or replaces the rule for domain.
func (s *Store) SetCustomRule(ctx context.Context, domain, action string) error {
	if action != RuleBlock && action != RuleAllow {
		return fmt.Errorf("invalid custom rule action %q", action)
	}
	_, err := s.write.ExecContext(ctx,
		`INSERT OR REPLACE INTO custom_rules (domain, action, created_at) VALUES (?, ?, ?)`,
		domain, action, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("set custom rule %s: %w", domain, err)
	}
	return nil
}

// DeleteCustomRule removes the rule for domain (no-op when absent).
func (s *Store) DeleteCustomRule(ctx context.Context, domain string) error {
	_, err := s.write.ExecContext(ctx,
		`DELETE FROM custom_rules WHERE domain = ?`, domain)
	if err != nil {
		return fmt.Errorf("delete custom rule %s: %w", domain, err)
	}
	return nil
}
