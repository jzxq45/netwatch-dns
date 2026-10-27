package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Interface             string   `yaml:"interface"`                   // LAN iface for SNI capture / device resolver
	UpstreamDNS           string   `yaml:"upstream_dns"`                // resolver PC forwards queries to
	FallbackUpstream      string   `yaml:"fallback_upstream,omitempty"` // used when the primary upstream fails
	DNSListen             string   `yaml:"dns_listen"`                  // UDP+TCP listener for the DNS server
	WebListen             string   `yaml:"web_listen"`                  // web UI / health endpoint
	DBPath                string   `yaml:"db_path"`                     // SQLite file
	RetentionDays         int      `yaml:"retention_days"`
	DoHBlocklist          []string `yaml:"doh_blocklist"`                     // replaces built-in list when set
	BlocklistFiles        []string `yaml:"blocklist_files,omitempty"`         // extra hosts/adblock files
	BlocklistURLs         []string `yaml:"blocklist_urls,omitempty"`          // remote hosts/adblock lists
	BlocklistRefreshHours int      `yaml:"blocklist_refresh_hours,omitempty"` // refresh period; 0 disables
	SkipPTR               bool     `yaml:"skip_ptr"`                          // swallow PTR in-addr.arpa queries locally
	SearchSuffixes        []string `yaml:"search_suffixes"`                   // stripped from logged domain names
	DoHLogLevel           string   `yaml:"doh_log_level"`                     // debug|info|off for dns_blocked_doh
	DoHWindow             string   `yaml:"doh_aggregate_window"`              // e.g. 10s
	NoiseDomains          []string `yaml:"noise_domains"`                     // bg traffic: noise=1 in db, hidden from stdout/feed
	WebToken              string   `yaml:"web_token"`                         // when set: web UI needs X-Auth-Token / ?token= / cookie
}

const (
	defaultUpstreamDNS   = "1.1.1.1:53"
	defaultFallbackDNS   = "1.0.0.1:53"
	defaultDNSListen     = "0.0.0.0:53"
	defaultWebListen     = "127.0.0.1:8080"
	defaultDBPath        = "monitor.db"
	defaultRetention     = 7
	defaultBlocklistFile = "blocklist.txt"
)

// Load reads YAML from path (missing file is fine — defaults apply) and
// overrides each field from MONITOR_* env vars.
func Load(path string) (Config, error) {
	cfg := Config{
		UpstreamDNS:      defaultUpstreamDNS,
		FallbackUpstream: defaultFallbackDNS,
		DNSListen:        defaultDNSListen,
		WebListen:        defaultWebListen,
		DBPath:           defaultDBPath,
		RetentionDays:    defaultRetention,
		SkipPTR:          true,    // router/OS PTR noise is swallowed by default
		DoHLogLevel:      "debug", // aggregated blocks stay out of Info output
		DoHWindow:        "10s",   // aggregation window for dns_blocked_doh

		BlocklistRefreshHours: 24, // remote-list refresh period
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	} else {
		// Missing file is allowed, but must not stay silent: operators should
		// know defaults are in effect instead of wondering why their config
		// "didn't apply".
		slog.Warn("config file not found, defaults apply", "path", path)
	}
	for _, o := range overrides(&cfg) {
		if v := os.Getenv(o.env); v != "" {
			if err := o.apply(v); err != nil {
				return Config{}, err
			}
		}
	}
	// Work out of the box: when no list files are configured explicitly,
	// pick up the bundled blocklist.txt sitting next to the executable/cwd.
	if len(cfg.BlocklistFiles) == 0 {
		if _, err := os.Stat(defaultBlocklistFile); err == nil {
			cfg.BlocklistFiles = []string{defaultBlocklistFile}
		}
	}
	if cfg.RetentionDays < 1 {
		return Config{}, fmt.Errorf("retention_days must be >= 1, got %d", cfg.RetentionDays)
	}
	// Address fields are used by listeners/clients as host:port verbatim;
	// validate here so a broken config fails fast instead of at first bind.
	// host:port only — IPv6 literals need net.JoinHostPort on the caller's
	// side, bare hosts are invalid here.
	for _, addr := range []struct{ name, val string }{
		{"upstream_dns", cfg.UpstreamDNS},
		{"dns_listen", cfg.DNSListen},
		{"web_listen", cfg.WebListen},
	} {
		if _, _, err := net.SplitHostPort(addr.val); err != nil {
			return Config{}, fmt.Errorf("%s %q: need host:port (net.JoinHostPort for IPv6 literals): %w", addr.name, addr.val, err)
		}
	}
	// Fallback may be a plain host:port or a DoH endpoint (https://...);
	// only the former is validated here.
	if cfg.FallbackUpstream != "" &&
		!strings.HasPrefix(cfg.FallbackUpstream, "https://") &&
		!strings.HasPrefix(cfg.FallbackUpstream, "http://") {
		if _, _, err := net.SplitHostPort(cfg.FallbackUpstream); err != nil {
			return Config{}, fmt.Errorf("fallback_upstream %q: need host:port or https:// URL: %w", cfg.FallbackUpstream, err)
		}
	}
	return cfg, nil
}

type override struct {
	env   string
	apply func(string) error
}

func overrides(c *Config) []override {
	return []override{
		{"MONITOR_INTERFACE", func(v string) error { c.Interface = v; return nil }},
		{"MONITOR_UPSTREAM_DNS", func(v string) error { c.UpstreamDNS = v; return nil }},
		{"MONITOR_FALLBACK_UPSTREAM", func(v string) error { c.FallbackUpstream = v; return nil }},
		{"MONITOR_DNS_LISTEN", func(v string) error { c.DNSListen = v; return nil }},
		{"MONITOR_WEB_LISTEN", func(v string) error { c.WebListen = v; return nil }},
		{"MONITOR_DB_PATH", func(v string) error { c.DBPath = v; return nil }},
		{"MONITOR_RETENTION_DAYS", func(v string) error {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("MONITOR_RETENTION_DAYS: %w", err)
			}
			c.RetentionDays = n
			return nil
		}},
		{"MONITOR_WEB_TOKEN", func(v string) error { c.WebToken = v; return nil }},
	}
}
