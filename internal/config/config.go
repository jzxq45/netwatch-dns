package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Interface     string `yaml:"interface"`    // LAN iface for SNI capture / device resolver
	UpstreamDNS   string `yaml:"upstream_dns"` // resolver PC forwards queries to
	DNSListen     string `yaml:"dns_listen"`   // UDP+TCP listener for the DNS server
	WebListen     string `yaml:"web_listen"`   // web UI / health endpoint
	DBPath        string `yaml:"db_path"`      // SQLite file
	RetentionDays int    `yaml:"retention_days"`
}

const (
	defaultUpstreamDNS = "1.1.1.1:53"
	defaultDNSListen   = "0.0.0.0:53"
	defaultWebListen   = "127.0.0.1:8080"
	defaultDBPath      = "monitor.db"
	defaultRetention   = 7
)

// Load reads YAML from path (missing file is fine — defaults apply) and
// overrides each field from MONITOR_* env vars.
func Load(path string) (Config, error) {
	cfg := Config{
		UpstreamDNS:   defaultUpstreamDNS,
		DNSListen:     defaultDNSListen,
		WebListen:     defaultWebListen,
		DBPath:        defaultDBPath,
		RetentionDays: defaultRetention,
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	for _, o := range overrides(&cfg) {
		if v := os.Getenv(o.env); v != "" {
			if err := o.apply(v); err != nil {
				return Config{}, err
			}
		}
	}
	if cfg.RetentionDays < 1 {
		return Config{}, fmt.Errorf("retention_days must be >= 1, got %d", cfg.RetentionDays)
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
	}
}
