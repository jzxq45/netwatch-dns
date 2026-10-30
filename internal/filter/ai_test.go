package filter

import (
	"strings"
	"sync"
	"testing"
)

// TestAIDetectsDGA pins the DGA heuristic on labels with high entropy, missing
// vowels, long digit runs and risky TLDs — all scores must clear the block
// threshold and stay within the documented 0.85..0.95 band.
func TestAIDetectsDGA(t *testing.T) {
	t.Parallel()
	e := NewAIEngine()
	domains := []string{"x8a19bkc92.biz", "d7192fkznx91024.cc", "qzwxkjfn1.top"}
	for _, d := range domains {
		a := e.Analyze(d)
		if a.Threat != ThreatDGA {
			t.Errorf("%s: threat = %v, want DGA (score=%.2f reason=%q)", d, a.Threat, a.Score, a.Reason)
			continue
		}
		if a.Score < AIBlockThreshold || a.Score > 0.95 {
			t.Errorf("%s: score = %.3f, want within [0.85, 0.95]", d, a.Score)
		}
		if a.Reason == "" {
			t.Errorf("%s: empty reason", d)
		}
	}
}

// TestAIDetectsPhishing covers exact brand tokens, embedded brands with
// trigger words, typosquatting and brand-name-in-subdomain cases.
func TestAIDetectsPhishing(t *testing.T) {
	t.Parallel()
	e := NewAIEngine()
	domains := []string{
		"paypal-security-update.com",
		"login-appleid-verify.info",
		"steam-community-trade.xyz",
		"paypa1.com",
		"g00gle-login.com",
		"rnicrosoft-support.net",
		"appie-id.apple-verify.com",
	}
	for _, d := range domains {
		a := e.Analyze(d)
		if a.Threat != ThreatPhishing {
			t.Errorf("%s: threat = %v, want phishing (score=%.2f reason=%q)", d, a.Threat, a.Score, a.Reason)
			continue
		}
		if a.Score < AIBlockThreshold || a.Score > 0.98 {
			t.Errorf("%s: score = %.3f, want within [0.85, 0.98]", d, a.Score)
		}
	}
}

// TestAIAllowsLegitimate: trusted brands, their official subdomains, CDNs and
// LAN suffixes must never be flagged (false-positive guard).
func TestAIAllowsLegitimate(t *testing.T) {
	t.Parallel()
	e := NewAIEngine()
	domains := []string{
		"google.com",
		"paypal.com",
		"apple.com",
		"github.com",
		"my-home-server.lan",
		"nas.local",
		"router.home",
		"login.microsoft.com",
		"store.steampowered.com",
		"a.b.gstatic.com",
		"api.github.com",
		"ec2.us-east-1.amazonaws.com",
		"example.com",
		"doubleclick.net",
		"cdn.cloudflare.com",
	}
	for _, d := range domains {
		a := e.Analyze(d)
		if a.Threat != ThreatNone || a.Score != 0 {
			t.Errorf("%s: threat=%v score=%.2f, want none/0 (reason=%q)", d, a.Threat, a.Score, a.Reason)
		}
	}
}

// TestAIModerateSuspicious: some risk signals without a clear DGA verdict
// land in ThreatSuspicious, which must stay below the block threshold.
func TestAIModerateSuspicious(t *testing.T) {
	t.Parallel()
	e := NewAIEngine()
	a := e.Analyze("kqzmxq.win")
	if a.Threat != ThreatSuspicious {
		t.Fatalf("threat = %v (score=%.2f reason=%q), want suspicious", a.Threat, a.Score, a.Reason)
	}
	if a.Score >= AIBlockThreshold {
		t.Fatalf("suspicious-only name must not reach block threshold: %.2f", a.Score)
	}
}

// TestAIConcurrent: the engine is shared across resolver goroutines; run
// Analyze from many goroutines to catch accidental mutable state under -race.
func TestAIConcurrent(t *testing.T) {
	t.Parallel()
	e := NewAIEngine()
	domains := []string{"x8a19bkc92.biz", "google.com", "paypal-security-update.com", "example.com"}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				for _, d := range domains {
					_ = e.Analyze(d)
				}
			}
		}()
	}
	wg.Wait()
}

// TestThreatKindString pins the log-facing rendering.
func TestThreatKindString(t *testing.T) {
	t.Parallel()
	cases := map[ThreatKind]string{
		ThreatNone:       "none",
		ThreatDGA:        "dga",
		ThreatPhishing:   "phishing",
		ThreatSuspicious: "suspicious",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", int(k), got, want)
		}
	}
}

// TestAIAllocations proves the clean hot path is allocation-free: Analyze on
// an already-lowercase trusted domain must not touch the heap.
func TestAIAllocations(t *testing.T) {
	e := NewAIEngine()
	tests := []string{"google.com", "example.com", "nas.lan"}
	if n := testing.AllocsPerRun(1000, func() {
		for _, d := range tests {
			_ = e.Analyze(d)
		}
	}); n != 0 {
		t.Fatalf("Analyze allocations = %.1f per run, want 0 for clean names", n)
	}
}

// TestAIWhitelistBoundary: suffix trust must respect label boundaries.
func TestAIWhitelistBoundary(t *testing.T) {
	t.Parallel()
	e := NewAIEngine()
	if a := e.Analyze("notgoogle.com"); a.Threat != ThreatNone {
		t.Fatalf("notgoogle.com flagged as %v", a.Threat)
	}
	if a := e.Analyze("google.com.evil.example"); a.Threat == ThreatNone {
		t.Fatalf("brand in a subdomain of a non-official root must be phishing, got none")
	}
	if !strings.HasPrefix(e.Analyze("paypal-security-update.com").Reason, "brand impersonation") {
		t.Fatalf("unexpected reason for exact-brand impersonation")
	}
}
