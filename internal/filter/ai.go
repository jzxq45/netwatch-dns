// Package filter's AI engine is a local, dependency-free heuristic detector
// for zero-day DNS threats: algorithmically generated domains (DGA / botnet
// malware), brand impersonation / typosquatting (phishing) and general
// suspicious random-looking labels. It runs in the resolver hot path, holds
// no mutable state (safe for concurrent use) and allocates nothing for the
// vast majority of queries — clean names return before any string building.
package filter

import (
	"fmt"
	"math"
	"strings"
)

// ThreatKind classifies what (if anything) the heuristics recognized.
type ThreatKind int

const (
	ThreatNone ThreatKind = iota
	ThreatDGA
	ThreatPhishing
	ThreatSuspicious
)

// String makes slog/json output readable ("DGA", "phishing", ...).
func (t ThreatKind) String() string {
	switch t {
	case ThreatDGA:
		return "dga"
	case ThreatPhishing:
		return "phishing"
	case ThreatSuspicious:
		return "suspicious"
	default:
		return "none"
	}
}

// AIBlockThreshold is the score at/above which the resolver blocks the name.
const AIBlockThreshold = 0.85

// AIAnalysis is the verdict for one domain. Score is 0 for trusted/clean
// names and >= AIBlockThreshold for names the resolver must answer NXDOMAIN.
type AIAnalysis struct {
	Threat ThreatKind
	Score  float64
	Reason string
}

// AIEngine is the stateless heuristic classifier. All lookup tables are
// immutable after construction, so one instance can be shared by every
// resolver goroutine without locking.
type AIEngine struct {
	trusted   []string
	brands    []brandRule
	triggers  []string
	riskyTLDs map[string]bool
}

type brandRule struct {
	name     string
	official []string
}

// engine is process-wide; Analyze is read-only so sharing is safe.
var engine = &AIEngine{
	// Parents/CDNs and LAN suffixes trusted outright (false-positive guard).
	trusted: []string{
		"google.com", "apple.com", "paypal.com", "microsoft.com",
		"github.com", "amazon.com", "cloudflare.com", "akamaized.net",
		"cloudfront.net", "1e100.net", "fastly.net",
		"lan", "local", "home",
	},
	brands: []brandRule{
		{"paypal", []string{"paypal.com", "paypal.me", "paypalobjects.com"}},
		{"apple", []string{"apple.com", "icloud.com", "apple.co"}},
		{"google", []string{"google.com", "google.co.uk", "googleapis.com", "goo.gl", "gmail.com", "youtube.com", "youtu.be", "googleusercontent.com", "gstatic.com"}},
		{"microsoft", []string{"microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com", "windows.com", "azure.com", "bing.com", "msn.com", "xbox.com"}},
		{"netflix", []string{"netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net", "nflxso.net"}},
		{"amazon", []string{"amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com", "media-amazon.com", "a2z.com", "amazon-adsystem.com"}},
		{"binance", []string{"binance.com", "binance.us", "bnbstatic.com"}},
		{"steam", []string{"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com"}},
		{"telegram", []string{"telegram.org", "telegram.me", "t.me", "tdesktop.com", "telegram-cdn.org"}},
		{"facebook", []string{"facebook.com", "fb.com", "fbcdn.net", "facebook.net"}},
		{"instagram", []string{"instagram.com", "cdninstagram.com"}},
		{"whatsapp", []string{"whatsapp.com", "whatsapp.net", "wa.me"}},
		{"roblox", []string{"roblox.com", "rbxcdn.com", "robloxlabs.com"}},
		{"coinbase", []string{"coinbase.com", "coinbase.in"}},
		{"metamask", []string{"metamask.io", "metamask.app"}},
	},
	triggers: []string{
		"login", "verify", "account", "security", "update", "support",
		"billing", "wallet", "claim", "bonus", "gift", "secure",
	},
	riskyTLDs: map[string]bool{
		"top": true, "xyz": true, "cc": true, "buzz": true,
		"cfd": true, "sbs": true, "icu": true, "tk": true,
	},
}

// NewAIEngine returns the shared stateless engine.
func NewAIEngine() *AIEngine { return engine }

// Analyze scores domain against the whitelist, phishing and DGA heuristics.
// It is allocation-free on the clean path (strings.ToLower returns the input
// unchanged when no upper-case rune is present).
func (e *AIEngine) Analyze(domain string) AIAnalysis {
	if e == nil {
		return AIAnalysis{}
	}
	name := strings.ToLower(strings.TrimSpace(domain))
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return AIAnalysis{}
	}
	for _, trusted := range e.trusted {
		if hasDomainSuffix(name, trusted) {
			return AIAnalysis{}
		}
	}

	rest, tld := name, ""
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		rest, tld = name[:i], name[i+1:]
	}
	if a, ok := e.analyzePhishing(name, rest, tld); ok {
		return a
	}
	return e.analyzeDGA(rest, tld)
}

// hasDomainSuffix reports whether name equals suffix or is a subdomain of it
// (full label boundary; "notgoogle.com" does not match "google.com").
func hasDomainSuffix(name, suffix string) bool {
	if name == suffix {
		return true
	}
	if len(name) <= len(suffix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	return name[len(name)-len(suffix)-1] == '.'
}

// analyzePhishing looks for a protected brand in a domain that is not one of
// that brand's official domains: exact token ("paypal-security-update.com"),
// embedded prefix with trigger words ("login-appleid-verify.info") or a
// homoglyph/typosquat ("paypa1", "g00gle", "rnicrosoft", "appie").
func (e *AIEngine) analyzePhishing(name, rest, tld string) (AIAnalysis, bool) {
	for _, b := range e.brands {
		for _, off := range b.official {
			if hasDomainSuffix(name, off) {
				return AIAnalysis{}, false
			}
		}
	}

	triggers := 0
	exact, prefix, typo := "", "", ""
	forEachToken(rest, func(tok string) bool {
		for _, t := range e.triggers {
			if tok == t {
				triggers++
			}
		}
		for _, b := range e.brands {
			if tok == b.name {
				if exact == "" {
					exact = b.name
				}
				continue
			}
			if prefix == "" && len(tok) > len(b.name)+1 && strings.HasPrefix(tok, b.name) {
				prefix = b.name
			}
			if typo == "" && canonicalEquals(tok, b.name) {
				typo = b.name
			}
		}
		return true
	})

	impersonated := exact
	switch {
	case typo != "":
		impersonated = typo
	case impersonated == "" && prefix != "" && triggers > 0:
		impersonated = prefix
	}
	if impersonated == "" {
		return AIAnalysis{}, false
	}

	score := 0.90
	reason := "brand impersonation of " + impersonated
	if typo != "" {
		score = 0.96
		reason = "typosquatting " + impersonated
	}
	if triggers > 3 {
		triggers = 3
	}
	score += float64(triggers) * 0.02
	if e.riskyTLDs[tld] {
		score += 0.01
	}
	if score > 0.98 {
		score = 0.98
	}
	return AIAnalysis{Threat: ThreatPhishing, Score: score, Reason: reason}, true
}

// analyzeDGA scores every label token (split on '.' and '-') and classifies
// the name from the most suspicious one. Thresholds are tuned so known DGA
// shapes score >= 0.85 while ordinary words stay well below it.
func (e *AIEngine) analyzeDGA(rest, tld string) AIAnalysis {
	best, bestTok := 0, ""
	bestEnt, bestVR, bestDR := 0.0, 0.0, 0.0
	forEachToken(rest, func(tok string) bool {
		if p, ent, vr, dr := dgaTokenPoints(tok); p > best {
			best, bestTok, bestEnt, bestVR, bestDR = p, tok, ent, vr, dr
		}
		return true
	})
	if best == 0 {
		return AIAnalysis{}
	}
	if e.riskyTLDs[tld] {
		best++
	}
	switch {
	case best < 5:
		return AIAnalysis{}
	case best < 8:
		return AIAnalysis{
			Threat: ThreatSuspicious,
			Score:  0.50 + float64(best-5)*0.04,
			Reason: fmt.Sprintf("suspicious label %q", bestTok),
		}
	default:
		score := 0.85 + 0.10*math.Min(1, float64(best-8)/8)
		return AIAnalysis{
			Threat: ThreatDGA,
			Score:  score,
			Reason: fmt.Sprintf("dga-like label %q (entropy=%.2f vowels=%.2f digits=%.2f)",
				bestTok, bestEnt, bestVR, bestDR),
		}
	}
}

// dgaTokenPoints accumulates risk points for one label token. It returns the
// points plus the measured features for the log line.
func dgaTokenPoints(tok string) (points int, entropy, vowelRatio, digitRatio float64) {
	n := len(tok)
	if n < 6 {
		return 0, 0, 0, 0
	}

	var counts [256]uint16
	letters, vowels, digits := 0, 0, 0
	maxCons, maxDigit, runCons, runDigit, transitions := 0, 0, 0, 0, 0
	prevClass := 0 // 1 letter, 2 digit

	for i := 0; i < n; i++ {
		c := tok[i]
		counts[c]++
		switch {
		case c >= '0' && c <= '9':
			digits++
			runDigit++
			if runCons > maxCons {
				maxCons = runCons
			}
			runCons = 0
			if prevClass == 1 {
				transitions++
			}
			prevClass = 2
		case c >= 'a' && c <= 'z':
			letters++
			isVowel := c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u'
			if isVowel {
				vowels++
				if runCons > maxCons {
					maxCons = runCons
				}
				runCons = 0
			} else {
				runCons++
			}
			if runDigit > maxDigit {
				maxDigit = runDigit
			}
			runDigit = 0
			if prevClass == 2 {
				transitions++
			}
			prevClass = 1
		default:
			// Hyphen/underscore/other breaks both runs and the class chain.
			if runCons > maxCons {
				maxCons = runCons
			}
			if runDigit > maxDigit {
				maxDigit = runDigit
			}
			runCons, runDigit, prevClass = 0, 0, 0
		}
	}
	if runCons > maxCons {
		maxCons = runCons
	}
	if runDigit > maxDigit {
		maxDigit = runDigit
	}
	if letters == 0 {
		// Digit-only label: no language can produce this; DGA/analytics bait.
		if digits >= 6 {
			return 8, 0, 0, 1
		}
		return 0, 0, 0, 1
	}

	entropy = 0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(n)
		entropy -= p * math.Log2(p)
	}
	vowelRatio = float64(vowels) / float64(n)
	digitRatio = float64(digits) / float64(n)

	switch {
	case entropy >= 3.6:
		points += 4
	case entropy >= 3.0:
		points += 3
	case entropy >= 2.7:
		points += 2
	case entropy >= 2.4:
		points++
	}
	switch {
	case vowelRatio < 0.15:
		points += 3
	case vowelRatio < 0.22:
		points += 2
	case vowelRatio > 0.80:
		points += 2
	}
	switch {
	case digitRatio >= 0.4:
		points += 3
	case digitRatio >= 0.2:
		points += 2
	case digitRatio >= 0.1:
		points++
	}
	switch {
	case maxCons >= 5:
		points += 3
	case maxCons >= 4:
		points += 2
	}
	switch {
	case maxDigit >= 5:
		points += 3
	case maxDigit >= 4:
		points += 2
	case maxDigit >= 3:
		points++
	}
	switch {
	case transitions >= 4:
		points += 2
	case transitions >= 2:
		points++
	}
	switch {
	case n >= 15:
		points += 2
	case n >= 12:
		points++
	}
	return points, entropy, vowelRatio, digitRatio
}

// forEachToken walks labels (split '.') and their hyphen-separated tokens of
// rest without allocating slices. fn returns false to stop early.
func forEachToken(rest string, fn func(tok string) bool) {
	labelStart := 0
	for i := 0; i <= len(rest); i++ {
		if i != len(rest) && rest[i] != '.' {
			continue
		}
		label := rest[labelStart:i]
		tokStart := 0
		for j := 0; j <= len(label); j++ {
			if j != len(label) && label[j] != '-' {
				continue
			}
			if tok := label[tokStart:j]; tok != "" {
				if !fn(tok) {
					return
				}
			}
			tokStart = j + 1
		}
		labelStart = i + 1
	}
}

// canonicalEquals reports whether tok is a homoglyph/typo variant of brand
// (paypa1→paypal, g00gle→google, rnicrosoft→microsoft, appie→apple).
// Byte-wise with bounded backtracking, allocation-free.
func canonicalEquals(tok, brand string) bool {
	if tok == brand {
		return false
	}
	return canonMatch(tok, brand)
}

func canonMatch(tok, brand string) bool {
	if tok == "" {
		return brand == ""
	}
	if len(tok) >= 2 && len(brand) > 0 {
		var pair byte
		switch tok[:2] {
		case "rn":
			pair = 'm'
		case "vv":
			pair = 'w'
		}
		if pair != 0 && brand[0] == pair && canonMatch(tok[2:], brand[1:]) {
			return true
		}
	}
	if len(brand) == 0 {
		return false
	}
	c := tok[0]
	if brand[0] == c && canonMatch(tok[1:], brand[1:]) {
		return true
	}
	if homoglyphMatch(c, brand[0]) && canonMatch(tok[1:], brand[1:]) {
		return true
	}
	return false
}

// homoglyphMatch maps the common digit/symbol look-alikes onto letters.
func homoglyphMatch(c, want byte) bool {
	switch c {
	case '0':
		return want == 'o'
	case '1':
		return want == 'l' || want == 'i'
	case '3':
		return want == 'e'
	case '4', '@':
		return want == 'a'
	case '5', '$':
		return want == 's'
	case '7':
		return want == 't'
	case 'i':
		return want == 'l'
	}
	return false
}
