package filter

import (
	"strings"
	"testing"
)

func TestParseHosts(t *testing.T) {
	input := `
# hosts style
0.0.0.0 bad.com
127.0.0.1 tracker.org
127.0.0.1 localhost
0.0.0.0 broadcasthost
::1 ip6-localhost

0.0.0.0 Another.Example. # trailing dot and case
`
	got, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"bad.com", "tracker.org", "another.example"}
	assertDomains(t, got, want)
}

func TestParseHostsMultiDomain(t *testing.T) {
	input := `
0.0.0.0 ad1.com ad2.com ad3.com # comment
127.0.0.1 tracker1.org tracker2.org
`
	got, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"ad1.com", "ad2.com", "ad3.com", "tracker1.org", "tracker2.org"}
	assertDomains(t, got, want)
}

func TestParseAdblock(t *testing.T) {
	input := `
! easylist comment
||adservice.com^
||ads.tracker.net^$third-party
||plainad.org
# mixed comment
`
	got, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"adservice.com", "ads.tracker.net", "plainad.org"}
	assertDomains(t, got, want)
}

func TestParsePlain(t *testing.T) {
	input := `
badsite.ru
evil.example.
BADSITE.RU
# comment
! comment

localhost
127.0.0.1
0.0.0.0
broadcasthost
`
	got, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"badsite.ru", "evil.example"}
	assertDomains(t, got, want)
}

func TestParseMixed(t *testing.T) {
	input := "0.0.0.0 hosts.com\n||adblock.com^\nplain.com\n"
	got, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertDomains(t, got, []string{"hosts.com", "adblock.com", "plain.com"})
}

func TestMatcherExact(t *testing.T) {
	m := NewMatcher()
	m.Add("bad.com")

	if !m.Match("bad.com") {
		t.Fatal("expected exact match for bad.com")
	}
	if !m.Match("BAD.COM") {
		t.Fatal("expected case-insensitive match for BAD.COM")
	}
	if !m.Match("bad.com.") {
		t.Fatal("expected match ignoring trailing dot")
	}
	if m.Match("notbad.com") {
		t.Fatal("notbad.com must not match the bad.com rule")
	}
	if m.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", m.Count())
	}
}

func TestMatcherSubdomain(t *testing.T) {
	m := NewMatcher()
	m.Add("bad.com")

	for _, domain := range []string{"sub.bad.com", "a.b.bad.com", "SUB.BAD.COM."} {
		if !m.Match(domain) {
			t.Fatalf("expected subdomain match for %q", domain)
		}
	}
	if m.Match("sub.notbad.com") {
		t.Fatal("sub.notbad.com must not match the bad.com rule")
	}
	if m.Match("bad.com.evil.org") {
		t.Fatal("bad.com.evil.org must not match the bad.com rule")
	}
}

func TestMatcherParentRule(t *testing.T) {
	m := NewMatcher()
	m.Add("com")

	if !m.Match("example.com") {
		t.Fatal("expected parent-domain rule to match example.com")
	}
	if m.Match("example.org") {
		t.Fatal("example.org must not match the com rule")
	}
}

func TestMatcherCountAndDuplicates(t *testing.T) {
	m := NewMatcher()
	m.Add("bad.com")
	m.Add("BAD.COM.")
	m.Add("other.org")
	m.Add("")

	if m.Count() != 2 {
		t.Fatalf("Count() = %d, want 2", m.Count())
	}
}

func TestMatcherAllowlist(t *testing.T) {
	m := NewMatcher()
	m.Add("bad.com")
	m.AddAllow("safe.bad.com")

	for _, domain := range []string{"safe.bad.com", "sub.safe.bad.com", "SAFE.BAD.COM."} {
		if m.Match(domain) {
			t.Fatalf("allowlisted domain %q must not match", domain)
		}
	}
	if !m.Match("bad.com") {
		t.Fatal("bad.com must still match")
	}
	if !m.Match("other.bad.com") {
		t.Fatal("other.bad.com must still match")
	}
}

func TestMatcherAllowlistParentWins(t *testing.T) {
	m := NewMatcher()
	m.Add("ads.example.com")
	m.AddAllow("example.com")

	if m.Match("ads.example.com") {
		t.Fatal("parent allow rule must override a blocked child")
	}
	if m.Match("tracker.example.com") {
		t.Fatal("allowlisted parent must cover all subdomains")
	}
}

func TestMatcherRemoveRule(t *testing.T) {
	m := NewMatcher()
	m.Add("tracker.com")
	m.AddAllow("tracker.com")

	if m.Match("tracker.com") {
		t.Fatal("allow rule must win before removal")
	}
	m.RemoveRule("tracker.com")
	if m.Match("tracker.com") {
		t.Fatal("RemoveRule must drop both the block and allow rule")
	}
	if m.Count() != 0 {
		t.Fatalf("Count() = %d, want 0", m.Count())
	}
}

func TestMatcherEmpty(t *testing.T) {
	m := NewMatcher()
	if m.Match("bad.com") {
		t.Fatal("empty matcher must not match")
	}
	if m.Match("") {
		t.Fatal("empty matcher must not match an empty domain")
	}
}

func assertDomains(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
