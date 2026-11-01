package filter

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMatchSafeSearch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		domain    string
		wantMatch bool
		wantCNAME string
	}{
		// Google
		{"google.com", true, "forcesafesearch.google.com."},
		{"www.google.com", true, "forcesafesearch.google.com."},
		{"google.ru", true, "forcesafesearch.google.com."},
		{"google.co.uk", true, "forcesafesearch.google.com."},
		{"www.google.de", true, "forcesafesearch.google.com."},
		{"google.com.br", true, "forcesafesearch.google.com."},
		{"forcesafesearch.google.com", false, ""},
		{"drive.google.com", false, ""},
		{"mail.google.com", false, ""},
		{"accounts.google.com", false, ""},
		{"notgoogle.com", false, ""},

		// YouTube
		{"youtube.com", true, "restrict.youtube.com."},
		{"www.youtube.com", true, "restrict.youtube.com."},
		{"m.youtube.com", true, "restrict.youtube.com."},
		{"youtubei.googleapis.com", true, "restrict.youtube.com."},
		{"music.youtube.com", false, ""},

		// Bing
		{"bing.com", true, "strict.bing.com."},
		{"www.bing.com", true, "strict.bing.com."},
		{"cn.bing.com", true, "strict.bing.com."},
		{"api.bing.com", false, ""},

		// DuckDuckGo
		{"duckduckgo.com", true, "safe.duckduckgo.com."},
		{"www.duckduckgo.com", true, "safe.duckduckgo.com."},
		{"api.duckduckgo.com", false, ""},

		// Yandex
		{"yandex.ru", true, "family.yandex.ru."},
		{"www.yandex.ru", true, "family.yandex.ru."},
		{"ya.ru", true, "family.yandex.ru."},
		{"www.ya.ru", true, "family.yandex.ru."},
		{"yandex.com", true, "family.yandex.ru."},
		{"mail.yandex.ru", false, ""},

		// Other
		{"example.com", false, ""},
		{"github.com", false, ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.domain, func(t *testing.T) {
			t.Parallel()
			rule, ok := MatchSafeSearch(tc.domain)
			if ok != tc.wantMatch {
				t.Fatalf("MatchSafeSearch(%q) = %v, want %v", tc.domain, ok, tc.wantMatch)
			}
			if ok && rule.CNAME != tc.wantCNAME {
				t.Fatalf("rule.CNAME = %q, want %q", rule.CNAME, tc.wantCNAME)
			}
		})
	}
}

func TestSafeSearchRewrite(t *testing.T) {
	t.Parallel()

	// 1. Google TypeA
	msgA := new(dns.Msg)
	msgA.SetQuestion("www.google.com.", dns.TypeA)
	respA := SafeSearchRewrite(msgA)
	if respA == nil {
		t.Fatal("expected SafeSearchRewrite response for Google TypeA")
	}
	if len(respA.Answer) != 2 {
		t.Fatalf("expected 2 answers (CNAME + A), got %d", len(respA.Answer))
	}
	cname, ok := respA.Answer[0].(*dns.CNAME)
	if !ok || cname.Target != "forcesafesearch.google.com." {
		t.Fatalf("expected CNAME to forcesafesearch.google.com., got %v", respA.Answer[0])
	}
	aRec, ok := respA.Answer[1].(*dns.A)
	if !ok || aRec.A.String() != "216.239.38.120" {
		t.Fatalf("expected A 216.239.38.120, got %v", respA.Answer[1])
	}

	// 2. Google TypeAAAA
	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion("google.com.", dns.TypeAAAA)
	respAAAA := SafeSearchRewrite(msgAAAA)
	if respAAAA == nil || len(respAAAA.Answer) != 2 {
		t.Fatalf("expected CNAME + AAAA for google.com, got %v", respAAAA)
	}
	aaaaRec, ok := respAAAA.Answer[1].(*dns.AAAA)
	if !ok || aaaaRec.AAAA.String() != "2001:4860:4806::78" {
		t.Fatalf("expected AAAA 2001:4860:4806::78, got %v", respAAAA.Answer[1])
	}

	// 3. YouTube TypeA
	msgYT := new(dns.Msg)
	msgYT.SetQuestion("youtube.com.", dns.TypeA)
	respYT := SafeSearchRewrite(msgYT)
	if respYT == nil || len(respYT.Answer) != 2 {
		t.Fatalf("expected CNAME + A for youtube.com, got %v", respYT)
	}

	// 4. Bing TypeA
	msgBing := new(dns.Msg)
	msgBing.SetQuestion("bing.com.", dns.TypeA)
	respBing := SafeSearchRewrite(msgBing)
	if respBing == nil || len(respBing.Answer) != 2 {
		t.Fatalf("expected CNAME + A for bing.com, got %v", respBing)
	}

	// 5. HTTPS type (Type 65) should return empty NOERROR (NODATA)
	msgHTTPS := new(dns.Msg)
	msgHTTPS.SetQuestion("www.google.com.", 65) // TypeHTTPS
	respHTTPS := SafeSearchRewrite(msgHTTPS)
	if respHTTPS == nil {
		t.Fatal("expected empty NOERROR response for HTTPS query to prevent bypass")
	}
	if len(respHTTPS.Answer) != 0 || respHTTPS.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected 0 answers with NOERROR, got %d answers, rcode=%d", len(respHTTPS.Answer), respHTTPS.Rcode)
	}

	// 6. Non-search engine should return nil
	msgOther := new(dns.Msg)
	msgOther.SetQuestion("github.com.", dns.TypeA)
	if SafeSearchRewrite(msgOther) != nil {
		t.Fatal("expected nil rewrite for github.com")
	}
}
