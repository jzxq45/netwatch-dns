// Package filter implements DNS filtering, heuristic threat detection, and
// search engine safe-search enforcement.
package filter

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// SafeSearchRule describes the rewrite target for a search provider.
type SafeSearchRule struct {
	CNAME string
	IPv4  net.IP
	IPv6  net.IP
}

var (
	googleSafeSearch = SafeSearchRule{
		CNAME: "forcesafesearch.google.com.",
		IPv4:  net.ParseIP("216.239.38.120"),
		IPv6:  net.ParseIP("2001:4860:4806::78"),
	}

	youtubeSafeSearch = SafeSearchRule{
		CNAME: "restrict.youtube.com.",
		IPv4:  net.ParseIP("216.239.38.119"),
		IPv6:  net.ParseIP("2001:4860:4806::77"),
	}

	bingSafeSearch = SafeSearchRule{
		CNAME: "strict.bing.com.",
		IPv4:  net.ParseIP("204.79.197.220"),
	}

	duckduckgoSafeSearch = SafeSearchRule{
		CNAME: "safe.duckduckgo.com.",
		IPv4:  net.ParseIP("52.142.124.215"),
	}

	yandexSafeSearch = SafeSearchRule{
		CNAME: "family.yandex.ru.",
		IPv4:  net.ParseIP("77.88.8.7"),
	}

	pixabaySafeSearch = SafeSearchRule{
		CNAME: "safesearch.pixabay.com.",
	}
)

var googleCCSLDs = map[string]struct{}{
	"com": {}, "co": {}, "org": {}, "net": {}, "edu": {}, "gov": {},
	"ac": {}, "ne": {}, "or": {}, "in": {}, "it": {},
}

var youtubeDomains = map[string]struct{}{
	"youtube.com":              {},
	"www.youtube.com":          {},
	"m.youtube.com":            {},
	"youtubei.googleapis.com":  {},
	"youtube.googleapis.com":   {},
	"www.youtube-nocookie.com": {},
	"youtube-nocookie.com":     {},
}

var yandexDomains = map[string]struct{}{
	"yandex.ru":      {},
	"www.yandex.ru":  {},
	"ya.ru":          {},
	"www.ya.ru":      {},
	"yandex.com":     {},
	"www.yandex.com": {},
	"yandex.by":      {},
	"www.yandex.by":  {},
	"yandex.kz":      {},
	"www.yandex.kz":  {},
	"yandex.uz":      {},
	"www.yandex.uz":  {},
}

// MatchSafeSearch checks if domain is a supported search engine and returns
// its SafeSearch rule. If not matched, ok is false.
func MatchSafeSearch(domain string) (rule SafeSearchRule, ok bool) {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if d == "" {
		return SafeSearchRule{}, false
	}

	// 1. YouTube
	if _, found := youtubeDomains[d]; found {
		return youtubeSafeSearch, true
	}

	// 2. Bing
	if d == "bing.com" || d == "www.bing.com" || d == "cn.bing.com" {
		return bingSafeSearch, true
	}

	// 3. DuckDuckGo
	if d == "duckduckgo.com" || d == "www.duckduckgo.com" {
		return duckduckgoSafeSearch, true
	}

	// 4. Yandex
	if _, found := yandexDomains[d]; found {
		return yandexSafeSearch, true
	}

	// 5. Pixabay
	if d == "pixabay.com" || d == "www.pixabay.com" {
		return pixabaySafeSearch, true
	}

	// 6. Google search (google.com, www.google.com, google.co.uk, google.ru, etc.)
	// Do not rewrite special subdomains (drive, mail, accounts, docs, etc.) or VIPs
	if strings.HasPrefix(d, "forcesafesearch.") || strings.HasPrefix(d, "restrict.") {
		return SafeSearchRule{}, false
	}
	clean := strings.TrimPrefix(d, "www.")
	parts := strings.Split(clean, ".")
	if len(parts) >= 2 && parts[0] == "google" {
		if len(parts) == 2 {
			// e.g. google.com, google.de, google.ru
			return googleSafeSearch, true
		}
		if len(parts) == 3 {
			// e.g. google.co.uk, google.com.au
			if _, isSLD := googleCCSLDs[parts[1]]; isSLD {
				return googleSafeSearch, true
			}
		}
	}

	return SafeSearchRule{}, false
}

// SafeSearchRewrite checks if query r is for a known search engine, and if so,
// builds an authoritative DNS reply enforcing safe search. Returns nil if not matched.
func SafeSearchRewrite(r *dns.Msg) *dns.Msg {
	if r == nil || len(r.Question) == 0 {
		return nil
	}
	q := r.Question[0]
	rule, ok := MatchSafeSearch(q.Name)
	if !ok {
		return nil
	}

	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true
	const ttl = 300

	switch q.Qtype {
	case dns.TypeA:
		if rule.IPv4 != nil {
			var answers []dns.RR
			if rule.CNAME != "" {
				answers = append(answers, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
					Target: rule.CNAME,
				})
			}
			answers = append(answers, &dns.A{
				Hdr: dns.RR_Header{Name: rule.CNAME, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   rule.IPv4.To4(),
			})
			resp.Answer = answers
		} else if rule.CNAME != "" {
			resp.Answer = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: rule.CNAME,
			}}
		}

	case dns.TypeAAAA:
		if rule.IPv6 != nil {
			var answers []dns.RR
			if rule.CNAME != "" {
				answers = append(answers, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
					Target: rule.CNAME,
				})
			}
			answers = append(answers, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: rule.CNAME, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: rule.IPv6.To16(),
			})
			resp.Answer = answers
		} else if rule.CNAME != "" {
			// Provider does not have IPv6 SafeSearch VIP; return CNAME
			resp.Answer = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: rule.CNAME,
			}}
		}

	case dns.TypeCNAME:
		if rule.CNAME != "" {
			resp.Answer = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: rule.CNAME,
			}}
		}

	default:
		// For HTTPS/SVCB or other types, return empty NOERROR (NODATA) to prevent
		// modern browsers from bypassing SafeSearch via HTTPS/SVCB DNS hints.
	}

	return resp
}
