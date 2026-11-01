// Package filter provides content filtering, service catalogs and adult/NSFW protection.
package filter

import (
	"strings"
	"sync"
)

// AdultCatalog holds the curated list of major adult/NSFW domain platforms.
var defaultAdultDomains = []string{
	// Global Top Adult Sites & Networks
	"pornhub.com", "phncdn.com", "pornhubpremium.com",
	"xvideos.com", "xvideos-cdn.com", "xv-r.com",
	"xnxx.com", "xnxx-cdn.com",
	"stripchat.com", "stripchat.org",
	"chaturbate.com",
	"camsoda.com",
	"cam4.com",
	"bongacams.com",
	"livejasmin.com",
	"onlyfans.com",
	"fansly.com",
	"redtube.com", "redtube.net",
	"youporn.com", "ypncdn.com",
	"spankbang.com",
	"eporner.com",
	"tube8.com",
	"beeg.com",
	"tnaflix.com",
	"drtuber.com",
	"fuq.com",
	"brazzers.com",
	"naughtyamerica.com",
	"realitykings.com",
	"bangbros.com",
	"mofos.com",
	"twistys.com",
	"babes.com",
	"porn.com",
	"adultfriendfinder.com",
	"flirt4free.com",
	"myfreecams.com",
	"faphouse.com",
	"fapchat.com",
	"youjizz.com",
	"porntrex.com",
	"hqporner.com",
	"daftsex.com",
	"thumbzilla.com",
	"txxx.com",
	"upornia.com",
	"hclips.com",
	"tubegalore.com",
	"bravoteens.com",
	"javhd.com",
	"javlibrary.com",
	"dmm.co.jp",
	"r18.com",
	"erome.com",
	"heavy-r.com",
	"motherless.com",
	"rule34.xxx",
	"e621.net",
	"gelbooru.com",
	"danbooru.donmai.us",
	"hentaihaven.xxx",
	"hanime.tv",
}

// AdultFilter manages 18+ content detection and blocking rules.
type AdultFilter struct {
	mu      sync.RWMutex
	domains map[string]struct{}
}

// NewAdultFilter initializes the adult filter with built-in curated platforms.
func NewAdultFilter() *AdultFilter {
	af := &AdultFilter{
		domains: make(map[string]struct{}, len(defaultAdultDomains)+64),
	}
	for _, d := range defaultAdultDomains {
		af.domains[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}
	return af
}

// Add adds a custom adult domain.
func (af *AdultFilter) Add(domain string) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return
	}
	af.mu.Lock()
	af.domains[d] = struct{}{}
	af.mu.Unlock()
}

// Count returns the number of tracked adult domains.
func (af *AdultFilter) Count() int {
	af.mu.RLock()
	defer af.mu.RUnlock()
	return len(af.domains)
}

// Match reports whether domain or any of its parent domains belongs to the adult catalog.
func (af *AdultFilter) Match(domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return false
	}

	af.mu.RLock()
	defer af.mu.RUnlock()

	// Exact match
	if _, ok := af.domains[d]; ok {
		return true
	}

	// Subdomain match (e.g. static.pornhub.com -> pornhub.com)
	for {
		idx := strings.IndexByte(d, '.')
		if idx == -1 {
			break
		}
		d = d[idx+1:]
		if _, ok := af.domains[d]; ok {
			return true
		}
	}

	return false
}

