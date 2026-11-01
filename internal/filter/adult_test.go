package filter

import (
	"sync"
	"testing"
)

func TestAdultFilter_Match(t *testing.T) {
	t.Parallel()

	af := NewAdultFilter()

	cases := []struct {
		domain string
		want   bool
	}{
		{"pornhub.com", true},
		{"www.pornhub.com", true},
		{"m.pornhub.com", true},
		{"cdn.phncdn.com", true},
		{"xvideos.com", true},
		{"static.xvideos.com.", true},
		{"chaturbate.com", true},
		{"onlyfans.com", true},
		{"google.com", false},
		{"github.com", false},
		{"not-adult.org", false},
		{"", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.domain, func(t *testing.T) {
			t.Parallel()
			got := af.Match(tc.domain)
			if got != tc.want {
				t.Fatalf("Match(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

func TestAdultFilter_AddAndCount(t *testing.T) {
	t.Parallel()

	af := NewAdultFilter()
	initialCount := af.Count()

	af.Add("custom-nsfw.test")
	if !af.Match("custom-nsfw.test") {
		t.Fatal("expected custom domain to match after Add")
	}
	if !af.Match("sub.custom-nsfw.test") {
		t.Fatal("expected subdomain to match after Add")
	}
	if af.Count() != initialCount+1 {
		t.Fatalf("count = %d, want %d", af.Count(), initialCount+1)
	}
}

func TestAdultFilter_Concurrent(t *testing.T) {
	t.Parallel()

	af := NewAdultFilter()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = af.Match("pornhub.com")
				_ = af.Match("example.com")
			}
		}()
	}
	wg.Wait()
}

