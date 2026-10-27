package dns

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
)

func TestDoHUpstream(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(data); err != nil {
			http.Error(w, "unpack error", http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   []byte{1, 2, 3, 4},
			},
		}
		wire, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer ts.Close()

	srv := &Server{
		upstream:  ts.URL,
		dohClient: ts.Client(),
	}

	q := dns.Question{Name: "test.local.", Qtype: dns.TypeA}
	res, err := srv.resolveUpstream(q)
	if err != nil {
		t.Fatalf("resolveUpstream DoH failed: %v", err)
	}
	if len(res.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(res.Answer))
	}
	a, ok := res.Answer[0].(*dns.A)
	if !ok || a.A.String() != "1.2.3.4" {
		t.Fatalf("unexpected answer: %v", res.Answer[0])
	}
}
