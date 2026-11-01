package web

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func mockDNSExchange(req *dns.Msg, clientAddr net.Addr) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	if len(req.Question) > 0 {
		q := req.Question[0]
		if q.Name == "example.com." && q.Qtype == dns.TypeA {
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("93.184.216.34").To4(),
			}}
		}
	}
	return resp
}

func TestDoH_POST_Success(t *testing.T) {
	t.Parallel()

	srv := New(seedStore(t), nil)
	srv.Token = "secret-token" // DoH must bypass token auth
	srv.DNSExchange = mockDNSExchange
	h := srv.Handler()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	rawQ, err := q.Pack()
	if err != nil {
		t.Fatalf("pack question: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(rawQ))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/dns-message" {
		t.Fatalf("content-type = %q, want application/dns-message", ct)
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(rec.Body.Bytes()); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(reply.Answer))
	}
	aRec, ok := reply.Answer[0].(*dns.A)
	if !ok || aRec.A.String() != "93.184.216.34" {
		t.Fatalf("unexpected answer: %v", reply.Answer[0])
	}
}

func TestDoH_GET_Success(t *testing.T) {
	t.Parallel()

	srv := New(seedStore(t), nil)
	srv.DNSExchange = mockDNSExchange
	h := srv.Handler()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	rawQ, err := q.Pack()
	if err != nil {
		t.Fatalf("pack question: %v", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(rawQ)

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+b64, nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(rec.Body.Bytes()); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(reply.Answer))
	}
}

func TestDoH_Errors(t *testing.T) {
	t.Parallel()

	srv := New(seedStore(t), nil)
	srv.DNSExchange = mockDNSExchange
	h := srv.Handler()

	// 1. Method not allowed (PUT)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/dns-query", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}

	// 2. Unsupported Content-Type
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader("bad"))
	req.Header.Set("Content-Type", "text/plain")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rec.Code)
	}

	// 3. GET missing ?dns
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dns-query", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	// 4. GET invalid base64
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dns-query?dns=!!!not-base64", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	// 5. POST malformed DNS payload
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader("garbage"))
	req.Header.Set("Content-Type", "application/dns-message")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
