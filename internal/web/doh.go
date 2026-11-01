// Package web implements the HTTP interface of NetWatch, including the
// RFC 8484 DNS-over-HTTPS (DoH) inbound endpoint.
package web

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

// maxDoHBodySize bounds incoming HTTP query payloads to protect from memory exhaustion.
const maxDoHBodySize = 65536 // 64KB max DNS wire message

// handleDoH implements RFC 8484 (DNS Queries over HTTPS).
// Supports both GET (base64url ?dns=...) and POST (binary application/dns-message).
func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	if s.DNSExchange == nil {
		http.Error(w, "DNS resolver unavailable", http.StatusServiceUnavailable)
		return
	}

	var rawMsg []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing ?dns query parameter", http.StatusBadRequest)
			return
		}
		rawMsg, err = decodeBase64URL(dnsParam)
		if err != nil {
			http.Error(w, "invalid base64url encoding", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		ct := r.Header.Get("Content-Type")
		if ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/dns-message") {
			http.Error(w, "unsupported content-type, expected application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		rawMsg, err = io.ReadAll(io.LimitReader(r.Body, maxDoHBodySize))
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		if len(rawMsg) == 0 {
			http.Error(w, "empty request body", http.StatusBadRequest)
			return
		}

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(rawMsg); err != nil {
		http.Error(w, "malformed dns message", http.StatusBadRequest)
		return
	}

	// Client IP is preserved for analytics, device logs and ACL
	clientHost := clientIPFromRequest(r)
	clientAddr := &net.TCPAddr{IP: net.ParseIP(clientHost), Port: 443}

	resp := s.DNSExchange(req, clientAddr)
	if resp == nil {
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
	}

	rawResp, err := resp.Pack()
	if err != nil {
		http.Error(w, "failed to pack dns response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", minResponseTTL(resp)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rawResp)
}

// decodeBase64URL parses base64url with or without padding (RFC 4648 § 5).
func decodeBase64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func minResponseTTL(m *dns.Msg) uint32 {
	if m == nil || len(m.Answer) == 0 {
		return 300
	}
	min := uint32(3600)
	for _, rr := range m.Answer {
		if h := rr.Header(); h != nil && h.Ttl < min {
			min = h.Ttl
		}
	}
	if min < 5 {
		min = 5
	}
	return min
}

