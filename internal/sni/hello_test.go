package sni

import (
	"encoding/binary"
	"testing"
)

// buildHello assembles a synthetic ClientHello payload for parser tests.
// Layout: type(1) len(3) ver(2) random(32) sid(1+0) ciphers(2+2) comp(1+1) exts(2+payload).
func buildHello(exts ...[]byte) []byte {
	var e []byte
	for _, x := range exts {
		e = append(e, x...)
	}
	var b []byte
	b = append(b, 0x01)                   // handshake type
	b = append(b, 0x00, 0x00, 0x00)       // len placeholder (uint24)
	b = append(b, 0x03, 0x03)             // TLS 1.2
	b = append(b, make([]byte, 32)...)    // random
	b = append(b, 0x00)                   // session id: empty
	b = append(b, 0x00, 0x02, 0x13, 0x01) // one cipher
	b = append(b, 0x01, 0x00)             // null compression
	b = append(b, 0x00, 0x00)             // ext len placeholder
	b = append(b, e...)
	inner := len(b) - 4 // everything after the 4-byte handshake header
	if inner > 0xffff {
		panic("test hello too large")
	}
	b[1] = 0x00
	b[2] = byte(inner >> 8)
	b[3] = byte(inner)
	extLenAt := 4 + 2 + 32 + 1 + 4 + 2 // ver+rand+sidlen+ciphers+complen
	binary.BigEndian.PutUint16(b[extLenAt:], uint16(len(e)))

	rec := []byte{0x16, 0x03, 0x03, 0x00, 0x00}
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(b)))
	return append(rec, b...)
}

func sniExt(host string) []byte {
	entry := append([]byte{0x00}, byte(len(host)>>8), byte(len(host)))
	entry = append(entry, host...)
	list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	out := make([]byte, 4)
	binary.BigEndian.PutUint16(out[0:2], extServerName)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(list)))
	return append(out, list...)
}

func echExt(code uint16) []byte {
	out := make([]byte, 4+len(" placeholder"))
	binary.BigEndian.PutUint16(out[0:2], code)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(" placeholder")))
	return append(out, " placeholder"...)
}

func TestParse(t *testing.T) {
	t.Parallel()
	capsule := func(host string, ech bool) Result { return Result{Host: host, ECH: ech} }
	tests := []struct {
		name    string
		payload []byte
		want    Result
		wantOK  bool
	}{
		{"plain SNI", buildHello(sniExt("example.com")), capsule("example.com", false), true},
		{"no extensions", buildHello(), capsule("", false), true},
		{"ECH only", buildHello(echExt(extECHGrease)), capsule("", true), true},
		{"ECH + SNI(public name)", buildHello(sniExt("encrypted.example.com"), echExt(extECHGrease)), capsule("encrypted.example.com", true), true},
		{"not tls", []byte("GET / HTTP/1.1"), Result{}, false},
		{"empty", nil, Result{}, false},
		{"other record type", append([]byte{0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02}, make([]byte, 40)...), Result{}, false},
		{"other handshake type", append([]byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x03, 0x03}, make([]byte, 60)...), Result{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := Parse(tt.payload)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
