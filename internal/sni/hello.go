// Package sni extracts the server name from a TLS ClientHello seen on the wire.
// Phase 4 limitation: the ClientHello must be fully contained in one captured
// segment (>v1: no TCP reassembly); the common web handshake fits.
package sni

import "encoding/binary"

const (
	tlsRecordTypeHandshake = 0x16
	tlsHandshakeTypeCH1    = 0x01
	extServerName          = 0x0000
	extECH                 = 0xfe0d // draft-ietf-tls-esni: encrypted_client_hello
	extECHGrease           = 0xffcd // GREASE-ECH envelope with public_name only
)

// Result carries the sniffed metadata for one ClientHello.
type Result struct {
	Host string
	ECH  bool // true when ECH hides the real name (Host empty then)
}

// Parse returns (Result, true) for a TCP payload containing a ClientHello.
// ok=false means "not a ClientHello / malformed" — caller stays silent.
func Parse(payload []byte) (Result, bool) {
	if len(payload) < 5 || payload[0] != tlsRecordTypeHandshake {
		return Result{}, false
	}
	// Skip the 5-byte TLS record header; accept the clock that the handshake
	// body may predict the remainder of the record (not yet reassembled).
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	end := 5 + recLen
	if end > len(payload) {
		end = len(payload)
	}
	body := payload[5:end]
	if len(body) < 4 || body[0] != tlsHandshakeTypeCH1 {
		return Result{}, false
	}
	// body[1:4] is the handshake length (checked only for sanity by c.Total below).
	c := 4
	// client_version(2) + random(32)
	if c+34 > len(body) {
		return Result{}, false
	}
	c += 34
	// legacy_session_id
	n := int(body[c])
	c += 1 + n
	// cipher_suites
	if c+2 > len(body) {
		return Result{}, false
	}
	n = int(binary.BigEndian.Uint16(body[c : c+2]))
	c += 2 + n
	// compression_methods
	if c >= len(body) {
		return Result{}, false
	}
	n = int(body[c])
	c += 1 + n
	// extensions (absent in legacy clients)
	if c+2 > len(body) {
		return Result{Host: ""}, true
	}
	n = int(binary.BigEndian.Uint16(body[c : c+2]))
	c += 2
	_ = n

	var res Result
loopExts:
	for c+4 <= len(body) {
		etype := binary.BigEndian.Uint16(body[c : c+2])
		elen := int(binary.BigEndian.Uint16(body[c+2 : c+4]))
		c += 4
		if c+elen > len(body) {
			// truncated extension — stop rather than read nonsense
			break
		}
		ext := body[c : c+elen]
		c += elen
		switch etype {
		case extServerName:
			if h, valid := parseSNIExt(ext); valid {
				if res.Host != "" && res.Host != h {
					break loopExts // inconsistent duplicates — do not guess
				}
				res.Host = h
			}
		case extECH, extECHGrease:
			res.ECH = true
		}
	}
	return res, true
}

// parseSNIExt decodes the RFC6066 server_name list (host_name entries only).
func parseSNIExt(ext []byte) (string, bool) {
	// ext = server_name_list: uint16 len, entries: type(1)+len(2)+name
	if len(ext) < 2 {
		return "", false
	}
	list := int(binary.BigEndian.Uint16(ext[:2]))
	end := 2 + list
	if end > len(ext) {
		end = len(ext)
	}
	// Take the first well-formed host_name entry; multiple SNI entries are
	// pathological in the wild.
	for c := 2; c+3 <= end; {
		nType := ext[c]
		nLen := int(binary.BigEndian.Uint16(ext[c+1 : c+3]))
		c += 3
		if c+nLen > end {
			return "", false
		}
		if nType == 0 && nLen > 0 {
			return string(ext[c : c+nLen]), true
		}
		c += nLen
	}
	return "", false
}
