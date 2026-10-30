package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Pure-Go QR Code generator (no external dependencies).
//
// Scope: byte mode, error-correction level M, versions 1..10 — enough for
// every pairing URL the panel produces (up to 213 UTF-8 bytes). The layout
// follows the ISO/IEC 18004 construction: RS blocks, interleaving, finder /
// timing / alignment patterns, format & version info and mask selection.
//
// The public surface is qrSVG, used by GET /api/qr.

// QR level-M block layout per version: total data codewords, RS block count
// and EC codewords per block. Totals equal the standard capacity table.
var (
	qrDataCodewordsM = [10]int{16, 28, 44, 64, 86, 108, 124, 154, 182, 216}
	qrBlocksM        = [10]int{1, 1, 1, 2, 2, 4, 4, 4, 5, 5}
	qrECPerBlockM    = [10]int{10, 16, 26, 18, 24, 16, 18, 22, 22, 26}
)

// qrAlignPos holds alignment-pattern centre coordinates by version.
var qrAlignPos = [11][]int{
	nil,
	nil,
	{6, 18},
	{6, 22},
	{6, 26},
	{6, 30},
	{6, 34},
	{6, 22, 38},
	{6, 24, 42},
	{6, 26, 46},
	{6, 28, 50},
}

// qrVersionInfo holds the precomputed 18-bit version information for v7+.
var qrVersionInfo = map[int]int{
	7:  0x07C94,
	8:  0x085BC,
	9:  0x09A99,
	10: 0x0A4D3,
}

const (
	qrMinVersion = 1
	qrMaxVersion = 10
	// qrMaxBytesM is the byte-mode capacity of version 10 at level M.
	qrMaxBytesM = 213
)

type qrCode struct {
	version int
	size    int
	modules [][]bool
	isFunc  [][]bool
}

// qrSVG renders text as a standalone SVG QR code with a 4-module quiet zone.
func qrSVG(text string) (string, error) {
	q, err := encodeQR(text)
	if err != nil {
		return "", err
	}
	const quiet = 4
	dim := q.size + 2*quiet
	var b strings.Builder
	b.Grow(q.size * q.size * 18)
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 `)
	b.WriteString(strconv.Itoa(dim))
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(dim))
	b.WriteString(`" shape-rendering="crispEdges">`)
	b.WriteString(`<rect width="100%" height="100%" fill="#ffffff"/>`)
	b.WriteString(`<g fill="#000000">`)
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; {
			if !q.modules[y][x] {
				x++
				continue
			}
			start := x
			for x < q.size && q.modules[y][x] {
				x++
			}
			b.WriteString(`<rect x="`)
			b.WriteString(strconv.Itoa(start + quiet))
			b.WriteString(`" y="`)
			b.WriteString(strconv.Itoa(y + quiet))
			b.WriteString(`" width="`)
			b.WriteString(strconv.Itoa(x - start))
			b.WriteString(`" height="1"/>`)
		}
	}
	b.WriteString(`</g></svg>`)
	return b.String(), nil
}

// encodeQR builds the module matrix for text, picking the smallest version
// whose level-M data capacity fits.
func encodeQR(text string) (*qrCode, error) {
	data := []byte(text)
	version := 0
	for v := qrMinVersion; v <= qrMaxVersion; v++ {
		countBits := 8
		if v >= 10 {
			countBits = 16
		}
		if 4+countBits+8*len(data) <= qrDataCodewordsM[v-1]*8 {
			version = v
			break
		}
	}
	if version == 0 {
		return nil, fmt.Errorf("text too long for QR code: %d bytes (max %d)", len(data), qrMaxBytesM)
	}

	dataCodewords := qrDataCodewordsM[version-1]
	codewords := interleaveQR(buildQRData(data, version, dataCodewords), version)

	q := newQRCode(version)
	q.drawFunctionPatterns()
	q.placeData(codewords)

	bestMask, bestPenalty := 0, -1
	for mask := 0; mask < 8; mask++ {
		q.applyMask(mask)
		q.drawFormat(mask)
		if p := q.penalty(); bestPenalty < 0 || p < bestPenalty {
			bestMask, bestPenalty = mask, p
		}
		q.applyMask(mask)
	}
	q.applyMask(bestMask)
	q.drawFormat(bestMask)
	return q, nil
}

func newQRCode(version int) *qrCode {
	size := 17 + 4*version
	modules := make([][]bool, size)
	isFunc := make([][]bool, size)
	for i := range modules {
		modules[i] = make([]bool, size)
		isFunc[i] = make([]bool, size)
	}
	return &qrCode{version: version, size: size, modules: modules, isFunc: isFunc}
}

// buildQRData packs byte-mode data with terminator and pad codewords.
func buildQRData(data []byte, version, dataCodewords int) []byte {
	bits := make([]bool, 0, dataCodewords*8)
	appendBits := func(val uint32, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, (val>>uint(i))&1 == 1)
		}
	}
	appendBits(0b0100, 4) // byte mode
	if version >= 10 {
		appendBits(uint32(len(data)), 16)
	} else {
		appendBits(uint32(len(data)), 8)
	}
	for _, b := range data {
		appendBits(uint32(b), 8)
	}
	for i := 0; i < 4 && len(bits) < dataCodewords*8; i++ {
		bits = append(bits, false)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	out := make([]byte, 0, dataCodewords)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for j := 0; j < 8; j++ {
			b <<= 1
			if bits[i+j] {
				b |= 1
			}
		}
		out = append(out, b)
	}
	for pad := byte(0xEC); len(out) < dataCodewords; {
		out = append(out, pad)
		if pad == 0xEC {
			pad = 0x11
		} else {
			pad = 0xEC
		}
	}
	return out
}

// interleaveQR splits data into RS blocks, appends EC codewords and
// interleaves the result per the QR spec.
func interleaveQR(data []byte, version int) []byte {
	numBlocks := qrBlocksM[version-1]
	ecLen := qrECPerBlockM[version-1]
	shortLen := len(data) / numBlocks
	numShort := numBlocks - len(data)%numBlocks
	if len(data)%numBlocks == 0 {
		numShort = numBlocks
	}
	longLen := shortLen + 1

	type block struct{ data, ec []byte }
	blocks := make([]block, numBlocks)
	off := 0
	for i := range blocks {
		n := shortLen
		if i >= numShort {
			n = longLen
		}
		blocks[i].data = data[off : off+n]
		off += n
		blocks[i].ec = rsEC(blocks[i].data, ecLen)
	}

	out := make([]byte, 0, len(data)+numBlocks*ecLen)
	for i := 0; i < longLen; i++ {
		for _, b := range blocks {
			if i < len(b.data) {
				out = append(out, b.data[i])
			}
		}
	}
	for i := 0; i < ecLen; i++ {
		for _, b := range blocks {
			out = append(out, b.ec[i])
		}
	}
	return out
}

// GF(256) tables for Reed-Solomon, primitive polynomial 0x11D.
var (
	qrGFExp [512]byte
	qrGFLog [256]byte
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		qrGFExp[i] = byte(x)
		qrGFLog[byte(x)] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < len(qrGFExp); i++ {
		qrGFExp[i] = qrGFExp[i-255]
	}
}

func qrGFMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return qrGFExp[int(qrGFLog[a])+int(qrGFLog[b])]
}

// rsEC returns n Reed-Solomon error-correction codewords for data.
func rsEC(data []byte, n int) []byte {
	gen := []byte{1}
	for i := 0; i < n; i++ {
		next := make([]byte, len(gen)+1)
		copy(next, gen)
		root := qrGFExp[i]
		for j, c := range gen {
			next[j+1] ^= qrGFMul(c, root)
		}
		gen = next
	}
	rem := make([]byte, len(data)+n)
	copy(rem, data)
	for i := 0; i < len(data); i++ {
		coef := rem[i]
		if coef == 0 {
			continue
		}
		for j := 0; j <= n; j++ {
			rem[i+j] ^= qrGFMul(gen[j], coef)
		}
	}
	return rem[len(data):]
}

func (q *qrCode) setFunc(row, col int, dark bool) {
	q.modules[row][col] = dark
	q.isFunc[row][col] = true
}

// drawFunctionPatterns lays out timing, finder, alignment, format and version
// areas. Order matches the reference generator so overlaps resolve correctly.
func (q *qrCode) drawFunctionPatterns() {
	for i := 0; i < q.size; i++ {
		q.setFunc(6, i, i%2 == 0)
		q.setFunc(i, 6, i%2 == 0)
	}
	for _, c := range [][2]int{{3, 3}, {q.size - 4, 3}, {3, q.size - 4}} {
		q.drawFinder(c[0], c[1])
	}
	pos := qrAlignPos[q.version]
	last := len(pos) - 1
	for i, cy := range pos {
		for j, cx := range pos {
			if (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0) {
				continue
			}
			q.drawAlignment(cx, cy)
		}
	}
	q.drawFormat(0)
	q.drawVersion()
}

// drawFinder paints a 9x9 area around the finder centre (row, col), including
// the one-module white separator.
func (q *qrCode) drawFinder(row, col int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			r, c := row+dy, col+dx
			if r < 0 || r >= q.size || c < 0 || c >= q.size {
				continue
			}
			dist := max(abs(dx), abs(dy))
			q.setFunc(r, c, dist != 2 && dist != 4)
		}
	}
}

func (q *qrCode) drawAlignment(row, col int) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			q.setFunc(row+dy, col+dx, max(abs(dx), abs(dy)) != 1)
		}
	}
}

// qrFormatBits computes the 15-bit BCH-coded format word (level M, given mask).
func qrFormatBits(mask int) int {
	data := mask // level M indicator is 0b00, so the top bits are just mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	return ((data << 10) | rem) ^ 0x5412
}

func (q *qrCode) drawFormat(mask int) {
	bits := qrFormatBits(mask)
	bit := func(i int) bool { return (bits>>uint(i))&1 == 1 }
	for i := 0; i <= 5; i++ {
		q.setFunc(i, 8, bit(i))
	}
	q.setFunc(7, 8, bit(6))
	q.setFunc(8, 8, bit(7))
	q.setFunc(8, 7, bit(8))
	for i := 9; i < 15; i++ {
		q.setFunc(8, 14-i, bit(i))
	}
	for i := 0; i < 8; i++ {
		q.setFunc(8, q.size-1-i, bit(i))
	}
	for i := 8; i < 15; i++ {
		q.setFunc(q.size-15+i, 8, bit(i))
	}
	q.setFunc(q.size-8, 8, true) // dark module
}

func (q *qrCode) drawVersion() {
	if q.version < 7 {
		return
	}
	bits := qrVersionInfo[q.version]
	for i := 0; i < 18; i++ {
		dark := (bits>>uint(i))&1 == 1
		a := q.size - 11 + i%3
		b := i / 3
		q.setFunc(b, a, dark)
		q.setFunc(a, b, dark)
	}
}

// placeData walks column pairs from the bottom-right, skipping the timing
// column, and fills non-function modules with codeword bits (MSB first).
func (q *qrCode) placeData(codewords []byte) {
	total := len(codewords) * 8
	i := 0
	for right := q.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < q.size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				upward := ((right + 1) & 2) == 0
				y := vert
				if upward {
					y = q.size - 1 - vert
				}
				if !q.isFunc[y][x] && i < total {
					q.modules[y][x] = (codewords[i>>3]>>uint(7-(i&7)))&1 == 1
					i++
				}
			}
		}
	}
}

func qrMask(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return (x*y)%2+(x*y)%3 == 0
	case 6:
		return ((x*y)%2+(x*y)%3)%2 == 0
	default:
		return ((x+y)%2+(x*y)%3)%2 == 0
	}
}

func (q *qrCode) applyMask(mask int) {
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			if !q.isFunc[y][x] && qrMask(mask, x, y) {
				q.modules[y][x] = !q.modules[y][x]
			}
		}
	}
}

// penalty implements the four ISO penalty rules used to choose the mask.
func (q *qrCode) penalty() int {
	n := q.size
	score := 0

	// Rule 1: runs of five or more same-coloured modules.
	for y := 0; y < n; y++ {
		run := 1
		for x := 1; x < n; x++ {
			if q.modules[y][x] == q.modules[y][x-1] {
				run++
			} else {
				if run >= 5 {
					score += 3 + run - 5
				}
				run = 1
			}
		}
		if run >= 5 {
			score += 3 + run - 5
		}
	}
	for x := 0; x < n; x++ {
		run := 1
		for y := 1; y < n; y++ {
			if q.modules[y][x] == q.modules[y-1][x] {
				run++
			} else {
				if run >= 5 {
					score += 3 + run - 5
				}
				run = 1
			}
		}
		if run >= 5 {
			score += 3 + run - 5
		}
	}

	// Rule 2: 2x2 blocks of the same colour.
	for y := 0; y < n-1; y++ {
		for x := 0; x < n-1; x++ {
			c := q.modules[y][x]
			if c == q.modules[y][x+1] && c == q.modules[y+1][x] && c == q.modules[y+1][x+1] {
				score += 3
			}
		}
	}

	// Rule 3: finder-like 1:1:3:1:1 patterns with four light modules.
	p1 := []bool{true, false, true, true, true, false, true, false, false, false, false}
	p2 := []bool{false, false, false, false, true, false, true, true, true, false, true}
	row := make([]bool, n)
	col := make([]bool, n)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			row[x] = q.modules[y][x]
			col[x] = q.modules[x][y]
		}
		score += countQRPatterns(row, p1, p2)
		score += countQRPatterns(col, p1, p2)
	}

	// Rule 4: deviation of the dark-module ratio from 50%.
	dark := 0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if q.modules[y][x] {
				dark++
			}
		}
	}
	total := n * n
	score += abs(dark*20-total*10) / total * 10
	return score
}

func countQRPatterns(vals, p1, p2 []bool) int {
	n := 0
	for i := 0; i+len(p1) <= len(vals); i++ {
		match1, match2 := true, true
		for j := range p1 {
			if vals[i+j] != p1[j] {
				match1 = false
			}
			if vals[i+j] != p2[j] {
				match2 = false
			}
			if !match1 && !match2 {
				break
			}
		}
		if match1 {
			n++
		}
		if match2 {
			n++
		}
	}
	return n * 40
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// apiQR serves an SVG QR code for ?text=...; without text it encodes this
// panel's own base URL so a phone camera opens the mobile view directly.
func (s *Server) apiQR(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("text")
	if text == "" {
		text = requestBaseURL(r)
	}
	svg, err := qrSVG(text)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(svg))
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/"
}
