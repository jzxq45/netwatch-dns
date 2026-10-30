// Package devices' profiler turns raw MAC/hostname sightings and the 24h DNS
// activity of a client into a human-readable device profile plus a privacy
// "X-ray" score: how much surveillance traffic the server neutralized for
// that device. Pure functions only — no I/O, safe for concurrent use.
package devices

import (
	"strings"

	"monitor/internal/filter"
)

// DeviceType is a coarse hardware class used for the icon and grouping.
type DeviceType string

const (
	DeviceTV      DeviceType = "tv"
	DeviceMobile  DeviceType = "mobile"
	DevicePC      DeviceType = "pc"
	DeviceIoT     DeviceType = "iot"
	DeviceConsole DeviceType = "console"
	DeviceRouter  DeviceType = "router"
	DeviceUnknown DeviceType = "unknown"
)

// DeviceProfile is the classified identity of one LAN client.
type DeviceProfile struct {
	Type      DeviceType
	Vendor    string
	Icon      string
	ModelName string
}

// Keywords per class, matched against the lowercased hostname. Order is
// significant: "androidtv" must win over the generic "android" mobile rule.
var (
	tvKeywords = []string{
		"tv", "tizen", "webos", "bravia", "androidtv", "chromecast",
		"roku", "appletv",
	}
	mobileKeywords = []string{
		"iphone", "ipad", "galaxy", "pixel", "xiaomi", "redmi", "huawei",
		"honor", "oneplus", "android", "phone", "mobile",
	}
	pcKeywords = []string{
		"desktop", "laptop", "macbook", "pc", "win-", "windows", "arch",
		"ubuntu", "debian",
	}
	iotKeywords = []string{
		"esp_", "espressif", "tuya", "shelly", "sonoff", "yeelight", "hue",
		"vacuum", "camera", "gateway", "bridge",
	}
	consoleKeywords = []string{
		"playstation", "ps5", "ps4", "xbox", "nintendo", "switch",
	}
	routerVendors = []string{"Keenetic", "Zyxel", "Cisco"}
)

func deviceIcon(t DeviceType) string {
	switch t {
	case DeviceTV:
		return "📺"
	case DeviceMobile:
		return "📱"
	case DevicePC:
		return "💻"
	case DeviceIoT:
		return "💡"
	case DeviceConsole:
		return "🎮"
	case DeviceRouter:
		return "📡"
	default:
		return "🌐"
	}
}

// ProfileDevice classifies a client from its MAC (OUI vendor) and hostname.
// Hostname keywords decide first; unknown hostnames fall back to vendor
// heuristics (Apple/Samsung are phones unless a TV marker matched).
func ProfileDevice(mac, hostname string) DeviceProfile {
	vendor := VendorLookup(mac)
	name := strings.ToLower(strings.TrimSpace(hostname))

	switch {
	case containsAny(name, tvKeywords):
		return newProfile(DeviceTV, vendor, hostname)
	case containsAny(name, mobileKeywords):
		return newProfile(DeviceMobile, vendor, hostname)
	case containsAny(name, pcKeywords):
		return newProfile(DevicePC, vendor, hostname)
	case containsAny(name, iotKeywords):
		return newProfile(DeviceIoT, vendor, hostname)
	case containsAny(name, consoleKeywords):
		return newProfile(DeviceConsole, vendor, hostname)
	case containsAny(vendor, routerVendors):
		return newProfile(DeviceRouter, vendor, hostname)
	}

	switch {
	case strings.Contains(vendor, "PlayStation") || strings.Contains(vendor, "Xbox"):
		return newProfile(DeviceConsole, vendor, hostname)
	case strings.Contains(vendor, "Apple") || strings.Contains(vendor, "Samsung"):
		return newProfile(DeviceMobile, vendor, hostname)
	}
	return newProfile(DeviceUnknown, vendor, hostname)
}

func newProfile(t DeviceType, vendor, hostname string) DeviceProfile {
	return DeviceProfile{
		Type:      t,
		Vendor:    vendor,
		Icon:      deviceIcon(t),
		ModelName: cleanHostname(hostname),
	}
}

func containsAny(s string, needles []string) bool {
	if s == "" {
		return false
	}
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// cleanHostname strips the FQDN suffix so the card shows "Galaxy-S21" not
// "Galaxy-S21.lan".
func cleanHostname(hostname string) string {
	h := strings.TrimSpace(strings.TrimSuffix(hostname, "."))
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	return h
}

// PrivacyScore is the "X-Ray" rating: 100 means the device generated no
// blockable/tracking traffic in the window, lower means the server had to
// neutralize a share of its requests.
type PrivacyScore struct {
	Score          int
	Grade          string
	GradeColor     string
	LeakCategories []string
}

// Leak categories, in display order.
const (
	LeakACR       = "📺 ACR-слежка (распознавание аудио/видео)"
	LeakAds       = "📊 Рекламные трекеры и профилирование"
	LeakTelemetry = "📡 Фоновая телеметрия производителя"
	LeakMalware   = "🛡️ Вредоносная активность / DGA"
)

var (
	acrPatterns = []string{
		"samsungcloudsolution", "samsungelectronics", "lgtvcommon",
		"smartclip", "samba.tv",
	}
	adsPatterns = []string{
		"doubleclick", "google-analytics", "appsflyer", "adjust.com", "branch.io",
	}
	telemetryPatterns = []string{
		"telemetry.microsoft", "data.mistat.xiaomi", "tracking.miui", "diag.meethue",
	}
)

// CalculatePrivacyScore maps activity to a 0..100 rating. The base score is
// 100 - block percent: a Smart TV that ships 70% tracking traffic scores 30.
// LeakCategories explain what the blocklist/AI shield actually stopped.
func CalculatePrivacyScore(totalQueries, blockedQueries int64, sampleDomains []string) PrivacyScore {
	categories := leakCategories(sampleDomains)
	if totalQueries <= 0 {
		return PrivacyScore{Score: 100, Grade: "A+", GradeColor: gradeColor("A+"), LeakCategories: categories}
	}
	if blockedQueries < 0 {
		blockedQueries = 0
	}
	if blockedQueries > totalQueries {
		blockedQueries = totalQueries
	}
	score := 100 - int(blockedQueries*100/totalQueries)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	grade := gradeFor(score)
	return PrivacyScore{
		Score:          score,
		Grade:          grade,
		GradeColor:     gradeColor(grade),
		LeakCategories: categories,
	}
}

// leakCategories detects the classes of traffic present in sampleDomains.
func leakCategories(sampleDomains []string) []string {
	var out []string
	if domainsContain(sampleDomains, acrPatterns) {
		out = append(out, LeakACR)
	}
	if domainsContain(sampleDomains, adsPatterns) {
		out = append(out, LeakAds)
	}
	if domainsContain(sampleDomains, telemetryPatterns) {
		out = append(out, LeakTelemetry)
	}
	if hasMalicious(sampleDomains) {
		out = append(out, LeakMalware)
	}
	return out
}

func domainsContain(domains, patterns []string) bool {
	for _, d := range domains {
		low := strings.ToLower(d)
		for _, p := range patterns {
			if strings.Contains(low, p) {
				return true
			}
		}
	}
	return false
}

// hasMalicious reuses the AI heuristics: any sampled blocked domain that the
// engine classifies above the block threshold is flagged as malware/DGA.
func hasMalicious(domains []string) bool {
	engine := filter.NewAIEngine()
	for _, d := range domains {
		if engine.Analyze(d).Score >= filter.AIBlockThreshold {
			return true
		}
	}
	return false
}

// gradeFor maps the 0..100 score to the A+..F scale.
func gradeFor(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 85:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func gradeColor(grade string) string {
	switch grade {
	case "A+", "A":
		return "#80ff80"
	case "B":
		return "#b3ff80"
	case "C":
		return "#ffff80"
	case "D":
		return "#ffb380"
	default:
		return "#ff8080"
	}
}

// GradeIcon is the traffic-light emoji for the grade.
func GradeIcon(grade string) string {
	switch grade {
	case "A+", "A":
		return "🟢"
	case "B", "C":
		return "🟡"
	default:
		return "🔴"
	}
}

// GradeAdvice is the short human verdict shown after the numeric rating.
func GradeAdvice(grade string) string {
	switch grade {
	case "A+", "A":
		return "отличная приватность"
	case "B":
		return "умеренная слежка"
	case "C":
		return "заметная слежка"
	case "D":
		return "высокая слежка"
	default:
		return "критическая слежка"
	}
}
