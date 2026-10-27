package devices

import (
	"strings"
)

// VendorLookup returns a human-friendly manufacturer name for a given MAC address.
func VendorLookup(mac string) string {
	clean := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", ""))
	if len(clean) < 6 {
		return ""
	}
	prefix := clean[:6]

	if vendor, ok := ouiPrefixes[prefix]; ok {
		return vendor
	}
	return ""
}

// Curated list of high-frequency consumer device OUIs.
var ouiPrefixes = map[string]string{
	// Keenetic / Zyxel
	"6813e2": "Keenetic",
	"50ff20": "Keenetic",
	"ec43f6": "Keenetic",
	"28285d": "Keenetic",
	"cc5d4e": "Zyxel",

	// Apple
	"001cb3": "Apple",
	"000393": "Apple",
	"bcd074": "Apple",
	"f01898": "Apple",
	"3c22fb": "Apple",
	"acbc32": "Apple",
	"f434f0": "Apple",
	"88665a": "Apple",
	"a483e7": "Apple",
	"d0817a": "Apple",
	"f8ffc2": "Apple",
	"4098ad": "Apple",
	"7c5049": "Apple",
	"149877": "Apple",
	"286aba": "Apple",
	"909c4a": "Apple",
	"e4e0a6": "Apple",
	"2c200b": "Apple",
	"94e979": "Apple",

	// Samsung
	"0012fb": "Samsung",
	"002637": "Samsung",
	"bc4486": "Samsung",
	"508569": "Samsung",
	"244bfe": "Samsung",
	"64b5c6": "Samsung",
	"b407f9": "Samsung",
	"8c7712": "Samsung",
	"c4731e": "Samsung",
	"a00798": "Samsung",
	"5c3c27": "Samsung",
	"e8508b": "Samsung",

	// Xiaomi / Roborock / Aqara
	"64cc2e": "Xiaomi",
	"7c49eb": "Xiaomi",
	"acc1ee": "Xiaomi",
	"508f4c": "Xiaomi",
	"286c07": "Xiaomi",
	"34800d": "Xiaomi",
	"7802f8": "Xiaomi",
	"04cf8c": "Xiaomi",
	"5448e6": "Xiaomi",
	"8c2505": "Xiaomi",
	"a4c138": "Xiaomi",
	"009e60": "Roborock",

	// Espressif (Smart Home / ESP8266 / ESP32 / Tuya)
	"240ac4": "Espressif (IoT)",
	"30aea4": "Espressif (IoT)",
	"84f3eb": "Espressif (IoT)",
	"a020a6": "Espressif (IoT)",
	"bcddc2": "Espressif (IoT)",
	"dc4f22": "Espressif (IoT)",
	"485519": "Espressif (IoT)",
	"2cf432": "Espressif (IoT)",
	"e831cd": "Espressif (IoT)",
	"c44f33": "Espressif (IoT)",
	"68c63a": "Espressif (IoT)",
	"7cdfa1": "Espressif (IoT)",

	// TP-Link / Tapo / Kasa
	"50c7bf": "TP-Link",
	"984827": "TP-Link",
	"e848b8": "TP-Link",
	"30de4b": "TP-Link",
	"1c3bf3": "TP-Link",
	"c006c3": "TP-Link",
	"b09575": "TP-Link",
	"003192": "Tapo (TP-Link)",

	// Huawei / Honor
	"4846fb": "Huawei",
	"00e0fc": "Huawei",
	"24dbac": "Huawei",
	"7089cc": "Huawei",
	"dc729b": "Huawei",
	"e8088b": "Huawei",

	// Google
	"f4f5e8": "Google",
	"d86c63": "Google",
	"1c56fe": "Google",
	"546009": "Google",
	"a47733": "Google",

	// LG Electronics
	"001c62": "LG Electronics",
	"a823fe": "LG Electronics",
	"58a2b5": "LG Electronics",
	"203dbd": "LG Electronics",
	"7440be": "LG Electronics",

	// Sony / PlayStation
	"00041f": "Sony",
	"fc0f4b": "Sony PlayStation",
	"709e29": "Sony PlayStation",
	"00d9d1": "Sony",

	// Microsoft / Xbox
	"7cfeb9": "Microsoft Xbox",
	"281878": "Microsoft",
	"985fd3": "Microsoft",

	// Raspberry Pi
	"b827eb": "Raspberry Pi",
	"dca632": "Raspberry Pi",
	"e45f01": "Raspberry Pi",
	"28cdc1": "Raspberry Pi",

	// Amazon / Kindle / Echo
	"44650d": "Amazon Echo",
	"68545a": "Amazon",
	"fc65de": "Amazon",
	"38f73d": "Amazon",
}
