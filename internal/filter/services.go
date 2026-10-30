// Package filter — service catalog for 1-click blocking of well-known
// services (one click labels / applies every domain of a service).
package filter

// Service is a family of domains belonging to one known internet service
// (YouTube, TikTok, ...). The first domain is the canonical one used to
// render the shortest human name in logs.
type Service struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

// Services is the built-in 1-click blocklist catalog. Order defines UI order.
var Services = []Service{
	{ID: "youtube", Name: "YouTube", Domains: []string{
		"youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
	}},
	{ID: "tiktok", Name: "TikTok", Domains: []string{
		"tiktok.com", "tiktokv.com", "tiktokcdn.com", "byteoversea.com", "ibytedtos.com",
	}},
	{ID: "telegram", Name: "Telegram", Domains: []string{
		"telegram.org", "t.me", "telesco.pe", "tdesktop.com",
	}},
	{ID: "discord", Name: "Discord", Domains: []string{
		"discord.com", "discordapp.com", "discord.gg", "discord.media",
	}},
	{ID: "steam", Name: "Steam", Domains: []string{
		"steampowered.com", "steamcommunity.com", "steamstatic.com",
	}},
	{ID: "roblox", Name: "Roblox", Domains: []string{
		"roblox.com", "rbxcdn.com", "robloxlabs.com",
	}},
	{ID: "vk", Name: "VK", Domains: []string{
		"vk.com", "userapi.com", "vk-cdn.net",
	}},
}

// ServiceByID returns the catalog entry with id.
func ServiceByID(id string) (Service, bool) {
	for _, svc := range Services {
		if svc.ID == id {
			return svc, true
		}
	}
	return Service{}, false
}
