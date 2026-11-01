package dns

import (
	"strings"
	"sync"
	"time"

	"monitor/internal/filter"
	"monitor/internal/store"
)

// ScheduleEngine is a concurrency-safe snapshot of bedtime / time-limit rules.
// The web layer writes a new snapshot after every CRUD operation; the DNS hot
// path only reads, so there is no DB access per query.
type ScheduleEngine struct {
	mu        sync.RWMutex
	schedules []store.Schedule
}

// NewScheduleEngine returns an empty engine (no scheduled blocks).
func NewScheduleEngine() *ScheduleEngine {
	return &ScheduleEngine{}
}

// SetSchedules replaces the current rule snapshot with a copy.
func (e *ScheduleEngine) SetSchedules(list []store.Schedule) {
	cp := make([]store.Schedule, len(list))
	copy(cp, list)
	e.mu.Lock()
	e.schedules = cp
	e.mu.Unlock()
}

// IsScheduledBlocked reports whether clientIP querying domain at now is inside
// an enabled rule window. clientIP is ignored by rules with an empty ClientIP
// ("all devices"). Domain matching is exact or subdomain for concrete targets;
// service targets (youtube, tiktok, ...) expand to their whole domain family.
func (e *ScheduleEngine) IsScheduledBlocked(clientIP, domain string, now time.Time) bool {
	domain = normalizeScheduleDomain(domain)
	if domain == "" {
		return false
	}
	clientIP = strings.TrimSpace(clientIP)
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, sc := range e.schedules {
		if !sc.Enabled {
			continue
		}
		if sc.ClientIP != "" && !strings.EqualFold(sc.ClientIP, clientIP) {
			continue
		}
		if !scheduleWindowActive(sc, now) {
			continue
		}
		if scheduleTargetMatches(sc.Target, domain) {
			return true
		}
	}
	return false
}

func normalizeScheduleDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// scheduleWindowActive checks the weekday mask and the (possibly overnight)
// time window. start == end means the whole day; an empty mask means every day.
func scheduleWindowActive(sc store.Schedule, now time.Time) bool {
	if sc.DaysMask != 0 && sc.DaysMask&(1<<uint(now.Weekday())) == 0 {
		return false
	}
	cur := now.Hour()*60 + now.Minute()
	start := sc.StartHour*60 + sc.StartMin
	end := sc.EndHour*60 + sc.EndMin
	switch {
	case start == end:
		return true
	case start < end:
		return cur >= start && cur < end
	default:
		return cur >= start || cur < end
	}
}

// scheduleTargetMatches resolves a service ID or a concrete domain target.
func scheduleTargetMatches(target, domain string) bool {
	target = normalizeScheduleDomain(target)
	if target == "" {
		return false
	}
	if svc, ok := filter.ServiceByID(target); ok {
		for _, d := range svc.Domains {
			if domainMatchesTarget(domain, normalizeScheduleDomain(d)) {
				return true
			}
		}
		return false
	}
	return domainMatchesTarget(domain, target)
}

func domainMatchesTarget(domain, target string) bool {
	return domain == target || strings.HasSuffix(domain, "."+target)
}

// SetSchedules installs a new rule snapshot into the live resolver.
func (s *Server) SetSchedules(list []store.Schedule) {
	s.schedules.SetSchedules(list)
}

// IsScheduledBlocked reports whether the query is currently inside a bedtime /
// time-limit window for this client.
func (s *Server) IsScheduledBlocked(clientIP, domain string, now time.Time) bool {
	return s.schedules.IsScheduledBlocked(clientIP, domain, now)
}
