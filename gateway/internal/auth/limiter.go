package auth

import (
	"container/list"
	"strings"
	"sync"
	"time"
)

// Limiter slows down password guessing: after Max failures for a key
// (username + client IP) within Window, or after MaxPerIP total failures from
// a single client IP across usernames within Window, further attempts are
// refused until the window passes.
//
// Memory stays bounded via an LRU order list + periodic expiry sweeps, and a
// single source IP cannot exhaust MaxKeys with random usernames.
type Limiter struct {
	Max      int
	Window   time.Duration
	MaxKeys  int
	MaxPerIP int

	mu        sync.Mutex
	fails     map[string][]time.Time
	ipFails   map[string][]time.Time
	lru       *list.List
	lruElems  map[string]*list.Element
	lastSweep time.Time
}

func NewLimiter() *Limiter {
	return &Limiter{
		Max:      5,
		Window:   15 * time.Minute,
		MaxKeys:  100_000,
		MaxPerIP: 50,
		fails:    map[string][]time.Time{},
		ipFails:  map[string][]time.Time{},
		lru:      list.New(),
		lruElems: map[string]*list.Element{},
	}
}

func (l *Limiter) ensureInit() {
	if l.Max <= 0 {
		l.Max = 5
	}
	if l.Window <= 0 {
		l.Window = 15 * time.Minute
	}
	if l.MaxKeys <= 0 {
		l.MaxKeys = 100_000
	}
	if l.MaxPerIP <= 0 {
		l.MaxPerIP = 50
	}
	if l.fails == nil {
		l.fails = map[string][]time.Time{}
	}
	if l.ipFails == nil {
		l.ipFails = map[string][]time.Time{}
	}
	if l.lru == nil {
		l.lru = list.New()
	}
	if l.lruElems == nil {
		l.lruElems = map[string]*list.Element{}
	}
}

func extractIPFromKey(key string) string {
	idx := strings.LastIndex(key, "|")
	if idx < 0 || idx+1 >= len(key) {
		return ""
	}
	return key[idx+1:]
}

func (l *Limiter) recentIn(m map[string][]time.Time, key string, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range m[key] {
		if now.Sub(t) < l.Window {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(m, key)
	} else {
		m[key] = keep
	}
	return keep
}

func (l *Limiter) removeKey(key string) {
	delete(l.fails, key)
	if el, ok := l.lruElems[key]; ok {
		l.lru.Remove(el)
		delete(l.lruElems, key)
	}
}

func (l *Limiter) touchKey(key string) {
	if el, ok := l.lruElems[key]; ok {
		l.lru.MoveToFront(el)
		return
	}
	l.lruElems[key] = l.lru.PushFront(key)
}

func (l *Limiter) recent(key string, now time.Time) []time.Time {
	keep := l.recentIn(l.fails, key, now)
	if len(keep) == 0 {
		l.removeKey(key)
	}
	return keep
}

// sweep drops expired keys once per minute without blocking under contention.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now
	for key, ts := range l.fails {
		if now.Sub(ts[len(ts)-1]) >= l.Window {
			l.removeKey(key)
		}
	}
	for ip, ts := range l.ipFails {
		if now.Sub(ts[len(ts)-1]) >= l.Window {
			delete(l.ipFails, ip)
		}
	}
}

func (l *Limiter) Allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ensureInit()
	now := time.Now()
	l.sweep(now)
	if ip := extractIPFromKey(key); ip != "" {
		if len(l.recentIn(l.ipFails, ip, now)) >= l.MaxPerIP {
			return false
		}
	}
	return len(l.recent(key, now)) < l.Max
}

func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ensureInit()
	now := time.Now()
	l.sweep(now)

	ip := extractIPFromKey(key)
	if ip != "" {
		prevIP := l.recentIn(l.ipFails, ip, now)
		if len(prevIP) >= l.MaxPerIP {
			// IP is already rate-limited; still trim/append up to cap without creating
			// new per-username keys to protect MaxKeys against single-IP key flooding.
			return
		}
		l.ipFails[ip] = append(prevIP, now)
	}

	prev := l.recent(key, now)
	if len(prev) == 0 && len(l.fails) >= l.MaxKeys {
		// Evict oldest tracked key (LRU) so active attacks cannot bypass tracking.
		if back := l.lru.Back(); back != nil {
			l.removeKey(back.Value.(string))
		}
	}
	l.fails[key] = append(prev, now)
	l.touchKey(key)
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ensureInit()
	l.removeKey(key)
}

// Len is how many keys are tracked (for tests and metrics).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fails == nil {
		return 0
	}
	return len(l.fails)
}
