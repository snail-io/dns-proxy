package cache

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-dns-proxy/dns-proxy/internal/model"
	"github.com/go-dns-proxy/dns-proxy/internal/storage"
)

type HostEntry struct {
	Type   string
	Value  string
	TTL    uint32
}

type suffixHostEntry struct {
	labelCount int
	domain     string
	entries    []HostEntry
}

type HostCache struct {
	mu      sync.RWMutex
	exact   map[string][]HostEntry
	suffix  []suffixHostEntry
	hits    int64
}

func NewHostCache() *HostCache {
	return &HostCache{exact: make(map[string][]HostEntry)}
}

func (c *HostCache) Load(recs []model.HostRecord) {
	exact := make(map[string][]HostEntry)
	var suffixes []suffixHostEntry
	for _, r := range recs {
		if !r.Enabled {
			continue
		}
		origDomain := strings.TrimSpace(r.Domain)
		if origDomain == "" {
			continue
		}
		ttl := uint32(r.TTL)
		entry := HostEntry{
			Type: strings.ToUpper(r.Type),
			Value: r.Value,
			TTL:   ttl,
		}

		suffixDomain := origDomain
		if strings.HasPrefix(suffixDomain, "*.") {
			suffixDomain = suffixDomain[2:]
		}
		fqdn := normalize(suffixDomain)
		if fqdn == "" {
			continue
		}

		mode := strings.ToLower(strings.TrimSpace(r.MatchMode))
		if mode == "" {
			mode = "exact"
		}

		exact[fqdn] = append(exact[fqdn], entry)

		if mode == "suffix" {
			labels := labelsCount(fqdn)
			suffixes = append(suffixes, suffixHostEntry{labelCount: labels, domain: fqdn, entries: []HostEntry{entry}})
		}
	}
	sortHostSuffixes(suffixes)
	c.mu.Lock()
	c.exact = exact
	c.suffix = suffixes
	c.mu.Unlock()
}

func (c *HostCache) Lookup(fqdn, qtype string) ([]HostEntry, bool) {
	fqdn = normalize(fqdn)
	qtype = strings.ToUpper(strings.TrimSpace(qtype))
	if qtype == "" {
		qtype = "A"
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	if all, ok := c.exact[fqdn]; ok {
		if matched := filterEntries(all, qtype); len(matched) > 0 {
			atomic.AddInt64(&c.hits, 1)
			return matched, true
		}
	}

	for _, s := range c.suffix {
		if fqdn == s.domain || strings.HasSuffix(fqdn, "."+s.domain) {
			if matched := filterEntries(s.entries, qtype); len(matched) > 0 {
				atomic.AddInt64(&c.hits, 1)
				return matched, true
			}
		}
	}
	return nil, false
}

func filterEntries(all []HostEntry, qtype string) []HostEntry {
	var matched []HostEntry
	for _, h := range all {
		if h.Type == qtype || qtype == "ANY" {
			matched = append(matched, h)
		}
	}
	return matched
}

func (c *HostCache) Hits() int64 { return atomic.LoadInt64(&c.hits) }

func (c *HostCache) Size() int {
	c.mu.RLock()
	n := len(c.exact)
	c.mu.RUnlock()
	return n
}

type RuleCache struct {
	mu              sync.RWMutex
	exact           map[string]string
	suffix          []suffixEntry
	defaultUpstream string
	hits            int64
	misses          int64
}

type suffixEntry struct {
	labelCount int
	domain     string
	upstream   string
}

func New() *RuleCache {
	return &RuleCache{exact: make(map[string]string), suffix: nil}
}

func (c *RuleCache) Load(ctx context.Context, rules []model.DomainRule) {
	exact := make(map[string]string)
	var suffixes []suffixEntry
	var defaultUpstream string
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		rawDomain := strings.TrimSpace(r.Domain)
		if rawDomain == "" {
			continue
		}
		if rawDomain == "*" {
			defaultUpstream = r.Upstream
			continue
		}
		fqdn := normalize(rawDomain)
		if fqdn == "" {
			continue
		}
		if r.Mode == "exact" {
			exact[fqdn] = r.Upstream
			continue
		}
		labels := labelsCount(fqdn)
		suffixes = append(suffixes, suffixEntry{labelCount: labels, domain: fqdn, upstream: r.Upstream})
	}
	sortSuffixes(suffixes)
	c.mu.Lock()
	c.exact = exact
	c.suffix = suffixes
	c.defaultUpstream = defaultUpstream
	c.mu.Unlock()
}

func (c *RuleCache) Match(fqdn string) (upstream string, ok bool) {
	fqdn = normalize(fqdn)
	c.mu.RLock()
	if u, found := c.exact[fqdn]; found {
		c.mu.RUnlock()
		atomic.AddInt64(&c.hits, 1)
		return u, true
	}
	for _, s := range c.suffix {
		if fqdn == s.domain || strings.HasSuffix(fqdn, "."+s.domain) {
			c.mu.RUnlock()
			atomic.AddInt64(&c.hits, 1)
			return s.upstream, true
		}
	}
	if c.defaultUpstream != "" {
		def := c.defaultUpstream
		c.mu.RUnlock()
		atomic.AddInt64(&c.hits, 1)
		return def, true
	}
	c.mu.RUnlock()
	atomic.AddInt64(&c.misses, 1)
	return "", false
}

func (c *RuleCache) Hits() int64   { return atomic.LoadInt64(&c.hits) }
func (c *RuleCache) Misses() int64 { return atomic.LoadInt64(&c.misses) }
func (c *RuleCache) Size() int {
	c.mu.RLock()
	n := len(c.exact) + len(c.suffix)
	if c.defaultUpstream != "" {
		n++
	}
	c.mu.RUnlock()
	return n
}

var globalRuleCache *RuleCache

func SetGlobal(c *RuleCache) { globalRuleCache = c }
func HitsCounter() int64 {
	if globalRuleCache == nil {
		return 0
	}
	return globalRuleCache.Hits()
}
func MissesCounter() int64 {
	if globalRuleCache == nil {
		return 0
	}
	return globalRuleCache.Misses()
}

func normalize(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	if d == "" {
		return ""
	}
	if !strings.HasSuffix(d, ".") {
		d += "."
	}
	return d
}

func labelsCount(fqdn string) int {
	if fqdn == "." {
		return 0
	}
	return strings.Count(fqdn, ".")
}

func sortSuffixes(s []suffixEntry) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[j].labelCount > s[i].labelCount ||
				(s[j].labelCount == s[i].labelCount && len(s[j].domain) > len(s[i].domain)) {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

func sortHostSuffixes(s []suffixHostEntry) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[j].labelCount > s[i].labelCount ||
				(s[j].labelCount == s[i].labelCount && len(s[j].domain) > len(s[i].domain)) {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

type Reloader struct {
	store *storage.Store
	cache *RuleCache
	hosts *HostCache
}

func NewReloader(s *storage.Store, c *RuleCache) *Reloader {
	return &Reloader{store: s, cache: c}
}

func NewReloaderWithHosts(s *storage.Store, c *RuleCache, h *HostCache) *Reloader {
	return &Reloader{store: s, cache: c, hosts: h}
}

func (r *Reloader) Reload(ctx context.Context) error {
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()
	exact := make(map[string]string)
	var suffixes []suffixEntry
	var defaultUpstream string
	rules, err := r.store.ListRules(ctx)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		rawDomain := strings.TrimSpace(r.Domain)
		if rawDomain == "" {
			continue
		}
		if rawDomain == "*" {
			defaultUpstream = r.Upstream
			continue
		}
		fqdn := normalize(rawDomain)
		if fqdn == "" {
			continue
		}
		if r.Mode == "exact" {
			exact[fqdn] = r.Upstream
			continue
		}
		labels := labelsCount(fqdn)
		suffixes = append(suffixes, suffixEntry{labelCount: labels, domain: fqdn, upstream: r.Upstream})
	}
	sortSuffixes(suffixes)
	r.cache.exact = exact
	r.cache.suffix = suffixes
	r.cache.defaultUpstream = defaultUpstream

	if r.hosts != nil {
		recs, err := r.store.ListHosts(ctx)
		if err != nil {
			return err
		}
		r.hosts.Load(recs)
	}
	return nil
}

func (r *Reloader) Count() int {
	r.cache.mu.RLock()
	n := len(r.cache.exact) + len(r.cache.suffix)
	if r.cache.defaultUpstream != "" {
		n++
	}
	r.cache.mu.RUnlock()
	return n
}

func (r *Reloader) HostsCount() int {
	if r.hosts == nil {
		return 0
	}
	return r.hosts.Size()
}
