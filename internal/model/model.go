package model

import "time"

type DomainRule struct {
	ID        int64     `json:"id"`
	Domain    string    `json:"domain"`
	Mode      string    `json:"mode"`
	Upstream  string    `json:"upstream"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RuleCreate struct {
	Domain   string `json:"domain"`
	Mode     string `json:"mode"`
	Upstream string `json:"upstream"`
	Enabled  *bool  `json:"enabled,omitempty"`
}

type RuleUpdate struct {
	Domain   *string `json:"domain,omitempty"`
	Mode     *string `json:"mode,omitempty"`
	Upstream *string `json:"upstream,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
}

type HostRecord struct {
	ID        int64     `json:"id"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	MatchMode string    `json:"match_mode"`
	Value     string    `json:"value"`
	TTL       int       `json:"ttl"`
	Comment   string    `json:"comment"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type HostCreate struct {
	Domain    string `json:"domain"`
	Type      string `json:"type"`
	MatchMode string `json:"match_mode"`
	Value     string `json:"value"`
	TTL       *int   `json:"ttl,omitempty"`
	Comment   string `json:"comment,omitempty"`
	Enabled   *bool  `json:"enabled,omitempty"`
}

type HostUpdate struct {
	Domain    *string `json:"domain,omitempty"`
	Type      *string `json:"type,omitempty"`
	MatchMode *string `json:"match_mode,omitempty"`
	Value     *string `json:"value,omitempty"`
	TTL       *int    `json:"ttl,omitempty"`
	Comment   *string `json:"comment,omitempty"`
	Enabled   *bool   `json:"enabled,omitempty"`
}

type StatusInfo struct {
	Rules       int   `json:"rules"`
	Hosts       int   `json:"hosts"`
	CacheHits   int64 `json:"cache_hits"`
	CacheMisses int64 `json:"cache_misses"`
	Forwards    int64 `json:"forwards"`
	LocalHits   int64 `json:"local_hits"`
}

type ConfigInfo struct {
	DNSAddr          string `json:"dns_addr"`
	DoHAddr          string `json:"doh_addr"`
	HTTPAddr         string `json:"http_addr"`
	DefaultUpstream  string `json:"default_upstream"`
	DBPath           string `json:"db_path"`
	CertFile         string `json:"cert_file"`
	KeyFile          string `json:"key_file"`
	AdminUser        string `json:"admin_user"`
}
