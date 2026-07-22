package dns

import (
	"context"
	"net"
	"strings"
	"sync"

	miekgdns "github.com/miekg/dns"

	"github.com/go-dns-proxy/dns-proxy/internal/cache"
)

type Handler struct {
	mu              sync.RWMutex
	cache           *cache.RuleCache
	hosts           *cache.HostCache
	defaultUpstream string
}

func NewHandler(c *cache.RuleCache, h *cache.HostCache, defaultUpstream string) *Handler {
	return &Handler{cache: c, hosts: h, defaultUpstream: defaultUpstream}
}

func (h *Handler) GetDefault() string { return h.defaultUpstream }

func (h *Handler) Match(fqdn string) (string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cache.Match(fqdn)
}

func (h *Handler) resolveLocal(req *miekgdns.Msg) (*miekgdns.Msg, bool) {
	if h.hosts == nil {
		return nil, false
	}
	q := req.Question[0]
	qtype := q.Qtype
	qname := strings.ToLower(q.Name)

	lookupType := "ANY"
	switch qtype {
	case miekgdns.TypeA:
		lookupType = "A"
	case miekgdns.TypeAAAA:
		lookupType = "AAAA"
	case miekgdns.TypeTXT:
		lookupType = "TXT"
	case miekgdns.TypeCNAME:
		lookupType = "CNAME"
	case miekgdns.TypeANY:
		lookupType = "ANY"
	default:
		_, ok := h.hosts.Lookup(qname, "ANY")
		if !ok {
			return nil, false
		}
	}

	entries, ok := h.hosts.Lookup(qname, lookupType)
	if !ok {
		return nil, false
	}

	resp := new(miekgdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	for _, e := range entries {
		switch e.Type {
		case "A":
			if qtype != miekgdns.TypeA && qtype != miekgdns.TypeANY {
				continue
			}
			ip := net.ParseIP(e.Value)
			if ip == nil || ip.To4() == nil {
				continue
			}
			rr := &miekgdns.A{
				Hdr: miekgdns.RR_Header{Name: qname, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: e.TTL},
				A:   ip.To4(),
			}
			resp.Answer = append(resp.Answer, rr)
		case "AAAA":
			if qtype != miekgdns.TypeAAAA && qtype != miekgdns.TypeANY {
				continue
			}
			ip := net.ParseIP(e.Value)
			if ip == nil {
				continue
			}
			rr := &miekgdns.AAAA{
				Hdr:  miekgdns.RR_Header{Name: qname, Rrtype: miekgdns.TypeAAAA, Class: miekgdns.ClassINET, Ttl: e.TTL},
				AAAA: ip.To16(),
			}
			resp.Answer = append(resp.Answer, rr)
		case "TXT":
			if qtype != miekgdns.TypeTXT && qtype != miekgdns.TypeANY {
				continue
			}
			txt := e.Value
			rr := &miekgdns.TXT{
				Hdr: miekgdns.RR_Header{Name: qname, Rrtype: miekgdns.TypeTXT, Class: miekgdns.ClassINET, Ttl: e.TTL},
				Txt: []string{txt},
			}
			resp.Answer = append(resp.Answer, rr)
		case "CNAME":
			if qtype != miekgdns.TypeCNAME && qtype != miekgdns.TypeANY {
				continue
			}
			target := e.Value
			if !strings.HasSuffix(target, ".") {
				target = target + "."
			}
			rr := &miekgdns.CNAME{
				Hdr:    miekgdns.RR_Header{Name: qname, Rrtype: miekgdns.TypeCNAME, Class: miekgdns.ClassINET, Ttl: e.TTL},
				Target: target,
			}
			resp.Answer = append(resp.Answer, rr)
			if qtype == miekgdns.TypeA || qtype == miekgdns.TypeAAAA {
				targetQ := new(miekgdns.Msg)
				targetQ.SetQuestion(target, qtype)
				if tresp, tfound := h.resolveLocal(targetQ); tfound && len(tresp.Answer) > 0 {
					resp.Answer = append(resp.Answer, tresp.Answer...)
				}
			}
		}
	}
	if len(resp.Answer) == 0 {
		resp.Rcode = miekgdns.RcodeNameError
	}
	LocalCount.Incr()
	return resp, true
}

func (h *Handler) Resolve(ctx context.Context, req *miekgdns.Msg) (*miekgdns.Msg, error) {
	if len(req.Question) == 0 {
		resp := new(miekgdns.Msg)
		resp.SetReply(req)
		resp.Rcode = miekgdns.RcodeFormatError
		return resp, nil
	}

	if resp, ok := h.resolveLocal(req); ok {
		return resp, nil
	}

	q := req.Question[0]
	upstream, ok := h.Match(q.Name)
	if !ok {
		upstream = h.defaultUpstream
	}
	up := UpstreamQuery{URL: upstream}
	fwd, err := up.Query(ctx, req)
	if err != nil {
		resp := new(miekgdns.Msg)
		resp.SetReply(req)
		resp.Rcode = 2
		return resp, nil
	}
	ForwardCount.Incr()
	return fwd, nil
}

func (h *Handler) Handle(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
	resp, _ := h.Resolve(context.Background(), r)
	_ = w.WriteMsg(resp)
}
