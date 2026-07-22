package doh

import (
	"context"
	"io"
	"net/http"
	"time"

	miekgdns "github.com/miekg/dns"

	"github.com/go-dns-proxy/dns-proxy/internal/dns"
)

const mimeType = "application/dns-message"

type Resolver interface {
	Resolve(ctx context.Context, req *miekgdns.Msg) (*miekgdns.Msg, error)
}

type handlerResolver struct {
	h *dns.Handler
}

func (r *handlerResolver) Resolve(ctx context.Context, req *miekgdns.Msg) (*miekgdns.Msg, error) {
	return r.h.Resolve(ctx, req)
}

func Handler(h *dns.Handler) http.HandlerFunc {
	return ResolverHandler(&handlerResolver{h: h})
}

func ResolverHandler(r Resolver) http.HandlerFunc {
	return func(w http.ResponseWriter, rq *http.Request) {
		if rq.URL.Path != "/dns-query" {
			http.NotFound(w, rq)
			return
		}
		ctx, cancel := context.WithTimeout(rq.Context(), 10*time.Second)
		defer cancel()
		switch rq.Method {
		case http.MethodPost:
			if rq.Header.Get("Content-Type") != mimeType {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			}
			body, err := io.ReadAll(io.LimitReader(rq.Body, 65535))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = rq.Body.Close()
			req := new(miekgdns.Msg)
			if err := req.Unpack(body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			resp, err := r.Resolve(ctx, req)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			packed, err := resp.Pack()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", mimeType)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(packed)
		case http.MethodGet:
			qname := rq.URL.Query().Get("name")
			if qname == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			rdtype := rq.URL.Query().Get("type")
			qtype := miekgdns.TypeA
			if rd := miekgdns.StringToType[rdtype]; rd != 0 {
				qtype = rd
			}
			req := new(miekgdns.Msg)
			req.SetQuestion(miekgdns.Fqdn(qname), qtype)
			resp, err := r.Resolve(ctx, req)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			packed, err := resp.Pack()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", mimeType)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(packed)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}
