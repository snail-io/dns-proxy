package dns

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	miekgdns "github.com/miekg/dns"
)

type UpstreamQuery struct {
	URL string
}

func (u UpstreamQuery) Query(ctx context.Context, req *miekgdns.Msg) (*miekgdns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if strings.HasPrefix(u.URL, "https://") || strings.HasPrefix(u.URL, "http://") {
		return dohQuery(ctx, u.URL, req)
	}
	return stdDNSQuery(ctx, u.URL, req)
}

func dohQuery(ctx context.Context, url string, req *miekgdns.Msg) (*miekgdns.Msg, error) {
	packed, err := req.Pack()
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/dns-message")
	hreq.Header.Set("Accept", "application/dns-message")

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 5 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &httpErr{code: resp.StatusCode, body: body}
	}
	m := new(miekgdns.Msg)
	if err := m.Unpack(body); err != nil {
		return nil, err
	}
	return m, nil
}

type httpErr struct {
	code int
	body []byte
}

func (e *httpErr) Error() string { return "DoH HTTP " + string(e.body[:min(40, len(e.body))]) }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func stdDNSQuery(ctx context.Context, addr string, req *miekgdns.Msg) (*miekgdns.Msg, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	udp := &miekgdns.Client{Net: "udp", Timeout: 5 * time.Second}
	r, _, err := udp.ExchangeContext(ctx, req, addr)
	if err == nil && r != nil {
		return r, nil
	}
	tcp := &miekgdns.Client{Net: "tcp", Timeout: 5 * time.Second}
	resp, _, err2 := tcp.ExchangeContext(ctx, req, addr)
	if err2 != nil {
		return nil, err
	}
	return resp, nil
}

type forwardCounter struct {
	n int64
}

func (f *forwardCounter) Incr() { atomic.AddInt64(&f.n, 1) }
func (f *forwardCounter) Get() int64 { return atomic.LoadInt64(&f.n) }

var ForwardCount = &forwardCounter{}
var LocalCount = &forwardCounter{}
