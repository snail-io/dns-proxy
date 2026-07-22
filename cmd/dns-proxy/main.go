package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"
	miekgdns "github.com/miekg/dns"

	"github.com/go-dns-proxy/dns-proxy/internal/cache"
	"github.com/go-dns-proxy/dns-proxy/internal/config"
	"github.com/go-dns-proxy/dns-proxy/internal/dns"
	httpserverpkg "github.com/go-dns-proxy/dns-proxy/internal/httpserver"
	"github.com/go-dns-proxy/dns-proxy/internal/logging"
	"github.com/go-dns-proxy/dns-proxy/internal/model"
	"github.com/go-dns-proxy/dns-proxy/internal/storage"
	"github.com/go-dns-proxy/dns-proxy/internal/web"
)

func main() {
	cfg := config.Load()

	exe, _ := os.Executable()
	logDir := filepath.Join(filepath.Dir(exe), "logs")
	logging.Init(logDir)

	if isatty.IsTerminal(os.Stdin.Fd()) {
		_, dnsPort, _ := net.SplitHostPort(cfg.DNSAddr)
		_, dotPort, _ := net.SplitHostPort(cfg.DoTAddr)
		_, dohPort, _ := net.SplitHostPort(cfg.DoHAddr)

		dp := parseIntPort(dnsPort, 15353)
		dp = readPortInput("DNS 服务端口", dp)
		cfg.DNSAddr = fmt.Sprintf("0.0.0.0:%d", dp)

		dotp := parseIntPort(dotPort, 1853)
		dotp = readPortInput("DoT 服务端口", dotp)
		cfg.DoTAddr = fmt.Sprintf("0.0.0.0:%d", dotp)

		dohp := parseIntPort(dohPort, 1443)
		dohp = readPortInput("DoH 服务端口", dohp)
		cfg.DoHAddr = fmt.Sprintf("0.0.0.0:%d", dohp)
	}

	db, err := storage.Open(cfg.DBCacheDir + "dns.db")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}

	notify := cache.NewNotify()
	rc := cache.New()
	cache.SetGlobal(rc)
	hc := cache.NewHostCache()
	reloader := cache.NewReloaderWithHosts(db, rc, hc)
	if err := reloader.Reload(context.Background()); err != nil {
		log.Printf("initial rules reload: %v", err)
	}

	extraDomains := buildCertDomains(cfg)

	dnsHandler := dns.NewHandler(rc, hc, cfg.DefaultUpstream)
	dnsSrv := dns.NewServer(cfg.DNSAddr, dnsHandler)
	if err := dnsSrv.Start(); err != nil {
		log.Fatalf("dns start: %v", err)
	}
	if err := dnsSrv.StartTLS(cfg.DoTAddr, cfg.CertFile, cfg.KeyFile); err != nil {
		log.Fatalf("dot start: %v", err)
	}
	defer dnsSrv.Shutdown()

	dohMux := buildDoHMux(dnsHandler)
	dohServer, dohWasNew, err := httpserverpkg.NewWithTLS(cfg.DoHAddr, dohMux, "HTTPS/DoH", cfg.CertFile, cfg.KeyFile, cfg.CACertFile, cfg.CAKeyFile, cfg.DevCert, extraDomains...)
	if err != nil {
		log.Fatalf("doh https: %v", err)
	}

	adminMux := buildAdminMux(cfg, db, reloader, notify)
	adminServer, adminWasNew, err := httpserverpkg.NewWithTLS(cfg.HTTPAddr, adminMux, "HTTPS/Manage", cfg.CertFile, cfg.KeyFile, cfg.CACertFile, cfg.CAKeyFile, false, extraDomains...)
	if err != nil {
		log.Fatalf("admin https: %v", err)
	}

	if dohWasNew || adminWasNew {
		installCARootCert(cfg.CACertFile)
	}

	go dohServer.Start()
	go adminServer.Start()

	printQuickStart(cfg)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("shutting down...")
	dnsSrv.Shutdown()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	_ = dohServer.Server.Shutdown(ctx2)
	_ = adminServer.Server.Shutdown(ctx2)
	logging.Flush()
	log.Println("stopped.")
}

func buildDoHMux(h *dns.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", dohHandler(h))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<h1>DNS Proxy DoH</h1><p>Use <code>/dns-query</code>.</p>"))
			return
		}
		http.NotFound(w, r)
	})
	return mux
}

func dohHandler(h *dns.Handler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		var req *miekgdns.Msg

		if r.Method == http.MethodGet {
			q := r.URL.Query()
			if b64 := q.Get("dns"); b64 != "" {
				raw, err := base64.RawURLEncoding.DecodeString(b64)
				if err != nil {
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = io.WriteString(w, "bad dns param: must be base64url-encoded DNS wire message\nExample: /dns-query?dns=AAEBAAABAAAAA...\nOr try:  /dns-query?name=demo.com&type=A")
					return
				}
				req = new(miekgdns.Msg)
				if err := req.Unpack(raw); err != nil {
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = io.WriteString(w, "bad dns msg: decode failed")
					return
				}
			} else if name := q.Get("name"); name != "" {
				rdtype := q.Get("type")
				qt := miekgdns.TypeA
				if rd := miekgdns.StringToType[rdtype]; rd != 0 {
					qt = rd
				}
				req = new(miekgdns.Msg)
				req.SetQuestion(miekgdns.Fqdn(name), qt)
			} else {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w,
					"<h1>DNS Proxy DoH</h1>"+
						"<p>This endpoint speaks RFC 8484 DoH.</p>"+
						"<h3>Usage</h3>"+
						"<ul>"+
						"<li><b>POST</b> with <code>Content-Type: application/dns-message</code> and a DNS wire message in the body.</li>"+
						"<li><b>GET</b> <code>/dns-query?dns=&lt;base64url&gt;</code> — base64url-encoded DNS wire message.</li>"+
						"<li><b>GET</b> <code>/dns-query?name=demo.com&amp;type=A</code> — human-friendly test (only for GET).</li>"+
						"</ul>"+
						"<p>Try: <a href=\"/dns-query?name=demo.com&amp;type=A\">/dns-query?name=demo.com&amp;type=A</a></p>")
				return
			}
		} else if r.Method == http.MethodPost {
			ct := r.Header.Get("Content-Type")
			if ct != "application/dns-message" {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, "bad content-type: expected application/dns-message")
				return
			}
			raw, err := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if err != nil {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, "read body: "+err.Error())
				return
			}
			req = new(miekgdns.Msg)
			if err := req.Unpack(raw); err != nil {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, "bad dns msg: decode failed")
				return
			}
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = io.WriteString(w, "method not allowed: use GET or POST")
			return
		}

		resp, err := h.Resolve(ctx, req)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, err.Error())
			return
		}
		if resp == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "no response from upstream")
			return
		}
		out, err := resp.Pack()
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "pack failed: "+err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Content-Length", strconv.Itoa(len(out)))
		_, _ = w.Write(out)
	}
}

func buildAdminMux(cfg *config.Config, db *storage.Store, reloader *cache.Reloader, notify *cache.Notify) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/", auth(db, serveIndex()))
	mux.Handle("/app.js", auth(db, serveStaticFile("app.js")))
	mux.Handle("/style.css", auth(db, serveStaticFile("style.css")))

	mux.Handle("/api/rules", auth(db, rulesHandler(db, reloader, notify)))
	mux.Handle("/api/rules/", auth(db, ruleByIDHandler(db, reloader, notify)))
	mux.Handle("/api/rules/reload", auth(db, reloadHandler(reloader, notify)))
	mux.Handle("/api/hosts", auth(db, hostsHandler(db, reloader, notify)))
	mux.Handle("/api/hosts/", auth(db, hostByIDHandler(db, reloader, notify)))
	mux.Handle("/api/config", auth(db, configHandler(cfg)))
	mux.Handle("/api/status", auth(db, statusHandler(cfg, reloader)))
	mux.Handle("/api/auth", auth(db, authHandler(db)))
	return mux
}

func serveIndex() http.Handler {
	data, err := web.Static.ReadFile("static/index.html")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "index.html missing: "+err.Error(), 500)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
}

func serveStaticFile(name string) http.Handler {
	data, err := web.Static.ReadFile("static/" + name)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, name+" missing: "+err.Error(), 500)
		})
	}
	ct := "text/plain; charset=utf-8"
	switch name {
	case "app.js":
		ct = "application/javascript; charset=utf-8"
	case "style.css":
		ct = "text/css; charset=utf-8"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})
}

func auth(db *storage.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="dns-proxy"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		adminUser, err := db.GetAdminUser(r.Context())
		if err != nil {
			log.Printf("get admin user: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		adminPass, err := db.GetAdminPass(r.Context())
		if err != nil {
			log.Printf("get admin pass: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if subtle.ConstantTimeCompare([]byte(u), []byte(adminUser)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(adminPass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="dns-proxy"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func reloadHandler(reloader *cache.Reloader, notify *cache.Notify) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		if err := reloader.Reload(r.Context()); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		notify.Signal()
		writeJSON(w, map[string]string{"status": "ok"})
	})
}

func rulesHandler(db *storage.Store, reloader *cache.Reloader, notify *cache.Notify) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			list, err := db.ListRules(r.Context())
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			writeJSON(w, list)
		case http.MethodPost:
			var c model.RuleCreate
			if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			_ = r.Body.Close()
			if c.Domain == "" || c.Mode == "" {
				http.Error(w, "domain/mode required", 400)
				return
			}
			if c.Domain != "*" && c.Mode != "exact" && c.Mode != "suffix" {
				http.Error(w, "mode must be exact or suffix", 400)
				return
			}
			rule, err := db.CreateRule(r.Context(), c)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if err := reloader.Reload(r.Context()); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			notify.Signal()
			writeJSON(w, rule)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
}

func ruleByIDHandler(db *storage.Store, reloader *cache.Reloader, notify *cache.Notify) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trimmed := r.URL.Path[len("/api/rules/"):]
		if trimmed == "" {
			http.Error(w, "id required", 400)
			return
		}
		id, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			http.Error(w, "bad id", 400)
			return
		}
		switch r.Method {
		case http.MethodGet:
			rule, err := db.GetRule(r.Context(), id)
			if err != nil {
				http.Error(w, err.Error(), 404)
				return
			}
			writeJSON(w, rule)
		case http.MethodPut, http.MethodPatch:
			var u model.RuleUpdate
			if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			_ = r.Body.Close()
			if _, err := db.UpdateRule(r.Context(), id, u); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if err := reloader.Reload(r.Context()); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			notify.Signal()
			writeJSON(w, map[string]string{"status": "ok"})
		case http.MethodDelete:
			if err := db.DeleteRule(r.Context(), id); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if err := reloader.Reload(r.Context()); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			notify.Signal()
			writeJSON(w, map[string]string{"status": "ok"})
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
}

func hostsHandler(db *storage.Store, reloader *cache.Reloader, notify *cache.Notify) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			list, err := db.ListHosts(r.Context())
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			writeJSON(w, list)
		case http.MethodPost:
			var c model.HostCreate
			if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			_ = r.Body.Close()
			if c.Domain == "" || c.Value == "" {
				http.Error(w, "domain/value required", 400)
				return
			}
			h, err := db.CreateHost(r.Context(), c)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if err := reloader.Reload(r.Context()); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			notify.Signal()
			writeJSON(w, h)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
}

func hostByIDHandler(db *storage.Store, reloader *cache.Reloader, notify *cache.Notify) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trimmed := r.URL.Path[len("/api/hosts/"):]
		if trimmed == "" {
			http.Error(w, "id required", 400)
			return
		}
		id, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			http.Error(w, "bad id", 400)
			return
		}
		switch r.Method {
		case http.MethodGet:
			h, err := db.GetHost(r.Context(), id)
			if err != nil {
				http.Error(w, err.Error(), 404)
				return
			}
			writeJSON(w, h)
		case http.MethodPut, http.MethodPatch:
			var u model.HostUpdate
			if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			_ = r.Body.Close()
			if _, err := db.UpdateHost(r.Context(), id, u); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if err := reloader.Reload(r.Context()); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			notify.Signal()
			writeJSON(w, map[string]string{"status": "ok"})
		case http.MethodDelete:
			if err := db.DeleteHost(r.Context(), id); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if err := reloader.Reload(r.Context()); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			notify.Signal()
			writeJSON(w, map[string]string{"status": "ok"})
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
}

func configHandler(cfg *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		writeJSON(w, map[string]string{
			"dns_addr":         cfg.DNSAddr,
			"dot_addr":         cfg.DoTAddr,
			"doh_addr":         cfg.DoHAddr,
			"http_addr":        cfg.HTTPAddr,
			"default_upstream": cfg.DefaultUpstream,
			"cert_file":        cfg.CertFile,
			"key_file":         cfg.KeyFile,
		})
	})
}

func authHandler(db *storage.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			var req struct {
				OldUser     string `json:"old_user"`
				OldPassword string `json:"old_password"`
				NewUser     string `json:"new_user"`
				NewPassword string `json:"new_password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			_ = r.Body.Close()

			if req.OldUser == "" || req.OldPassword == "" || req.NewUser == "" || req.NewPassword == "" {
				http.Error(w, "all fields required", 400)
				return
			}

			currentUser, err := db.GetAdminUser(r.Context())
			if err != nil {
				log.Printf("get admin user: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			currentPass, err := db.GetAdminPass(r.Context())
			if err != nil {
				log.Printf("get admin pass: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			if subtle.ConstantTimeCompare([]byte(req.OldUser), []byte(currentUser)) != 1 ||
				subtle.ConstantTimeCompare([]byte(req.OldPassword), []byte(currentPass)) != 1 {
				http.Error(w, "old username or password incorrect", 401)
				return
			}

			if err := db.UpdateAdminAccount(r.Context(), req.NewUser, req.NewPassword); err != nil {
				log.Printf("update admin account: %v", err)
				http.Error(w, "update failed", 500)
				return
			}

			writeJSON(w, map[string]string{"status": "ok"})
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
}

func statusHandler(cfg *config.Config, reloader *cache.Reloader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		writeJSON(w, map[string]any{
			"dns_addr":         cfg.DNSAddr,
			"dot_addr":         cfg.DoTAddr,
			"doh_addr":         cfg.DoHAddr,
			"http_addr":        cfg.HTTPAddr,
			"default_upstream": cfg.DefaultUpstream,
			"rules_loaded":     reloader.Count(),
			"hosts_loaded":     reloader.HostsCount(),
			"cache_hits":       cache.HitsCounter(),
			"cache_misses":     cache.MissesCounter(),
			"forwards":         dns.ForwardCount.Get(),
			"local_hits":       dns.LocalCount.Get(),
		})
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func buildCertDomains(cfg *config.Config) []string {
	var out []string
	if cfg.DoHHost != "" {
		out = append(out, cfg.DoHHost)
	}
	return out
}

func firstLocalIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return "127.0.0.1"
}

func printQuickStart(cfg *config.Config) {
	dohHost, dohPort, _ := net.SplitHostPort(cfg.DoHAddr)
	if dohHost == "" || dohHost == "0.0.0.0" {
		dohHost = firstLocalIP()
	}
	dotHost, dotPort, _ := net.SplitHostPort(cfg.DoTAddr)
	if dotHost == "" || dotHost == "0.0.0.0" {
		dotHost = firstLocalIP()
	}
	adminHost, adminPort, _ := net.SplitHostPort(cfg.HTTPAddr)
	if adminHost == "" || adminHost == "0.0.0.0" {
		adminHost = firstLocalIP()
	}

	fmt.Println()
	fmt.Println("===========================================")
	fmt.Println("  DNS Proxy is running")
	fmt.Println("===========================================")
	fmt.Printf("  DNS (udp+tcp) : %s\n", cfg.DNSAddr)
	fmt.Printf("  DoT (TLS)     : %s:%s\n", dotHost, dotPort)
	if cfg.DoHHost != "" {
		fmt.Printf("  DoH (secure)  : https://%s:%s/dns-query  (via hostname)\n", cfg.DoHHost, dohPort)
	}
	fmt.Printf("  DoH (secure)  : https://%s:%s/dns-query  (via IP)\n", dohHost, dohPort)
	fmt.Printf("  DoH (secure)  : https://127.0.0.1:%s/dns-query\n", dohPort)
	fmt.Printf("  Admin (HTTPS) : https://%s:%s/  (user=admin, pass=123456) (初始密码，请立即修改)\n", adminHost, adminPort)
	fmt.Println()
	fmt.Printf("  CA root to import once: %s\n", cfg.CACertFile)
	fmt.Println()
	fmt.Println("===========================================")
	fmt.Println()
}

func installCARootCert(caCertFile string) {
	if runtime.GOOS != "windows" {
		return
	}
	abs, err := filepath.Abs(caCertFile)
	if err != nil {
		log.Printf("ca cert abs path: %v", err)
		return
	}
	fmt.Println()
	fmt.Println("=== Installing CA root certificate ===")
	fmt.Printf("  Cert : %s\n", abs)
	runCertutil("certutil", "-addstore", "-enterprise", "Root", abs)
	runCertutil("certutil", "-addstore", "Root", abs)
	fmt.Println("  (If certutil reports 'Access denied', run this program as Administrator once.)")
	fmt.Println()
}

func runCertutil(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("  > %s %s\n", name, strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		log.Printf("  certutil failed: %v", err)
	}
}

func parseIntPort(s string, def int) int {
	if s == "" {
		return def
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return def
	}
	return p
}

func readPortInput(prompt string, defaultPort int) int {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return defaultPort
	}
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%s (默认: %d): ", prompt, defaultPort)
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			return defaultPort
		}
		port, err := strconv.Atoi(input)
		if err != nil || port < 1 || port > 65535 {
			fmt.Println("  错误: 端口号必须在 1-65535 范围内，请重新输入")
			continue
		}
		return port
	}
}
