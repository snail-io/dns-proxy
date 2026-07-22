package config

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	DNSAddr        string
	DoTAddr        string
	DoHAddr        string
	HTTPAddr       string
	DBCacheDir     string
	CertDir        string
	CertFile       string
	KeyFile        string
	CACertFile     string
	CAKeyFile      string
	DoHHost        string
	DefaultUpstream string
	AdminUser      string
	AdminPass      string
	DevCert        bool
}

func parseEnvOrFlag(flagName, envKey, def string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return def
}

func Load() *Config {
	cfg := &Config{}
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)

	flag.StringVar(&cfg.DNSAddr, "dns", parseEnvOrFlag("dns", "DP_DNS_ADDR", "0.0.0.0:15353"), "DNS listen addr (udp+tcp)")
	flag.StringVar(&cfg.DoTAddr, "dot", parseEnvOrFlag("dot", "DP_DOT_ADDR", "0.0.0.0:1853"), "DoT listen addr (TLS)")
	flag.StringVar(&cfg.DoHAddr, "doh", parseEnvOrFlag("doh", "DP_DOH_ADDR", "0.0.0.0:1443"), "DoH listen addr (HTTPS)")
	flag.StringVar(&cfg.HTTPAddr, "http", parseEnvOrFlag("http", "DP_HTTP_ADDR", "0.0.0.0:8443"), "admin HTTPS listen addr")

	flag.StringVar(&cfg.DBCacheDir, "data", parseEnvOrFlag("data", "DP_DATA_DIR", filepath.Join(exeDir, "data")), "data dir (db + cache)")
	flag.StringVar(&cfg.CertDir, "cert-dir", parseEnvOrFlag("cert-dir", "DP_CERT_DIR", filepath.Join(exeDir, "certs")), "certificate directory")

	flag.StringVar(&cfg.CertFile, "cert-file", parseEnvOrFlag("cert-file", "DP_CERT_FILE", ""), "HTTPS cert file path (overrides cert-dir)")
	flag.StringVar(&cfg.KeyFile, "key-file", parseEnvOrFlag("key-file", "DP_KEY_FILE", ""), "HTTPS key file path (overrides cert-dir)")

	flag.StringVar(&cfg.DoHHost, "doh-host", parseEnvOrFlag("doh-host", "DP_DOH_HOST", ""), "hostname for DoH URL (e.g. dns.home; added to cert SAN; optional)")

	flag.StringVar(&cfg.DefaultUpstream, "default-upstream", parseEnvOrFlag("default-upstream", "DP_DEFAULT_UPSTREAM", "8.8.8.8:53"), "default upstream DNS server (host:port) or DoH URL")

	user := parseEnvOrFlag("admin-user", "DP_ADMIN_USER", "admin")
	pass := parseEnvOrFlag("admin-pass", "DP_ADMIN_PASS", "changeme")
	flag.StringVar(&cfg.AdminUser, "admin-user", user, "admin http basic user")
	flag.StringVar(&cfg.AdminPass, "admin-pass", pass, "admin http basic password")

	devCert := os.Getenv("DP_DEV_CERT") == "1"
	flag.BoolVar(&cfg.DevCert, "dev-cert", devCert, "force regenerate self-signed cert on each start")

	flag.Parse()

	if err := os.MkdirAll(cfg.DBCacheDir, 0o755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(cfg.CertDir, 0o755); err != nil {
		panic(err)
	}

	if cfg.CertFile == "" {
		cfg.CertFile = filepath.Join(cfg.CertDir, "server.crt")
	}
	if cfg.KeyFile == "" {
		cfg.KeyFile = filepath.Join(cfg.CertDir, "server.key")
	}
	cfg.CACertFile = filepath.Join(cfg.CertDir, "ca.crt")
	cfg.CAKeyFile = filepath.Join(cfg.CertDir, "ca.key")
	if !strings.HasSuffix(cfg.DBCacheDir, string(os.PathSeparator)) {
		cfg.DBCacheDir += string(os.PathSeparator)
	}
	return cfg
}
