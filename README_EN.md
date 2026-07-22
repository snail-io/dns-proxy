# DNS Proxy

English | [中文](README.md)

A lightweight DNS proxy server supporting DNS (UDP/TCP), DoT (DNS over TLS), and DoH (DNS over HTTPS) protocols with a built-in web management interface.

## Features

- **Multi-Protocol Support**: DNS (UDP/TCP), DoT (TLS 853), DoH (HTTPS)
- **Domain Rules**: Supports exact match and subdomain wildcard matching with customizable upstream servers
- **Local Records**: Custom A, AAAA, CNAME, TXT records with local priority responses
- **Web Management**: HTTPS-based admin panel with visual configuration and real-time status monitoring
- **Secure Authentication**: AES-encrypted admin credentials with online modification support
- **Self-Signed Certs**: Built-in CA certificate generation, ready to use

## Quick Start

### Build

```bash
go build -o dns-proxy.exe ./cmd/dns-proxy
```

### Run

```bash
# Default configuration
.\dns-proxy.exe

# Custom parameters
.\dns-proxy.exe -dns 0.0.0.0:15353 -dot 0.0.0.0:1853 -doh 0.0.0.0:1443 -http 0.0.0.0:8443
```

### Default Credentials

- Username: `admin`
- Password: `123456`

> ⚠️ Please change the password immediately after first login in the "Account Settings" tab.

## CLI Parameters

| Flag | Environment | Default | Description |
|------|-------------|---------|-------------|
| `-dns` | `DP_DNS_ADDR` | `0.0.0.0:15353` | DNS service listen address (UDP/TCP) |
| `-dot` | `DP_DOT_ADDR` | `0.0.0.0:1853` | DoT service listen address (TLS) |
| `-doh` | `DP_DOH_ADDR` | `0.0.0.0:1443` | DoH service listen address (HTTPS) |
| `-http` | `DP_HTTP_ADDR` | `0.0.0.0:8443` | Web admin listen address |
| `-data` | `DP_DATA_DIR` | `./data` | Data directory (database and cache) |
| `-cert-dir` | `DP_CERT_DIR` | `./certs` | Certificate directory |
| `-cert-file` | `DP_CERT_FILE` | - | HTTPS cert file path (overrides cert-dir) |
| `-key-file` | `DP_KEY_FILE` | - | HTTPS key file path (overrides cert-dir) |
| `-doh-host` | `DP_DOH_HOST` | - | DoH hostname (added to cert SAN) |
| `-default-upstream` | `DP_DEFAULT_UPSTREAM` | `8.8.8.8:53` | Default upstream DNS server |
| `-dev-cert` | `DP_DEV_CERT` | `false` | Regenerate self-signed cert on each start |

## Web Management

Access after startup: `https://<local-ip>:8443/`

### Modules

1. **Rules & Upstream**
   - Add/edit/delete domain matching rules
   - Exact match and subdomain wildcard support
   - Per-rule upstream server assignment
   - One-click cache refresh

2. **Local Records**
   - Add local DNS records (A, AAAA, CNAME, TXT)
   - Exact/suffix match modes
   - Configurable TTL and comments

3. **Account Settings**
   - Change admin username and password
   - Requires current credentials verification

## API Reference

All endpoints require HTTP Basic Auth.

### Rules

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/rules` | Get all rules |
| POST | `/api/rules` | Create a rule |
| GET | `/api/rules/{id}` | Get a rule |
| PUT | `/api/rules/{id}` | Update a rule |
| DELETE | `/api/rules/{id}` | Delete a rule |
| POST | `/api/rules/reload` | Reload cache |

### Local Records

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/hosts` | Get all local records |
| POST | `/api/hosts` | Create a local record |
| GET | `/api/hosts/{id}` | Get a record |
| PUT | `/api/hosts/{id}` | Update a record |
| DELETE | `/api/hosts/{id}` | Delete a record |

### System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | System status |
| GET | `/api/config` | Current config |
| PUT | `/api/auth` | Change credentials |

### DoH

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/dns-query` | RFC 8484 DoH protocol |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 DNS Proxy Server                         │
├─────────────┬──────────────┬────────────────────────────┤
│  DNS (UDP)  │   DoT (TLS)   │        DoH (HTTPS)         │
│  :15353     │    :1853      │          :1443             │
├─────────────┴──────────────┴────────────────────────────┤
│                  Core Forward Engine                      │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Local Match  │→│  Rule Select  │→│ Forward/Cache │  │
│  └──────────────┘  └──────────────┘  └───────────────┘  │
├─────────────────────────────────────────────────────────┤
│              Web Admin (HTTPS :8443)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Rules API    │  │ Records API  │  │ Account API   │  │
│  └──────────────┘  └──────────────┘  └───────────────┘  │
├─────────────────────────────────────────────────────────┤
│                SQLite Database                            │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ domain_rules │  │ host_records │  │  app_config   │  │
│  └──────────────┘  └──────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Directory Structure

```
dns-proxy/
├── cmd/dns-proxy/          # Main entry point
├── internal/
│   ├── cache/              # DNS cache
│   ├── config/             # Config loading
│   ├── crypto/             # AES encryption utilities
│   ├── dns/                # Core DNS handling
│   ├── doh/                # DoH service
│   ├── httpserver/         # HTTPS/TLS server
│   ├── logging/            # Logger
│   ├── model/              # Data models
│   ├── storage/            # SQLite storage
│   └── web/                # Frontend static files
├── data/                   # Database (generated at runtime)
├── certs/                  # Certificates (generated at runtime)
├── logs/                   # Logs (generated at runtime)
└── go.mod
```

## License

Apache License 2.0