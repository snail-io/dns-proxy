package httpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func EnsureSelfSigned(certFile, keyFile, caCertFile, caKeyFile string, force bool, extraDomains ...string) (*tls.Config, bool, error) {
	if certFile == "" || keyFile == "" {
		return nil, false, errors.New("cert file is empty")
	}

	if force {
		_ = os.Remove(certFile)
		_ = os.Remove(keyFile)
		_ = os.Remove(caCertFile)
		_ = os.Remove(caKeyFile)
	}

	needsGen := force || !fileExists(certFile) || !fileExists(keyFile)
	if needsGen {
		if err := generateCAAndServer(caCertFile, caKeyFile, certFile, keyFile, extraDomains...); err != nil {
			return nil, false, err
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, false, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}, needsGen, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func localIPs() []net.IP {
	var ips []net.IP
	ips = append(ips, net.IPv4(127, 0, 0, 1), net.IPv4(0, 0, 0, 0), net.IPv6loopback)
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
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
			switch v := a.(type) {
			case *net.IPNet:
				if v.IP == nil {
					continue
				}
				ips = append(ips, v.IP)
			case *net.IPAddr:
				if v.IP == nil {
					continue
				}
				ips = append(ips, v.IP)
			}
		}
	}
	return ips
}

func generateCAAndServer(caCertFile, caKeyFile, certFile, keyFile string, extraDomains ...string) error {
	for _, p := range []string{caCertFile, caKeyFile, certFile, keyFile} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
	}

	now := time.Now().Add(-1 * time.Hour)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			Organization: []string{"DNS Proxy Local CA"},
			CommonName:   "DNS Proxy Local CA",
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(caCertFile, "CERTIFICATE", caDER); err != nil {
		return err
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return err
	}
	if err := writePEM(caKeyFile, "EC PRIVATE KEY", caKeyDER); err != nil {
		return err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	srvSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}

	dnsNames := map[string]bool{
		"localhost":       true,
		"dns-proxy.local": true,
	}
	for _, d := range extraDomains {
		d = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(d, "https://"), "/"))
		if d != "" {
			dnsNames[d] = true
		}
		if !strings.Contains(d, "*.") {
			dnsNames["*."+d] = true
		}
	}
	ips := localIPs()

	var names []string
	for n := range dnsNames {
		names = append(names, n)
	}

	srvTmpl := &x509.Certificate{
		SerialNumber: srvSerial,
		Subject: pkix.Name{
			Organization: []string{"DNS Proxy"},
			CommonName:   firstCN(names, "dns-proxy.local"),
		},
		NotBefore: now,
		NotAfter:  now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              names,
		IPAddresses:           ips,
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(certFile, "CERTIFICATE", srvDER); err != nil {
		return err
	}
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return err
	}
	if err := writePEM(keyFile, "EC PRIVATE KEY", srvKeyDER); err != nil {
		return err
	}

	fmt.Println("=== TLS certificate generated ===")
	fmt.Printf("  CA Root : %s (import this one into your OS/browser once)\n", caCertFile)
	fmt.Printf("  Server  : %s\n", certFile)
	fmt.Printf("  Key     : %s\n", keyFile)
	fmt.Printf("  SAN DNS : %s\n", strings.Join(names, ", "))
	var ipStrs []string
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}
	fmt.Printf("  SAN IP  : %s\n", strings.Join(ipStrs, ", "))
	fmt.Println("  ")
	fmt.Println("  How to trust it:")
	fmt.Println("    Windows: right-click ca.crt → Install Certificate → Local Machine → Trusted Root")
	fmt.Println("    Edge/Chrome: Settings → Privacy/Security → Manage Certificates → Trusted Root → Import ca.crt")
	fmt.Println("    Firefox: Certificates → View Certificates → Authorities → Import ca.crt → check 'Trust for websites'")
	fmt.Println("  ")
	fmt.Println("  After importing, reload the app once to pick up the server cert.")
	return nil
}

func firstCN(names []string, fallback string) string {
	for _, n := range names {
		if !strings.HasPrefix(n, "*") {
			return n
		}
	}
	return fallback
}

func writePEM(path, blockType string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}
