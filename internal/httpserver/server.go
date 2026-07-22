package httpserver

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-dns-proxy/dns-proxy/internal/logging"
)

type TLSServer struct {
	Server   *http.Server
	serverName string
}

func New(addr string, handler http.Handler) (*TLSServer, error) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return &TLSServer{Server: srv}, nil
}

type tlsErrorFilter struct {
	writer io.Writer
}

func (f *tlsErrorFilter) Write(p []byte) (n int, err error) {
	msg := string(p)
	if strings.Contains(msg, "TLS handshake error") || strings.Contains(msg, "wsarecv") {
		go logging.WriteToFile(p)
		return len(p), nil
	}
	return f.writer.Write(p)
}

func NewWithTLS(addr string, handler http.Handler, serverName string, certFile, keyFile, caCertFile, caKeyFile string, forceRegen bool, extraDomains ...string) (*TLSServer, bool, error) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(&tlsErrorFilter{writer: log.Default().Writer()}, "", 0),
	}
	tlsConfig, wasNew, err := EnsureSelfSigned(certFile, keyFile, caCertFile, caKeyFile, forceRegen, extraDomains...)
	if err != nil {
		return nil, false, err
	}
	srv.TLSConfig = tlsConfig
	return &TLSServer{Server: srv, serverName: serverName}, wasNew, nil
}

func (s *TLSServer) Start() error {
	name := s.serverName
	if name == "" {
		name = "HTTPS"
	}
	log.Printf("%s listening on %s", name, s.Server.Addr)
	err := s.Server.ListenAndServeTLS("", "")
	if err != nil && err != http.ErrServerClosed {
		log.Printf("%s listen error: %v", name, err)
	}
	return err
}

func (s *TLSServer) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.Server.Shutdown(ctx)
}
