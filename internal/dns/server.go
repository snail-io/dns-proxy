package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	miekgdns "github.com/miekg/dns"
)

type Server struct {
	addr    string
	handler *Handler
	udp     *miekgdns.Server
	tcp     *miekgdns.Server
	tls     *miekgdns.Server
}

func NewServer(addr string, h *Handler) *Server {
	return &Server{addr: addr, handler: h}
}

func (s *Server) Start() error {
	uh := func(w miekgdns.ResponseWriter, r *miekgdns.Msg) { s.handler.Handle(w, r) }
	th := func(w miekgdns.ResponseWriter, r *miekgdns.Msg) { s.handler.Handle(w, r) }

	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", s.addr)
	if err != nil {
		return err
	}
	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		_ = udpConn.Close()
		return err
	}

	s.udp = &miekgdns.Server{Handler: miekgdns.HandlerFunc(uh), PacketConn: udpConn}
	s.tcp = &miekgdns.Server{Handler: miekgdns.HandlerFunc(th), Listener: tcpListener}

	go func() {
		if err := s.udp.ActivateAndServe(); err != nil {
			log.Printf("dns udp server stopped: %v", err)
		}
	}()

	go func() {
		if err := s.tcp.ActivateAndServe(); err != nil {
			log.Printf("dns tcp server stopped: %v", err)
		}
	}()

	log.Printf("DNS server listening on %s (udp+tcp)", s.addr)
	return nil
}

func waitListen(addr string) error {
	_, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return fmt.Errorf("resolve dns addr: %w", err)
	}
	time.Sleep(200 * time.Millisecond)
	return nil
}

func (s *Server) StartTLS(addr string, certFile, keyFile string) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			_ = tcpListener.Close()
			return err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	tlsListener := tls.NewListener(tcpListener, tlsConfig)

	th := func(w miekgdns.ResponseWriter, r *miekgdns.Msg) { s.handler.Handle(w, r) }
	s.tls = &miekgdns.Server{Handler: miekgdns.HandlerFunc(th), Listener: tlsListener}

	go func() {
		if err := s.tls.ActivateAndServe(); err != nil {
			log.Printf("dns tls server stopped: %v", err)
		}
	}()

	log.Printf("DNS over TLS (DoT) listening on %s", addr)
	return nil
}

func (s *Server) Shutdown() error {
	_ = context.Background()
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
	if s.tls != nil {
		_ = s.tls.Shutdown()
	}
	return nil
}
