// Package proxy orchestrates the SOCKS5 server, DNS resolution, routing,
// and tunnel runtimes.
package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"aSuspect/l3tun"
	"aSuspect/l4fast"
	"aSuspect/shared"
	"aSuspect/spa"

	"github.com/things-go/go-socks5"
)

// Proxy is the top-level application.
type Proxy struct {
	config    *shared.Config
	resolver  *resolver
	router    *router
	l3Runtime *l3tun.Runtime
}

// New creates a new Proxy.
func New(cfg *shared.Config, state *shared.SharedState) (*Proxy, error) {
	// Compute SPA extension if anti-MITM is required.
	var spaExt []byte
	if state.AntiMITM != nil && state.AntiMITM.NeedsSPA() {
		seed := spa.ParseSeed(state.AntiMITM.EncryptedChallenge)
		totp, err := spa.GenerateTOTP(seed)
		if err != nil {
			log.Printf("SPA: TOTP generation failed: %s", err)
		} else {
			spaExt = spa.BuildClientHelloExtension(seed, totp, nil)
			log.Printf("SPA: ClientHello extension ready (%d bytes)", len(spaExt))
		}
	}

	l3r, err := l3tun.NewRuntime(state, spaExt)
	if err != nil {
		return nil, err
	}

	// Create L4 tunnel.
	l4t := &l4fast.Tunnel{
		SID:          state.SID,
		DeviceID:     state.DeviceID,
		ConnectionID: state.ConnectionID,
		Username:     state.Username,
		SignKey:      state.SignKey,
		SpaExt:       spaExt,
	}

	// Create resolver (2-layer DNS: static → aTrust DNS → error).
	resolver := newResolver(state, l3r.Stack(), cfg.DNSTTL)

	// Create router.
	tcpMode := cfg.TCPMode
	if tcpMode == "" {
		tcpMode = "l4"
	}
	router := newRouter(state, l4t, l3r.Stack(), tcpMode)

	return &Proxy{
		config:    cfg,
		resolver:  resolver,
		router:    router,
		l3Runtime: l3r,
	}, nil
}

// Serve starts the SOCKS5 server and blocks until shutdown.
func (p *Proxy) Serve() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── SOCKS5 server ───────────────────────────────────────────────
	var authMethods []socks5.Authenticator
	if p.config.SocksUser != "" {
		authMethods = append(authMethods,
			socks5.UserPassAuthenticator{
				Credentials: socks5.StaticCredentials{
					p.config.SocksUser: p.config.SocksPasswd,
				},
			})
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	server := socks5.NewServer(
		socks5.WithAuthMethods(authMethods),
		socks5.WithResolver(&socks5ResolverAdapter{r: p.resolver}),
		socks5.WithDial(p.router.dial),
		socks5.WithLogger(socks5.NewLogger(
			log.New(os.Stdout, "[SOCKS5] ", log.LstdFlags),
		)),
	)

	listener, err := net.Listen("tcp", p.config.SocksBind)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen: %w", err)
	}

	log.Printf("SOCKS5 server listening on %s", p.config.SocksBind)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.l3Runtime.Run(ctx)
	}()

	var shutdownOnce sync.Once
	shutdown := func() {
		cancel()
		listener.Close()
		p.l3Runtime.Close()
	}
	defer func() {
		shutdownOnce.Do(shutdown)
		wg.Wait()
	}()

	// Graceful shutdown.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sig)
	go func() {
		select {
		case <-sig:
			log.Println("Shutting down...")
			shutdownOnce.Do(shutdown)
		case <-ctx.Done():
		}
	}()

	if err := server.Serve(listener); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("SOCKS5 serve: %w", err)
	}
	return nil
}

// ── SOCKS5 resolver adapter ─────────────────────────────────────────────

type socks5ResolverAdapter struct {
	r *resolver
}

func (a *socks5ResolverAdapter) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ip, err := a.r.resolve(name)
	if err != nil {
		return ctx, nil, err
	}

	// Preserve the original domain after SOCKS replaces it with the resolved IP.
	ctx = context.WithValue(ctx, ctxKeyResolveHost, name)
	return ctx, ip, nil
}

type contextKey string

const ctxKeyResolveHost contextKey = "RESOLVE_HOST"
