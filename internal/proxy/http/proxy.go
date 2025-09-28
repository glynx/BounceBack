package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/D00Movenok/BounceBack/internal/common"
	"github.com/D00Movenok/BounceBack/internal/database"
	"github.com/D00Movenok/BounceBack/internal/proxy/base"
	"github.com/D00Movenok/BounceBack/internal/rules"
	"github.com/D00Movenok/BounceBack/internal/wrapper"

	"github.com/rs/zerolog"
)

const (
	ProxyType = "http"
)

var (
	AllowedActions = []string{
		common.RejectActionProxy,
		common.RejectActionRedirect,
		common.RejectActionDrop,
		common.RejectActionNone,
	}
)

// ctxKey is a private context key type to avoid collisions.
type ctxKey string

// ctxKeyClientIP stores the client IP in the request context for header injection.
const ctxKeyClientIP ctxKey = "clientIP"

type Proxy struct {
	*base.Proxy

	TargetURL *url.URL
	ActionURL *url.URL

	server    *http.Server
	transport *http.Transport

	targetRP *httputil.ReverseProxy
	actionRP *httputil.ReverseProxy
}

func NewProxy(
	cfg common.ProxyConfig,
	rs *rules.RuleSet,
	db *database.DB,
) (*Proxy, error) {
	baseProxy, err := base.NewBaseProxy(cfg, rs, db, AllowedActions)
	if err != nil {
		return nil, fmt.Errorf("can't create base proxy: %w", err)
	}

	target, err := url.Parse(cfg.TargetAddr)
	if err != nil {
		return nil, fmt.Errorf("can't parse target url: %w", err)
	}

	var action *url.URL
	if cfg.RuleSettings.RejectAction == common.RejectActionProxy ||
		cfg.RuleSettings.RejectAction == common.RejectActionRedirect {
		action, err = url.Parse(cfg.RuleSettings.RejectURL)
		if err != nil {
			return nil, fmt.Errorf("can't parse action url: %w", err)
		}
	}

	p := &Proxy{
		Proxy:     baseProxy,
		TargetURL: target,
		ActionURL: action,
	}

	// Shared transport for both target and action reverse proxies.
	// Tuned for long-lived WebSocket/streaming connections.
	p.transport = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: baseProxy.Config.Timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true, // harmless for WS (handled via H1), beneficial for normal requests
		TLSHandshakeTimeout: 10 * time.Second,
		// ResponseHeaderTimeout protects only the initial response headers (e.g., WS handshake).
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       120 * time.Second,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		DisableCompression:    true, // we remove Accept-Encoding to simplify streaming
		TLSClientConfig:       baseProxy.TLSConfig,
	}

	// Build reverse proxies for target and (optional) action endpoints.
	p.targetRP = p.buildReverseProxy(p.TargetURL)
	if p.ActionURL != nil {
		p.actionRP = p.buildReverseProxy(p.ActionURL)
	}

	// HTTP server tuned for long-lived upgraded connections:
	// - No ReadTimeout/WriteTimeout (would kill idle WS)
	// - Use ReadHeaderTimeout to cap header phase only
	p.server = &http.Server{
		Addr:              p.Config.ListenAddr,
		ReadHeaderTimeout: minDuration(baseProxy.Config.Timeout, 10*time.Second),
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       0, // irrelevant for upgraded connections; 0 = no timeout
		Handler:           p.getHandler(),
		TLSConfig:         p.TLSConfig,
	}

	// When action is "drop" we need Hijack on H1; Go's H2 server does not support Hijack.
	// Disable HTTP/2 in that case.
	// https://github.com/golang/go/issues/34874
	if cfg.RuleSettings.RejectAction == common.RejectActionDrop {
		p.Logger.Warn().Msg("HTTP/2 disabled with action \"drop\"")
		p.server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}

	return p, nil
}

func (p *Proxy) Start() error {
	p.WG.Add(1)
	go p.serve()
	return nil
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	p.Closing = true
	if err := p.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("can't shutdown server: %w", err)
	}
	// Close idle backend connections (includes WS backends if gracefully closed).
	p.transport.CloseIdleConnections()

	done := make(chan any, 1)
	go func() {
		p.WG.Wait()
		done <- nil
	}()

	select {
	case <-ctx.Done():
		return base.ErrShutdownTimeout
	case <-done:
	}
	return nil
}

// buildReverseProxy constructs an httputil.ReverseProxy with sane defaults
// for streaming and WebSocket connections.
func (p *Proxy) buildReverseProxy(target *url.URL) *httputil.ReverseProxy {
	logger := p.Logger

	director := func(req *http.Request) {
		// Rewrite to target
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		// Keep existing RawQuery; ReverseProxy merges query correctly
		req.Host = target.Host

		// Forwarding headers (XFF/XFH/XFP)
		setForwardHeaders(req, req.Context())

		// Remove Accept-Encoding to avoid decompression/recompression pitfalls for streaming.
		req.Header.Del("Accept-Encoding")
	}

	rp := &httputil.ReverseProxy{
		Director:       director,
		Transport:      p.transport,
		ModifyResponse: nil, // full pass-through
		// Small flush interval supports low-latency streaming & WS frames.
		FlushInterval: 50 * time.Millisecond,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// Common benign errors for long-lived connections (client resets, EOF)
			if isProbableClientClose(err) {
				logger.Debug().Err(err).Msg("client closed connection")
				return
			}
			logger.Error().Err(err).Msg("proxy error")
			handleError(w)
		},
	}

	return rp
}

func (p *Proxy) processVerdict(
	w http.ResponseWriter,
	r *http.Request,
	e wrapper.Entity,
	logger zerolog.Logger,
) {
	switch p.Config.RuleSettings.RejectAction {
	case common.RejectActionProxy:
		if p.actionRP == nil {
			logger.Error().Msg("RejectActionProxy configured but actionRP is nil")
			handleError(w)
			return
		}
		// Inject client IP into context for header forwarding in Director.
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyClientIP, e.GetIP().String()))
		p.actionRP.ServeHTTP(w, r)

	case common.RejectActionRedirect:
		http.Redirect(w, r, p.ActionURL.String(), http.StatusMovedPermanently)

	case common.RejectActionDrop:
		hj, ok := w.(http.Hijacker)
		if !ok {
			// Not supported on HTTP/2 servers.
			logger.Warn().Msg("Response writer does not support http.Hijacker")
			handleError(w)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			logger.Error().Err(err).Msg("can't hijack response")
			handleError(w)
			return
		}
		_ = conn.Close()

	default:
		logger.Warn().Msg("Request was filtered, but action is none")
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyClientIP, e.GetIP().String()))
		p.targetRP.ServeHTTP(w, r)
	}
}

func (p *Proxy) createEntity(r *http.Request) (wrapper.Entity, error) {
	var err error
	r.Body, err = wrapper.WrapHTTPBody(r.Body)
	if err != nil {
		return nil, fmt.Errorf("can't wrap body: %w", err)
	}
	r.Header.Set("Host", r.Host)

	e := &wrapper.HTTPRequest{Request: r}
	return e, nil
}

func (p *Proxy) getHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e, err := p.createEntity(r)
		if err != nil {
			p.Logger.Error().Err(err).Msg("can't create entity")
			handleError(w)
			return
		}

		logger := p.Logger.With().
			Stringer("from", e.GetIP()).
			Logger()

		logRequest(e, logger)

		// Apply filters/rules first.
		if !p.RunFilters(e, logger) {
			p.processVerdict(w, r, e, logger)
			return
		}

		// Normal proxy path (covers WebSockets and other upgrades automatically).
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyClientIP, e.GetIP().String()))
		p.targetRP.ServeHTTP(w, r)
	}
}

func (p *Proxy) serve() {
	defer p.WG.Done()

	// Use a listener with TCP keepalive to help long-lived connections survive NAT/LB idling.
	lc := net.ListenConfig{
		KeepAlive: 30 * time.Second,
	}

	ln, err := lc.Listen(context.Background(), "tcp", p.Config.ListenAddr)
	if err != nil {
		p.Logger.Fatal().Err(err).Msg("listen failed")
		return
	}

	// Wrap with TLS if configured.
	if p.TLSConfig != nil {
		ln = tls.NewListener(ln, p.TLSConfig)
	}

	// Serve (instead of ListenAndServe) to use our custom listener.
	if err := p.server.Serve(ln); err != nil && err != http.ErrServerClosed {
		p.Logger.Fatal().Err(err).Msg("unexpected server error")
	}
}

// ----- Helpers -----

// setForwardHeaders sets common reverse-proxy headers (X-Forwarded-For/Host/Proto).
func setForwardHeaders(r *http.Request, ctx context.Context) {
	// X-Forwarded-For
	if ip, _ := ctx.Value(ctxKeyClientIP).(string); ip != "" {
		if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
			r.Header.Set("X-Forwarded-For", prior+","+ip)
		} else {
			r.Header.Set("X-Forwarded-For", ip)
		}
	}
	// X-Forwarded-Proto
	if r.Header.Get("X-Forwarded-Proto") == "" {
		if r.TLS != nil {
			r.Header.Set("X-Forwarded-Proto", "https")
		} else {
			r.Header.Set("X-Forwarded-Proto", "http")
		}
	}
	// X-Forwarded-Host
	if r.Header.Get("X-Forwarded-Host") == "" {
		r.Header.Set("X-Forwarded-Host", r.Host)
	}
}

// singleJoiningSlash joins two URL paths with a single slash between them.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	default:
		return a + b
	}
}

// minDuration returns the smaller of two durations.
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// isProbableClientClose checks common error messages that indicate the client
// closed the connection (not a backend/proxy failure).
func isProbableClientClose(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "client disconnected") ||
		strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "eof")
}
