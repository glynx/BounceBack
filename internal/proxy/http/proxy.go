package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
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
	client    *http.Client
	transport *http.Transport

	// Reverse proxies are used for Upgrade (WebSocket) requests.
	rpCache  sync.Map // key: string(targetURL), val: *httputil.ReverseProxy
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

	// Shared transport for both manual HTTP client and ReverseProxy.
	// Tuned for long-lived connections and streaming.
	p.transport = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: baseProxy.Config.Timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true, // harmless for WS (handled via H1), good for normal requests
		TLSHandshakeTimeout: 10 * time.Second,
		// ResponseHeaderTimeout protects only the initial response headers (e.g., WS handshake).
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       120 * time.Second,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		DisableCompression:    true, // we remove Accept-Encoding to simplify streaming
		TLSClientConfig:       baseProxy.TLSConfig,
	}

	p.client = &http.Client{
		Transport: p.transport,
		// Do not set a global timeout here; it would kill long-lived streams/WS.
		Timeout: 0,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
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

	// Build reverse proxies for target and (optional) action endpoints.
	_ = p.buildReverseProxy(p.TargetURL)
	if p.ActionURL != nil {
		_ = p.buildReverseProxy(p.ActionURL)
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
	p.client.CloseIdleConnections()
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
		// Preserve original client metadata before rewriting
		origHost := req.Host
		origProto := "http"
		if req.TLS != nil {
			origProto = "https"
		}

		// Rewrite to target
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		// Backend virtual host should be the target host
		req.Host = target.Host

		// Set forwarding headers with ORIGINAL values
		setForwardHeadersOn(req, req.Context(), origHost, origProto, getClientIPFromCtx(req.Context()))

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

// getReverseProxy returns the ReverseProxy for the destination (either cached or created)
func (p *Proxy) getReverseProxy(dst *url.URL) *httputil.ReverseProxy {
	if dst == nil || dst.String() == "" {
		return nil
	}

	key := dst.String()
	if v, ok := p.rpCache.Load(key); ok {
		return v.(*httputil.ReverseProxy)
	}
	// build
	rp := p.buildReverseProxy(dst)
	// Double-checked store 
	if v, loaded := p.rpCache.LoadOrStore(key, rp); loaded {
		return v.(*httputil.ReverseProxy)
	}
	return rp
}

// proxyRequest forwards a non-upgrade HTTP request using the manual client path.
// It keeps original client metadata for X-Forwarded-* headers and ensures
// the incoming body does not block the connection on errors.
func (p *Proxy) proxyRequest(
	dst *url.URL,
	w http.ResponseWriter,
	r *http.Request,
	e wrapper.Entity,
	logger zerolog.Logger,
) {
	// Preserve original client values
	origHost := r.Host
	origProto := "http"
	if r.TLS != nil {
		origProto = "https"
	}

	// IMPORTANT for your WrapHTTPBody: Close() on Body resets the reader to start.
	// Reset to beginning so filters that read the body do not consume it for upstream.
	if r.Body != nil {
		_ = r.Body.Close()
	}

	// Build outbound URL
	outURL := *r.URL
	outURL.Scheme = dst.Scheme
	outURL.Host = dst.Host
	outURL.Path = singleJoiningSlash(dst.Path, r.URL.Path)

	// Build outbound request with the (reset) body
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		logger.Error().Err(err).Msg("build outbound request failed")
		handleError(w)
		return
	}

	// Copy headers
	outReq.Header = make(http.Header, len(r.Header))
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	// Simplify streaming
	outReq.Header.Del("Accept-Encoding")

	// Backend virtual host should be the target host
	outReq.Host = dst.Host

	// Set forwarding headers with ORIGINAL values
	setForwardHeadersOn(outReq, r.Context(), origHost, origProto, e.GetIP().String())

	// Perform request
	resp, err := p.client.Do(outReq)
	if err != nil {
		logger.Error().Err(err).Msg("proxy upstream error")
		handleError(w)
		// Drain/close the original request body to keep the client connection healthy
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream response body
	if _, err := io.Copy(w, resp.Body); err != nil && !isProbableClientClose(err) {
		logger.Error().Err(err).Msg("copy response body failed")
	}
}

func (p *Proxy) processVerdict(
	w http.ResponseWriter,
	r *http.Request,
	e wrapper.Entity,
	logger zerolog.Logger,
) {
	actionRP := p.getReverseProxy(p.ActionURL)
	switch p.Config.RuleSettings.RejectAction {
	case common.RejectActionProxy:
		if isWebSocketRequest(r) && actionRP != nil {
			// Inject client IP into context for forwarding headers in Director
			r = r.WithContext(context.WithValue(r.Context(), ctxKeyClientIP, e.GetIP().String()))
			actionRP.ServeHTTP(w, r)
		} else {
			p.proxyRequest(p.ActionURL, w, r, e, logger)
		}
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
		if isWebSocketRequest(r) {
			targetRP := p.getReverseProxy(p.TargetURL)
			r = r.WithContext(context.WithValue(r.Context(), ctxKeyClientIP, e.GetIP().String()))
			targetRP.ServeHTTP(w, r)
		} else {
			p.proxyRequest(p.TargetURL, w, r, e, logger)
		}
	}
}

func (p *Proxy) createEntity(r *http.Request) (wrapper.Entity, error) {
	var err error
	r.Body, err = wrapper.WrapHTTPBody(r.Body)
	if err != nil {
		return nil, fmt.Errorf("can't wrap body: %w", err)
	}

	// IMPORTANT:
	// Do NOT write "Host" into the header map. The request host is r.Host.
	// Setting r.Header["Host"] leads to inconsistent behavior and parsing issues.

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
		isAllowed, target := p.RunFilters(e, logger)
		if !isAllowed {
			p.processVerdict(w, r, e, logger)
			return
		}

		var targetUrl *url.URL
		if strings.TrimSpace(target) != "" {
			u, err := url.Parse(target)
			if err != nil || u.Scheme == "" || u.Host == "" {
				logger.Warn().Str("target", target).Msg("invalid accept target; falling back to default")
				targetUrl = p.TargetURL
			} else {
				targetUrl = u
			}
		} else {
			targetUrl = p.TargetURL
		}

		// WebSocket/Upgrade → ReverseProxy (handles hijack/upgrade correctly)
		if isWebSocketRequest(r) {
			targetRP := p.getReverseProxy(targetUrl)
			r = r.WithContext(context.WithValue(r.Context(), ctxKeyClientIP, e.GetIP().String()))
			targetRP.ServeHTTP(w, r)
			return
		}

		// Normal HTTP → manual path
		p.proxyRequest(targetUrl, w, r, e, logger)
	}
}

func (p *Proxy) serve() {
	defer p.WG.Done()

	// Use Listen/Serve manually to respect TLS config and keep long-lived connections stable.
	if p.TLSConfig != nil {
		p.server.TLSConfig = p.TLSConfig
		if err := p.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			p.Logger.Fatal().Err(err).Msg("unexpected server error")
		}
		return
	}

	if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		p.Logger.Fatal().Err(err).Msg("unexpected server error")
	}
}

// ----- Helpers -----

func isWebSocketRequest(r *http.Request) bool {
	// Must have "Connection: Upgrade" and "Upgrade: websocket" (case-insensitive, comma handling)
	conn := r.Header.Get("Connection")
	upg := r.Header.Get("Upgrade")
	if upg == "" || !strings.EqualFold(strings.TrimSpace(upg), "websocket") {
		return false
	}
	// "Connection" can be a comma-separated list; check for token "upgrade"
	for _, t := range strings.Split(conn, ",") {
		if strings.EqualFold(strings.TrimSpace(t), "upgrade") {
			return true
		}
	}
	return false
}

// setForwardHeadersOn sets X-Forwarded-* headers using ORIGINAL client-facing values.
func setForwardHeadersOn(r *http.Request, ctx context.Context, origHost, origProto, clientIP string) {
	// X-Forwarded-For
	if clientIP != "" {
		if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
			r.Header.Set("X-Forwarded-For", prior+","+clientIP)
		} else {
			r.Header.Set("X-Forwarded-For", clientIP)
		}
	}
	// X-Forwarded-Proto: original client→proxy scheme
	if r.Header.Get("X-Forwarded-Proto") == "" {
		r.Header.Set("X-Forwarded-Proto", origProto)
	}
	// X-Forwarded-Host: original Host header seen by proxy
	if r.Header.Get("X-Forwarded-Host") == "" && origHost != "" {
		r.Header.Set("X-Forwarded-Host", origHost)
	}
}

func getClientIPFromCtx(ctx context.Context) string {
	if ip, _ := ctx.Value(ctxKeyClientIP).(string); ip != "" {
		return ip
	}
	return ""
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
