package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Proxy struct {
	cfg       *Config
	notAuthIp sync.Map
	transport http.RoundTripper
	socks     *socksServer
}

var hopByHopHeaders = []string{
	"Proxy-Authorization", "Proxy-Connection", "Connection",
	"Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade",
}

func NewProxy(cfg *Config) *Proxy {
	p := &Proxy{
		cfg: cfg,
	}
	if cfg.socksPort > 0 {
		p.socks = newSocksServer(cfg)
	}
	return p
}

func (p *Proxy) handler() http.Handler {
	return http.HandlerFunc(p.handleProxy)
}

func (p *Proxy) Run(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", p.cfg.port),
		Handler:           p.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	tlsEnabled := p.cfg.httpsPort > 0 && p.cfg.tlsCertFile != "" && p.cfg.tlsKeyFile != ""

	var httpsServer *http.Server
	if tlsEnabled {
		httpsServer = &http.Server{
			Addr:              fmt.Sprintf("0.0.0.0:%d", p.cfg.httpsPort),
			Handler:           p.handler(),
			ReadHeaderTimeout: 10 * time.Second,
		}
	} else {
		slog.Warn("TLS disabled: set PROXY_HTTPS_PORT, PROXY_TLS_CERT_FILE and PROXY_TLS_KEY_FILE to enable it")
	}

	socksEnabled := p.socks != nil
	if socksEnabled {
		slog.Info("SOCKS5 enabled", "port", p.cfg.socksPort)
	} else {
		slog.Warn("SOCKS5 disabled: set PROXY_SOCKS_PORT to enable it")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu       sync.Mutex
		firstErr error
	)
	recordErr := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
		cancel()
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("HTTP listener started", "addr", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			recordErr(fmt.Errorf("http server: %w", err))
		}
	}()

	if tlsEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("HTTPS listener started", "addr", httpsServer.Addr)
			if err := httpsServer.ListenAndServeTLS(p.cfg.tlsCertFile, p.cfg.tlsKeyFile); err != nil && err != http.ErrServerClosed {
				recordErr(fmt.Errorf("https server: %w", err))
			}
		}()
	}

	if socksEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.socks.Run(); err != nil {
				recordErr(fmt.Errorf("socks5 server: %w", err))
			}
		}()
	}

	<-runCtx.Done()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		recordErr(fmt.Errorf("http shutdown: %w", err))
	}
	if tlsEnabled {
		if err := httpsServer.Shutdown(shutdownCtx); err != nil {
			recordErr(fmt.Errorf("https shutdown: %w", err))
		}
	}
	if socksEnabled {
		if err := p.socks.Shutdown(); err != nil {
			recordErr(fmt.Errorf("socks5 shutdown: %w", err))
		}
	}

	wg.Wait()

	return firstErr

}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (p *Proxy) checkAuth(r *http.Request) (result bool) {
	ip := clientIP(r)
	if _, ok := p.cfg.blockedIp.Load(ip); ok {
		return false
	}

	defer func() {
		if result {
			p.notAuthIp.Delete(ip)
			return
		}
		actual, _ := p.notAuthIp.LoadOrStore(ip, new(int32))
		counter := actual.(*int32)
		newCount := atomic.AddInt32(counter, 1)

		if newCount >= int32(p.cfg.invalidAuthAttempts) {
			p.cfg.AddBlockIp(ip)
			p.notAuthIp.Delete(ip)
		}
	}()

	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		return false
	}

	return pair[0] == p.cfg.user && pair[1] == p.cfg.password
}

func (p *Proxy) handleProxy(w http.ResponseWriter, r *http.Request) {
	slog.Info("Tunneling request", "to", r.Host, "method", r.Method, "auth", r.Header.Get("Proxy-Authorization") != "")

	if !p.checkAuth(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Tunnel"`)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnectTunnel(w, r)
	} else {
		p.handleHTTPForwarding(w, r)
	}
}

func (p *Proxy) handleConnectTunnel(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Webserver does not support hijacking", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(destConn, clientConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, destConn)
		errChan <- err
	}()

	<-errChan
}

func (p *Proxy) handleHTTPForwarding(w http.ResponseWriter, r *http.Request) {
	reqCopy := r.Clone(r.Context())

	reqCopy.RequestURI = ""
	for _, h := range hopByHopHeaders {
		reqCopy.Header.Del(h)
	}

	slog.Debug("forwarding request",
		"host", reqCopy.Host,
		"url", reqCopy.URL.String(),
		"has_proxy_auth", reqCopy.Header.Get("Proxy-Authorization") != "",
		"has_proxy_connection", reqCopy.Header.Get("Proxy-Connection") != "",
	)

	transport := http.DefaultTransport
	if p.transport != nil {
		transport = p.transport
	}
	resp, err := transport.RoundTrip(reqCopy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}