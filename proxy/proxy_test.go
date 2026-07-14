package proxy

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func testConfig() *Config {
	return &Config{
		port:                0,
		user:                "test",
		password:            "test",
		invalidAuthAttempts: 2,
		blockedIpFile:       "",
		socksPort:           0,
	}
}

func authHeader(user string, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestCheckAuth_Table(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantOK     bool
	}{
		{"valid credentials", authHeader("test", "test"), true},
		{"no header at all", "", false},
		{"wrong scheme (Bearer)", "Bearer sometoken", false},
		{"invalid base64 payload", "Basic !!!not-base64!!!", false},
		{"missing colon in payload", "Basic " + base64.StdEncoding.EncodeToString([]byte("nouser")), false},
		{"wrong password", authHeader("test", "wrongpass"), false},
		{"wrong username", authHeader("nottest", "test"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProxy(testConfig())

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.RemoteAddr = "203.0.113.1:12345"
			if tt.authHeader != "" {
				req.Header.Set("Proxy-Authorization", tt.authHeader)
			}

			result := p.checkAuth(req)
			assert.Equal(t, tt.wantOK, result)
		})
	}
}

func TestSocks5AuthAndConnect(t *testing.T) {
	cfg := &Config{
		port:                0,
		user:                "testuser",
		password:            "testpass",
		invalidAuthAttempts: 10,
		blockedIpFile:       "",
		socksPort:           0,
	}
	s := newSocksServer(cfg)

	// Start a local TCP echo server as the "target"
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	// Start a local SOCKS5 listener
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksLn.Close()

	go func() {
		conn, err := socksLn.Accept()
		if err != nil {
			return
		}
		s.handleConn(conn)
	}()

	// Connect to SOCKS5 server
	conn, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Auth negotiation: version 5, 2 methods (none, userpass)
	_, err = conn.Write([]byte{5, 2, 0, 2})
	if err != nil {
		t.Fatal(err)
	}

	// Read auth method selection
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 5 || resp[1] != 2 {
		t.Fatalf("expected userpass auth, got %v", resp)
	}

	// Send username/password sub-negotiation
	// subver(1) ulen(1) uname ulen plen(1) passwd plen
	authMsg := []byte{1, 8}
	authMsg = append(authMsg, []byte("testuser")...)
	authMsg = append(authMsg, 8)
	authMsg = append(authMsg, []byte("testpass")...)
	if _, err := conn.Write(authMsg); err != nil {
		t.Fatal(err)
	}

	// Read auth response
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatal(err)
	}
	if authResp[0] != 1 || authResp[1] != 0 {
		t.Fatalf("auth failed: %v", authResp)
	}

	// Send CONNECT request to echo server
	echoAddr := echoLn.Addr().String()
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort := 0
	fmt.Sscanf(echoPortStr, "%d", &echoPort)
	ip := net.ParseIP(echoHost).To4()

	connectReq := []byte{5, 1, 0, 1}
	connectReq = append(connectReq, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(echoPort))
	connectReq = append(connectReq, portBytes...)

	if _, err := conn.Write(connectReq); err != nil {
		t.Fatal(err)
	}

	// Read SOCKS5 response
	// ver(1) rep(1) rsv(1) atyp(1) bnd.addr(4/16) bnd.port(2)
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		t.Fatal(err)
	}
	if respHeader[0] != 5 || respHeader[1] != 0 {
		t.Fatalf("connect failed: ver=%d rep=%d", respHeader[0], respHeader[1])
	}

	// Read the bind address (skip it)
	atyp := respHeader[3]
	switch atyp {
	case 1:
		buf := make([]byte, 6)
		io.ReadFull(conn, buf)
	case 4:
		buf := make([]byte, 18)
		io.ReadFull(conn, buf)
	}

	// Send data through the tunnel
	msg := "socks5-echo-test\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}

func TestSocks5AuthFailure(t *testing.T) {
	cfg := &Config{
		port:                0,
		user:                "testuser",
		password:            "testpass",
		invalidAuthAttempts: 10,
		blockedIpFile:       "",
		socksPort:           0,
	}
	s := newSocksServer(cfg)

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksLn.Close()

	go func() {
		conn, err := socksLn.Accept()
		if err != nil {
			return
		}
		s.handleConn(conn)
	}()

	conn, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Auth negotiation: version 5, 2 methods (none, userpass)
	_, err = conn.Write([]byte{5, 2, 0, 2})
	if err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 2)
	io.ReadFull(conn, resp)

	// Send wrong password
	authMsg := []byte{1, 8}
	authMsg = append(authMsg, []byte("testuser")...)
	authMsg = append(authMsg, 9)
	authMsg = append(authMsg, []byte("wrongpass")...)
	conn.Write(authMsg)

	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)
	assert.Equal(t, byte(1), authResp[1]) // rep=1 means auth failure
}

func TestBlockedIpPersistence(t *testing.T) {
	f, err := os.CreateTemp("", "blocked_ips_*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile := f.Name()
	f.Close()
	defer os.Remove(tmpFile)

	// Write pre-existing blocked IPs
	if err := os.WriteFile(tmpFile, []byte(`["10.0.0.1","10.0.0.2"]`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		port:                0,
		user:                "test",
		password:            "test",
		invalidAuthAttempts: 2,
		blockedIpFile:       tmpFile,
	}

	if err := cfg.loadBlockedIps(); err != nil {
		t.Fatal(err)
	}

	// Verify pre-loaded IPs are blocked
	_, loaded := cfg.blockedIp.Load("10.0.0.1")
	assert.True(t, loaded)
	_, loaded = cfg.blockedIp.Load("10.0.0.2")
	assert.True(t, loaded)

	// Block a new IP and verify it persists
	cfg.AddBlockIp("10.0.0.3")
	_, loaded = cfg.blockedIp.Load("10.0.0.3")
	assert.True(t, loaded)

	// Re-read file to ensure it was saved
	cfg2 := &Config{
		blockedIpFile: tmpFile,
	}
	if err := cfg2.loadBlockedIps(); err != nil {
		t.Fatal(err)
	}
	_, loaded = cfg2.blockedIp.Load("10.0.0.1")
	assert.True(t, loaded)
	_, loaded = cfg2.blockedIp.Load("10.0.0.2")
	assert.True(t, loaded)
	_, loaded = cfg2.blockedIp.Load("10.0.0.3")
	assert.True(t, loaded)
}

func TestCheckAuth_BlockAfterThreshold(t *testing.T) {
	cfg := testConfig()
	p := NewProxy(cfg)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	result := p.checkAuth(req)
	assert.False(t, result)

	req.RemoteAddr = "203.0.113.1:12346"
	result = p.checkAuth(req)
	assert.False(t, result)

	req.RemoteAddr = "203.0.113.1:12347"
	req.Header.Set("Proxy-Authorization", authHeader("test", "test"))
	result = p.checkAuth(req)
	assert.False(t, result) //valid auth is failed anyway

	actual, _ := cfg.blockedIp.LoadOrStore("203.0.113.1", new(bool))
	exist := actual.(bool)
	assert.True(t, exist)
}

// ---------- handleHTTPForwarding: интеграционный тест с фейковым upstream ----------

func TestHandleProxy_HTTPForwarding(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("Proxy-Authorization не должен долетать до upstream-сервера")
		}
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hello from upstream"))
	}))
	defer upstream.Close()

	p := NewProxy(testConfig())

	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/foo", nil)
	req.RemoteAddr = "203.0.113.20:4444"
	req.Header.Set("Proxy-Authorization", authHeader("test", "test"))

	rr := httptest.NewRecorder()
	p.handleProxy(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusTeapot)
	}
	if rr.Header().Get("X-Upstream") != "yes" {
		t.Fatal("заголовок от upstream не долетел до клиента")
	}
	if body := rr.Body.String(); body != "hello from upstream" {
		t.Fatalf("body = %q", body)
	}
}

func TestHandleProxy_UnauthorizedReturns407(t *testing.T) {
	p := NewProxy(testConfig())
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.30:1111"

	rr := httptest.NewRecorder()
	p.handleProxy(rr, req)

	if rr.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusProxyAuthRequired)
	}
	if rr.Header().Get("Proxy-Authenticate") == "" {
		t.Error("ожидался заголовок Proxy-Authenticate в ответе")
	}
}

// ---------- handleConnectTunnel: end-to-end тест через настоящий TCP ----------

func TestHandleProxy_ConnectTunnel(t *testing.T) {
	// "сайт назначения": простой TCP echo-сервер
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn) // эхо всего, что получили
	}()

	p := NewProxy(testConfig())
	proxyServer := httptest.NewServer(p.handler())
	defer proxyServer.Close()

	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		echoLn.Addr().String(), echoLn.Addr().String(), authHeader("test", "test"),
	)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(conn)

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("unexpected status line: %q", statusLine)
	}

	// вычитываем заголовки туннеля до пустой строки
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	msg := "ping-through-tunnel\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}

func TestHandleProxy_ConnectTunnel_Unauthorized(t *testing.T) {
	p := NewProxy(testConfig())
	proxyServer := httptest.NewServer(p.handler())
	defer proxyServer.Close()

	proxyAddr := strings.TrimPrefix(proxyServer.URL, "http://")
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// без Proxy-Authorization
	req := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusLine, "407") {
		t.Fatalf("unexpected status line: %q, want 407", statusLine)
	}
}
