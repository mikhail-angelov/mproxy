package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

// SOCKS5 constants
const (
	socksVersion5          = 5
	socksAuthNone          = 0
	socksAuthUserPass      = 2
	socksAuthNoAcceptable  = 0xFF
	socksCmdConnect        = 1
	socksAddrTypeIPv4      = 1
	socksAddrTypeDomain    = 3
	socksAddrTypeIPv6      = 4
	socksRepSuccess        = 0
	socksRepGeneralFailure = 1
	socksRepNotAllowed     = 2
	socksRepHostUnreach    = 4
	socksRepConnRefused    = 5
)

type socksServer struct {
	cfg *Config
}

func newSocksServer(cfg *Config) *socksServer {
	return &socksServer{cfg: cfg}
}

func (s *socksServer) Run() error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.socksPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}

	slog.Info("SOCKS5 listener started", "addr", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("socks5 accept", "error", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *socksServer) handleConn(conn net.Conn) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	if _, ok := s.cfg.blockedIp.Load(clientIP); ok {
		slog.Warn("socks5 blocked IP rejected", "ip", clientIP)
		return
	}

	// 1. Authentication negotiation
	if err := s.authenticate(conn, clientIP); err != nil {
		slog.Warn("socks5 auth failed", "ip", clientIP, "error", err)
		return
	}

	// 2. Read request
	host, port, cmd, err := s.readRequest(conn)
	if err != nil {
		slog.Warn("socks5 bad request", "ip", clientIP, "error", err)
		return
	}

	if cmd != socksCmdConnect {
		s.reply(conn, socksRepGeneralFailure, nil)
		slog.Warn("socks5 unsupported command", "ip", clientIP, "cmd", cmd)
		return
	}

	slog.Info("socks5 connect", "ip", clientIP, "host", host, "port", port)

	// Keep the client deadline through tunnel setup. Previously it was cleared
	// before dialing, so a stalled target connection or SOCKS reply could leave
	// the client waiting indefinitely without a useful proxy error.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 3. Connect to target
	targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	target, err := (&net.Dialer{Timeout: 10 * time.Second}).Dial("tcp", targetAddr)
	if err != nil {
		slog.Warn("socks5 dial failed", "target", targetAddr, "error", err)
		s.reply(conn, socksRepHostUnreach, nil)
		return
	}
	defer target.Close()

	// 4. Send success response with local binding address
	localAddr := target.LocalAddr().(*net.TCPAddr)
	if err := s.reply(conn, socksRepSuccess, localAddr); err != nil {
		slog.Warn("socks5 reply failed", "ip", clientIP, "target", targetAddr, "error", err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	// 5. Bidirectional copy
	errChan := make(chan error, 2)
	go func() { _, err := io.Copy(target, conn); errChan <- err }()
	go func() { _, err := io.Copy(conn, target); errChan <- err }()
	<-errChan
}

func (s *socksServer) authenticate(conn net.Conn, clientIP string) error {
	// Read auth methods
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read auth header: %w", err)
	}
	if buf[0] != socksVersion5 {
		return fmt.Errorf("unexpected version: %d", buf[0])
	}

	nauth := int(buf[1])
	if nauth > 8 {
		return fmt.Errorf("too many auth methods: %d", nauth)
	}

	methods := make([]byte, nauth)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	supportsUserPass := false
	for _, m := range methods {
		if m == socksAuthUserPass {
			supportsUserPass = true
			break
		}
	}

	if !supportsUserPass {
		conn.Write([]byte{socksVersion5, socksAuthNoAcceptable})
		return fmt.Errorf("no supported auth method")
	}

	// Select username/password auth
	conn.Write([]byte{socksVersion5, socksAuthUserPass})

	// Read username/password sub-negotiation
	subBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, subBuf); err != nil {
		return fmt.Errorf("read auth sub header: %w", err)
	}
	if subBuf[0] != 1 {
		return fmt.Errorf("unexpected auth sub version: %d", subBuf[0])
	}

	ulen := int(subBuf[1])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return fmt.Errorf("read username: %w", err)
	}

	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}
	plen := int(plenBuf[0])
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	if string(uname) != s.cfg.user || string(passwd) != s.cfg.password {
		conn.Write([]byte{1, 1}) // auth failure
		s.notifyFailedAuth(clientIP)
		return fmt.Errorf("invalid credentials")
	}

	conn.Write([]byte{1, 0}) // auth success
	return nil
}

func (s *socksServer) readRequest(conn net.Conn) (host string, port int, cmd byte, err error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", 0, 0, fmt.Errorf("read request header: %w", err)
	}
	if buf[0] != socksVersion5 {
		return "", 0, 0, fmt.Errorf("unexpected request version: %d", buf[0])
	}

	cmd = buf[1]
	// buf[2] is RSV, ignored

	atyp := buf[3]
	switch atyp {
	case socksAddrTypeIPv4:
		buf = make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, 0, fmt.Errorf("read IPv4: %w", err)
		}
		host = net.IP(buf).String()
	case socksAddrTypeDomain:
		buf = make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, 0, fmt.Errorf("read domain length: %w", err)
		}
		domainLen := int(buf[0])
		buf = make([]byte, domainLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, 0, fmt.Errorf("read domain: %w", err)
		}
		host = string(buf)
	case socksAddrTypeIPv6:
		buf = make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, 0, fmt.Errorf("read IPv6: %w", err)
		}
		host = net.IP(buf).String()
	default:
		return "", 0, 0, fmt.Errorf("unsupported address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, 0, fmt.Errorf("read port: %w", err)
	}
	port = int(binary.BigEndian.Uint16(portBuf))

	return host, port, cmd, nil
}

func (s *socksServer) reply(conn net.Conn, rep byte, bindAddr *net.TCPAddr) error {
	// Response format: ver(5), rep, rsv(0), atyp, bnd.addr, bnd.port
	resp := []byte{socksVersion5, rep, 0}

	if rep != socksRepSuccess {
		resp = append(resp, socksAddrTypeIPv4, 0, 0, 0, 0, 0, 0)
		_, err := conn.Write(resp)
		return err
	}

	if bindAddr == nil {
		// Should not happen for success, but handle gracefully
		resp = append(resp, socksAddrTypeIPv4, 0, 0, 0, 0, 0, 0)
	} else if ip4 := bindAddr.IP.To4(); ip4 != nil {
		resp = append(resp, socksAddrTypeIPv4)
		resp = append(resp, ip4...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(bindAddr.Port))
		resp = append(resp, portBytes...)
	} else {
		ip6 := bindAddr.IP.To16()
		resp = append(resp, socksAddrTypeIPv6)
		resp = append(resp, ip6...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(bindAddr.Port))
		resp = append(resp, portBytes...)
	}

	_, err := conn.Write(resp)
	return err
}

func (s *socksServer) notifyFailedAuth(ip string) {
	// Use the same IP blocking as the HTTP proxy
	if s.cfg.invalidAuthAttempts <= 0 {
		return
	}
	// For simplicity, we block immediately on SOCKS auth failure
	// since the HTTP proxy already has its own counter-based mechanism
	s.cfg.AddBlockIp(ip)
}
