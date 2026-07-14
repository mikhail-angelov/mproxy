package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
)

type Config struct {
	port                int
	httpsPort           int // 0 = HTTPS-disconnected
	tlsCertFile         string
	tlsKeyFile          string
	user                string
	password            string
	rateLimit           int
	invalidAuthAttempts int
	blockedIpFile       string
	blockedIp           sync.Map
	mu                  sync.Mutex
}

func NewConfig() (*Config, error) {
	cfg := &Config{
		port:                getEnvInt("PROXY_PORT", 8080),
		httpsPort:           getEnvInt("PROXY_HTTPS_PORT", 0),
		tlsCertFile:         os.Getenv("PROXY_TLS_CERT_FILE"),
		tlsKeyFile:          os.Getenv("PROXY_TLS_KEY_FILE"),
		user:                os.Getenv("PROXY_USER"),
		password:            os.Getenv("PROXY_PASSWORD"),
		rateLimit:           getEnvInt("PROXY_RATE_LIMIT", 100),
		invalidAuthAttempts: getEnvInt("PROXY_INVALID_AUTH_ATTEMPTS", 20),
		blockedIpFile:       getEnvStr("PROXY_BLOCKED_IP_FILE", "blocked_ips.json"),
	}

	if cfg.user == "" || cfg.password == "" {
		return nil, fmt.Errorf("PROXY_USER и PROXY_PASSWORD обязательны")
	}

	if cfg.httpsPort > 0 && (cfg.tlsCertFile == "" || cfg.tlsKeyFile == "") {
		return nil, fmt.Errorf("PROXY_HTTPS_PORT задан, но PROXY_TLS_CERT_FILE/PROXY_TLS_KEY_FILE отсутствуют")
	}

	if err := cfg.loadBlockedIps(); err != nil {
		return nil, fmt.Errorf("load blocked ips: %w", err)
	}

	return cfg, nil
}

func getEnvStr(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func getEnvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func (c *Config) loadBlockedIps() error {
	data, err := os.ReadFile(c.blockedIpFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // file doesn't exist yet — start empty
		}
		return fmt.Errorf("read %s: %w", c.blockedIpFile, err)
	}

	var ips []string
	if err := json.Unmarshal(data, &ips); err != nil {
		return fmt.Errorf("parse %s: %w", c.blockedIpFile, err)
	}

	for _, ip := range ips {
		c.blockedIp.Store(ip, true)
	}
	return nil
}

func (c *Config) saveBlockedIps() error {
	var ips []string
	c.blockedIp.Range(func(key, _ interface{}) bool {
		ips = append(ips, key.(string))
		return true
	})

	data, err := json.Marshal(ips)
	if err != nil {
		return fmt.Errorf("marshal blocked ips: %w", err)
	}

	if err := os.WriteFile(c.blockedIpFile, data, 0644); err != nil {
		return fmt.Errorf("write %s: %w", c.blockedIpFile, err)
	}
	return nil
}

func (c *Config) AddBlockIp(ip string) {
	c.blockedIp.LoadOrStore(ip, true)
	if c.blockedIpFile == "" {
		return // persistence disabled
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.saveBlockedIps(); err != nil {
		// Logging is not available here to avoid circular dependency,
		// but the error is non-fatal — the proxy continues to block the IP in memory.
	}
}
