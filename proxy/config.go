package proxy

import (
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
	blockedIp           sync.Map
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
	}

	if cfg.user == "" || cfg.password == "" {
		return nil, fmt.Errorf("PROXY_USER и PROXY_PASSWORD обязательны")
	}

	if cfg.httpsPort > 0 && (cfg.tlsCertFile == "" || cfg.tlsKeyFile == "") {
		return nil, fmt.Errorf("PROXY_HTTPS_PORT задан, но PROXY_TLS_CERT_FILE/PROXY_TLS_KEY_FILE отсутствуют")
	}

	//todo load blocked ip from file

	return cfg, nil
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

func (c *Config) AddBlockIp(ip string) {
	c.blockedIp.LoadOrStore(ip, true)
	//todo save to file
}
