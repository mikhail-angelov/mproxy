# mproxy — HTTP CONNECT proxy with authentication

A lightweight HTTP CONNECT proxy that supports both plain HTTP and TLS tunnels, authentication,
rate limiting, and automatic IP blocking after repeated failed auth attempts.

## Quick start

### 1. Generate certificates (for HTTPS proxy)

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/privkey.pem -out certs/fullchain.pem \
  -days 365 -subj "/CN=localhost"
```

### 2. Configure

Create a `.env` file (see `.env.example`):

```env
PROXY_PORT=8080
PROXY_HTTPS_PORT=8443
PROXY_TLS_CERT_FILE=/certs/fullchain.pem
PROXY_TLS_KEY_FILE=/certs/privkey.pem
PROXY_USER=alice
PROXY_PASSWORD=secret123
PROXY_RATE_LIMIT=100
PROXY_INVALID_AUTH_ATTEMPTS=20
```

### 3. Run

```bash
docker compose up -d
```

Or with plain Go:

```bash
go run . &
```

## Environment variables

| Variable                       | Default | Description                                |
|--------------------------------|---------|--------------------------------------------|
| `PROXY_PORT`                   | `8080`  | Plain HTTP listen port                     |
| `PROXY_HTTPS_PORT`             | `0`     | HTTPS listen port (`0` = disabled)         |
| `PROXY_TLS_CERT_FILE`          | —       | Path to TLS certificate (required for HTTPS) |
| `PROXY_TLS_KEY_FILE`           | —       | Path to TLS key (required for HTTPS)        |
| `PROXY_USER`                   | —       | **Required.** Proxy username               |
| `PROXY_PASSWORD`               | —       | **Required.** Proxy password               |
| `PROXY_RATE_LIMIT`             | `100`   | Max requests/second per client             |
| `PROXY_INVALID_AUTH_ATTEMPTS`  | `20`    | Failed attempts before IP is blocked       |

## Client configuration

### curl

Plain HTTP proxy:

```bash
curl -x http://alice:secret123@localhost:8080 https://api.example.com
```

HTTPS proxy (with self-signed cert, skip verification):

```bash
curl -x https://alice:secret123@localhost:8443 \
     --proxy-cacert certs/fullchain.pem \
     https://api.example.com
```

Tunnel-only (CONNECT), no upstream request:

```bash
curl -x http://alice:secret123@localhost:8080 \
     -p \
     https://api.example.com
```

### Git

```bash
git config --global http.proxy http://alice:secret123@localhost:8080
git config --global https.proxy http://alice:secret123@localhost:8080

# Remove when done:
git config --global --unset http.proxy
git config --global --unset https.proxy
```

### npm / yarn

```bash
npm config set proxy http://alice:secret123@localhost:8080
npm config set https-proxy http://alice:secret123@localhost:8080

yarn config set proxy http://alice:secret123@localhost:8080
yarn config set https-proxy http://alice:secret123@localhost:8080
```

### Docker daemon

Create or edit `/etc/docker/daemon.json`:

```json
{
  "proxies": {
    "http-proxy": "http://alice:secret123@localhost:8080",
    "https-proxy": "http://alice:secret123@localhost:8080"
  }
}
```

Then restart Docker.

### macOS / Linux system proxy

```bash
export http_proxy=http://alice:secret123@localhost:8080
export https_proxy=http://alice:secret123@localhost:8080
export no_proxy=localhost,127.0.0.1
```

### Windows (PowerShell)

```powershell
$env:HTTP_PROXY="http://alice:secret123@localhost:8080"
$env:HTTPS_PROXY="http://alice:secret123@localhost:8080"
$env:NO_PROXY="localhost,127.0.0.1"
```

### Browser

**Firefox:** Settings → Network Settings → Manual proxy — enter `localhost:8080` for HTTP,
check "Also use this proxy for HTTPS".

**Chrome:** Use the `--proxy-server` flag:

```bash
google-chrome --proxy-server=http://alice:secret123@localhost:8080
```

Note: Chrome does not send `Proxy-Authorization` headers automatically with
`--proxy-server`. Use a PAC file or an extension like **SwitchyOmega** to supply
credentials.

### Go programs

```go
proxyURL, _ := url.Parse("http://alice:secret123@localhost:8080")
transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
client := &http.Client{Transport: transport}
resp, _ := client.Get("https://api.example.com")
```

### Python

```python
import requests

proxies = {
    "http": "http://alice:secret123@localhost:8080",
    "https": "http://alice:secret123@localhost:8080",
}
resp = requests.get("https://api.example.com", proxies=proxies)
```

### Any other application

Most software that supports HTTP proxies expects the standard `Proxy-Authorization: Basic`
header with base64-encoded `user:password`. The proxy listens on port `8080` (plain HTTP)
and optionally `8443` (HTTPS with client certificates).