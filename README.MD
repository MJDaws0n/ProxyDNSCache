# ProxyDNSCache

ProxyDNSCache is a small, production-friendly TLS SNI proxy that routes inbound HTTPS connections to a backend discovered via DNS SRV records.

It terminates TLS (using your certificates via SNI), then forwards the raw TCP stream to the resolved target. For HTTP traffic, it also injects standard `X-Forwarded-*` headers so upstream apps (NGINX, PHP-FPM, etc.) can log the real client IP.

## Key behavior

### DNS routing
For an incoming SNI hostname `example.com`, ProxyDNSCache looks up:

`_pdcache._tcp.example.com`

The first SRV record returned is used as the proxy destination (`target:port`).

### Cache policy (updated)
Cache entries are refreshed and cleaned on a 1-minute tick:

- If the domain was accessed within the last **1 hour**, its SRV record is refreshed **every minute**.
- If the domain was accessed more than **1 hour** ago (but within **24 hours**), it is refreshed **every 15 minutes**.
- If the domain was not accessed for more than **24 hours**, it is **removed** from `cache.json`.

`cache.json` is backward-compatible: older entries without timestamps still work and will be upgraded as the service runs.

## Files

- `config.yml`: certificate configuration (required; auto-created if missing)
- `cache.json`: SRV lookup cache (auto-created if missing)

Both files are hot-reloaded when they change.

## Configuration (unchanged schema)

Example `config.yml`:

```yaml
certs:
    - "example.com":
            - cert: "/etc/letsencrypt/live/example.com/fullchain.pem"
                key: "/etc/letsencrypt/live/example.com/privkey.pem"
    - "*.example.com":
            - cert: "/etc/letsencrypt/live/example.com/fullchain.pem"
                key: "/etc/letsencrypt/live/example.com/privkey.pem"
```

Optional settings (new, but not required):

```yaml
# Which DNS resolvers to use (defaults to Cloudflare)
dnsServers:
    - "1.1.1.1"

# TLS ports to listen on (defaults to [443, 441])
tlsPorts:
    - 443
    - 441

# HTTP redirect port (defaults to 80)
httpPort: 80
```

## Run

Install:

```bash
npm install
```

Start:

```bash
npm start
```

Environment overrides (optional):

- `CONFIG_PATH`: path to `config.yml`
- `CACHE_PATH`: path to `cache.json`
- `HTTP_PORT`: redirect server port

## NGINX notes (real client IP)

If your upstream is behind NGINX and you want correct client IP logging:

```nginx
set_real_ip_from 127.0.0.1;
real_ip_header X-Forwarded-For;
```

For PHP backends, you may also want:

```nginx
fastcgi_param HTTPS on;
```

## Tests

Unit tests cover the pure logic (wildcard hostname matching, header injection, cache policy). Network integration tests are intentionally not included.

```bash
npm test
```

## Build (standalone binaries)

This project supports building standalone executables using `pkg`.

Install dependencies:

```bash
npm install
```

Build all configured targets:

```bash
npm run build
```

Build specific targets:

```bash
npm run build:mac
npm run build:linux
```

Artifacts are written to the `dist/` folder.

Expected outputs:

- `dist/proxydnscache-macos-x64`
- `dist/proxydnscache-macos-arm64`
- `dist/proxydnscache-linux-x64`
- `dist/proxydnscache-linux-arm64`

### Notes on building Linux binaries from macOS

`pkg` *can* build for multiple targets, but cross-building is not always reliable for every platform/architecture combination (especially Linux `arm64`) depending on which prebuilt Node runtimes `pkg` can fetch.

If `npm run build:linux` fails on macOS for `linux-arm64`, the most reliable option is to build on a Linux machine/runner.

Recommended approach:

- Use GitHub Actions (or any CI) with a Linux runner to build Linux artifacts.
- Optionally build Linux `arm64` on an ARM runner (or via QEMU), depending on your CI setup.
  5.  Generate a cloudflare API key that has read/write/delete access to the DNS records of the domain
  6.  Create a cloudflare.ini file in a safe place
  7.  File should look like
      ```env
      dns_cloudflare_api_token = KEY HERE
      ```
  8.  Set the files permissions
      ```bash
      sudo chmod 600 /path/to/cloudflare.ini
      ```
  9.  Generate certificate, remember to change the cloudflare path and the domain.com
      ```bash
      sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials /path/to/cloudflare.ini --preferred-challenges dns -d domain.com -d '*.domain.com'
      ```
  10.  Autorenewal will work as long as you are only using this app the manage certificates.

## Additional Notes
- ProxyDNSCache ensures that HTTP client IPs are forwarded through the X-Forwarded-For header. Forwarding IP's for non-http TCP connections are not currently supported.
- You can manage certificates for different domains in the config.yml file.
- If you are having issues with Windows, running the project directly via Node.js is recommended.

## Troubleshooting
Ensure that:

- SRV records are correctly set up for your domain.
- The SSL certificates are valid and properly configured.
- You're using Node.js v16 to build or run the project.
