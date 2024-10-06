# ProxyDNSCache

# NOTICE
PLEASE MAKE SURE YOU HAVE YOU `config.yml` AND `cache.json` IN THE SAME FOLDER AS YOUR EXECUTABLE OR IT WILL NOT WORK.

## Overview
ProxyDNSCache is a lightweight TCP proxy designed to handle redirection of HTTP (port 80) and HTTPS (port 443) traffic. It forwards HTTP traffic to HTTPS and routes HTTPS traffic to the appropriate domain. For example, it can forward traffic from `https://example.com/` to `localhost:304`.

This solution also ensures that the original client IP for HTTP connections is forwarded via the `X-Forwarded-For` header. You'll need to configure your web server (e.g., NGINX) to respect this header if required.

## Features
- Redirects all HTTP traffic from port 80 to HTTPS (port 443).
- Supports routing of HTTPS connections to specific domains or subdomains.
- Adds `X-Forwarded-For` headers to HTTP requests for logging original client IPs.
- Customizable configuration with support for multiple certificates and domains.

## Requirements
- A valid SRV record for DNS setup.
- A valid SSL certificate for each domain you wish to proxy.

## Installation and Setup

### Step 1: Configure DNS
Create an SRV record for your domain. For example:

```
_pdcache._tcp.example.com
````

Replace `example.com` with your domain or subdomain. Set the priority and weight to `10`, and specify the port and target. The target can be `localhost`, but do **not** use an IP address.

### Step 2: Configure `config.yml`
Edit the `config.yml` file to specify the SSL certificates for your domains. An example configuration looks like:

```yaml
certs:
  - "example.com":
      - cert: "/path/to/certs/fullchain.pem"
        key: "/path/to/certs/privkey.pem"
  - "*.example.com":
      - cert: "/path/to/certs/fullchain.pem"
        key: "/path/to/certs/privkey.pem"
```
For each domain you want to proxy, replace example.com with your actual domain and provide the paths to the SSL certificate and key.

### Step 3: Install and Run the Service
#### Linux / macOS
Download the appropriate executable:

- For Linux: ProxyDNSCache-linux
- For macOS: ProxyDNSCache-macos

To run the service automatically, create a systemd service:

```bash
sudo nano /etc/systemd/system/ProxyDNSCache.service
```
Then, paste the following configuration:

```ini
[Unit]
Description=ProxyDNSCache Service
After=network.target

[Service]
ExecStart=/path/to/your/ProxyDNSCache-linux
WorkingDirectory=/path/to/your/
Restart=always
User=your-username
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```
Edit the paths and username as necessary. Afterward, enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl start ProxyDNSCache
sudo systemctl enable ProxyDNSCache
```
#### Windows
For Windows, use the Node.js version as the executable may not work properly. Run the following commands to install and run the project:
```bash
nvm install 16
nvm use 16
npm install -g pkg
pkg .
```
You can then run the proxy directly using Node.js or build your own executable.
```bash
.\ProxyDNSCache-win.exe
```
## Building from Source
To build ProxyDNSCache from the source, follow these steps:

1.  Install Node.js version 16 using NVM:
    ```bash
    nvm install 16
    nvm use 16
    ```

2.  Install dependencies:
    ```bash
    npm install
    ```

3. Use pkg to build the executable:
    ```bash
    npm install -g pkg
    pkg .
    ```

## Additional Notes
- ProxyDNSCache ensures that HTTP client IPs are forwarded through the X-Forwarded-For header. Forwarding IP's for non-http TCP connections are not currently supported.
- You can manage certificates for different domains in the config.yml file.
- If you are having issues with Windows, running the project directly via Node.js is recommended.

## Troubleshooting
Ensure that:

- SRV records are correctly set up for your domain.
- The SSL certificates are valid and properly configured.
- You're using Node.js v16 to build or run the project.
