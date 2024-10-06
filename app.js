const fs = require('fs');
const tls = require('tls');
const dns = require('dns');
const yaml = require('js-yaml');
const net = require('net');
const http = require('http');
dns.setServers(['8.8.8.8']);

class ProxyServer {
    constructor(configPath, cachePath) {
        this.configPath = configPath;
        this.cachePath = cachePath;

        // Initialize cache as an object
        this.cache = {};

        // Keep track of last access times
        this.lastAccessed = {};
        this.loadConfig();
        this.loadCache();
        this.setupServer();

        // Clear cache on server restart
        this.clearCache();

        // Set up intervals for re-caching and cache cleanup
        this.setupCacheIntervals();
    }

    loadConfig() {
        try {
            const configFile = fs.readFileSync(this.configPath, 'utf8');
            this.config = yaml.load(configFile);
        } catch (err) {
            console.error('Error loading configuration:', err);
            process.exit(1);
        }
    }

    loadCache() {
        try {
            const cacheFile = fs.readFileSync(this.cachePath, 'utf8');
            this.cache = JSON.parse(cacheFile);
            this.lastAccessed = Object.keys(this.cache).reduce((acc, domain) => {
                acc[domain] = Date.now(); // Set last accessed time for each entry
                return acc;
            }, {});
        } catch (err) {
            console.error('Error loading cache:', err);
            this.cache = {};
        }
    }

    clearCache() {
        this.cache = {};
        this.lastAccessed = {};
        fs.writeFileSync(this.cachePath, JSON.stringify(this.cache, null, 2));
        console.log('Cache cleared.');
    }

    setupCacheIntervals() {
        // Re-cache and load config every minute
        setInterval(() => {
            for (const domain in this.cache) {
                this.refreshCache(domain);
            }
            // Reload config
            this.loadConfig();
        }, 60 * 1000); 

        // Auto delete cache entries after 96 hours of inactivity
        setInterval(() => {
            const now = Date.now();
            for (const domain in this.lastAccessed) {
                if (now - this.lastAccessed[domain] > 96 * 60 * 60 * 1000) {
                    console.log(`Removing cached entry for ${domain} due to inactivity.`);
                    delete this.cache[domain];
                    delete this.lastAccessed[domain];
                }
            }
            fs.writeFileSync(this.cachePath, JSON.stringify(this.cache, null, 2));
        }, 60 * 1000);        
    }

    refreshCache(domain) {
        const srvRecord = `_pdcache._tcp.${domain}`;
        dns.resolveSrv(srvRecord, (err, addresses) => {
            if (err) {
                console.error(`DNS lookup failed for ${srvRecord}:`, err);
                return;
            }

            if (addresses.length === 0) {
                console.error(`No SRV records found for ${srvRecord}`);
                return;
            }

            const target = addresses[0].name;
            const port = addresses[0].port;
            console.log(`Refreshing cache for ${domain}: Proxying to ${target}:${port}`);

            // Update cache with new proxy information
            this.cache[domain] = { target, port };
            this.lastAccessed[domain] = Date.now(); // Update last accessed time
            fs.writeFileSync(this.cachePath, JSON.stringify(this.cache, null, 2));
        });
    }

    domainMatches(wildcard, domain) {
        // Split the wildcard and domain into parts
        const wildcardParts = wildcard.split('.');
        const domainParts = domain.split('.');
    
        // Handle edge cases for empty inputs
        if (!wildcard || !domain) return false;
    
        // Handle case when wildcard starts with '*'
        if (wildcardParts[0] === '*') {
            // Check if the domain matches the rest of the wildcard after '*'
            return domainParts.slice(-wildcardParts.length + 1).join('.') === wildcardParts.slice(1).join('.');
        }
    
        // Handle wildcard in the middle or exact domain matches
        const starIndex = wildcardParts.indexOf('*');
        if (starIndex !== -1) {
            // Split into pre-star and post-star parts for comparison
            const preStar = wildcardParts.slice(0, starIndex);
            const postStar = wildcardParts.slice(starIndex + 1);
    
            // Match prefix and suffix of the domain with wildcard
            const prefixMatches = domainParts.slice(0, preStar.length).join('.') === preStar.join('.');
            const suffixMatches = domainParts.slice(-postStar.length).join('.') === postStar.join('.');
    
            return prefixMatches && suffixMatches;
        }
    
        // Exact match for no wildcards
        return wildcard === domain;
    }

    getCertAndKey(certs, hostname) {
        // Iterate over the keys in the certs object
        for (const domains in certs) {
            for (const domain in certs[domains]) {
                if (this.domainMatches(domain, hostname)) {
                    return certs[domains][domain];
                }
            }
        }
        return null;
    }

    setupServer() {
        const server = tls.createServer({
            SNICallback: (hostname, cb) => {
                const cert = this.getCertAndKey(this.config['certs'], hostname);
                if (cert === null) {
                    return cb(new Error('No certificate found for hostname'));
                }
                const config = {
                    cert: fs.readFileSync(cert[0].cert),
                    key: fs.readFileSync(cert[0].key)
                };
                cb(null, tls.createSecureContext(config));
            }
        }, (socket) => { this.handleConnection(socket); });

        server.listen(443, () => {
            console.log('Server listening on port 443');
        });
    }

    handleConnection(socket) {
        // Get the requested domain from the SNI
        const domain = socket.servername;

        console.log(domain);

        // Check cache for existing proxy
        if (this.cache[domain]) {
            console.log(`Proxy found in cache for domain: ${domain}`);
            this.lastAccessed[domain] = Date.now(); // Update last accessed time
            this.setupProxy(socket, this.cache[domain]);
            return;
        }

        // Perform DNS SRV lookup
        const srvRecord = `_pdcache._tcp.${domain}`;
        dns.resolveSrv(srvRecord, (err, addresses) => {
            if (err) {
                console.error(`DNS lookup failed for ${srvRecord}:`, err);
                // Close the socket on error
                socket.end();
                return;
            }

            if (addresses.length === 0) {
                console.error(`No SRV records found for ${srvRecord}`);
                // Close the socket if no addresses are found
                socket.end();
                return;
            }

            const target = addresses[0].name;
            const port = addresses[0].port;
            console.log(`Proxying to ${target}:${port} for domain: ${domain}`);

            // Update cache with new proxy information
            this.cache[domain] = { target, port };
            this.lastAccessed[domain] = Date.now(); // Set last accessed time
            fs.writeFileSync(this.cachePath, JSON.stringify(this.cache, null, 2));

            // Set up proxy to the target server
            this.setupProxy(socket, { target, port });
        });
    }

    httpMethods = [
        'GET',
        'POST',
        'PUT',
        'DELETE',
        'HEAD',
        'OPTIONS',
        'PATCH',
        'CONNECT',
        'TRACE'
    ];
    
    // Check if the request is an HTTP request
    isHttpRequest = requestData => this.httpMethods.some(method => requestData.startsWith(method));

    cleanIPAddress(ip) {
        // Check if the IP address is in IPv4-mapped IPv6 format
        if (ip.startsWith('::ffff:')) {
            return ip.slice(7);
        }
        return ip;
    }

    appendClientIPToHeaders(requestData, clientIP) {
        // Split the request data into lines
        const lines = requestData.split('\r\n');
    
        lines.splice(1, 0, `X-Forwarded-For: ${clientIP}`);
    
        // Reconstruct the request data with the modified headers
        return lines.join('\r\n');
    }

    setupProxy(clientSocket, { target, port }) {
        const targetSocket = net.createConnection(port, target, () => {
            console.log(`Connected to target ${target}:${port}`);
        });
    
        clientSocket.on('data', (data) => {
            const requestData = data.toString();
            
            // Check for WebSocket upgrade request
            if (requestData.includes('Upgrade: websocket')) {
                console.log(`WebSocket Upgrade Request from ${clientSocket.remoteAddress}`);
                targetSocket.write(data);
                return;
            }
    
            // Check if it's an HTTP request
            if (this.isHttpRequest(requestData)) {
                const clientIP = this.cleanIPAddress(clientSocket.remoteAddress);
                const updatedData = this.appendClientIPToHeaders(requestData, clientIP);
                targetSocket.write(updatedData);
            } else {
                // Not an HTTP request, just forward the data
                targetSocket.write(data);
            }
    
            // Update last accessed time using the domain
            const domain = clientSocket.servername;
            this.lastAccessed[domain] = Date.now();
        });
    
        // Forward data from target to client
        targetSocket.on('data', (data) => {
            clientSocket.write(data);
        });
    
        // Handle client disconnect
        clientSocket.on('end', () => {
            console.log(`Client disconnected from ${clientSocket.remoteAddress}`);
            // Close the target connection
            targetSocket.end();
        });
    
        // Handle target disconnect
        targetSocket.on('end', () => {
            console.log(`Disconnected from target ${target}:${port}`);
            // Close the client connection
            clientSocket.end();
        });
    
        // Handle errors on both sockets
        clientSocket.on('error', (err) => {
            console.error(`Client error: ${err}`);
            // Close target connection on client error
            targetSocket.end();
        });
    
        targetSocket.on('error', (err) => {
            console.error(`Target error: ${err}`);
            // Close client connection on target error
            clientSocket.end();
        });
    }
    
}

// Start the server
const server = new ProxyServer('config.yml', 'cache.json');

const server80 = http.createServer((req, res) => {
    // Redirect to HTTPS
    res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
    res.end();
});

server80.listen(80, () => {
    console.log(`HTTP Server listening on port 80`);
});