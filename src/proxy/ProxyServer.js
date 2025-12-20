const dns = require('dns');
const tls = require('tls');
const net = require('net');

const { computeCacheAction } = require('../cache/policy');
const { isHttpRequest, cleanIPAddress, appendClientIPToHeaders } = require('../utils/http');
const { CertificateManager } = require('./CertificateManager');

class ProxyServer {
  constructor({ configManager, cacheStore }) {
    this.configManager = configManager;
    this.cacheStore = cacheStore;

    this.certificateManager = new CertificateManager(this.configManager.get());

    this.tlsServers = [];
    this._intervalHandle = null;

    this._onConfigChanged = config => {
      this.applyRuntimeConfig(config);
    };
  }

  applyRuntimeConfig(config) {
    const dnsServers = Array.isArray(config.dnsServers) ? config.dnsServers : ['1.1.1.1'];
    try {
      dns.setServers(dnsServers);
    } catch {
      // ignore invalid DNS server config
    }

    this.certificateManager.updateConfig(config);
  }

  start() {
    const config = this.configManager.get();
    this.applyRuntimeConfig(config);

    this.configManager.on('changed', this._onConfigChanged);

    const tlsPorts = Array.isArray(config.tlsPorts) && config.tlsPorts.length > 0 ? config.tlsPorts : [443, 441];

    for (const port of tlsPorts) {
      const server = this.createTlsServer();
      server.listen(port, () => {
        console.log(`TLS server listening on port ${port}`);
      });
      this.tlsServers.push(server);
    }

    // Cache policy tick: every minute
    this._intervalHandle = setInterval(() => this.cachePolicyTick(), 60 * 1000);
  }

  stop() {
    if (this._intervalHandle) clearInterval(this._intervalHandle);
    this._intervalHandle = null;

    this.configManager.off('changed', this._onConfigChanged);

    for (const s of this.tlsServers) {
      try {
        s.close();
      } catch {
        // ignore
      }
    }
    this.tlsServers = [];
  }

  createTlsServer() {
    const server = tls.createServer(
      {
        minVersion: 'TLSv1.2',
        SNICallback: (hostname, cb) => {
          try {
            const ctx = this.certificateManager.getSecureContextForHostname(hostname);
            if (!ctx) return cb(new Error(`No certificate found for hostname: ${hostname}`));
            cb(null, ctx);
          } catch (err) {
            cb(err);
          }
        },
      },
      socket => this.handleConnection(socket)
    );

    server.on('error', err => {
      console.error('TLS server error:', err);
    });

    return server;
  }

  async resolveSrv(domain) {
    const srvRecord = `_pdcache._tcp.${domain}`;
    try {
      const addresses = await dns.promises.resolveSrv(srvRecord);
      if (!addresses || addresses.length === 0) return null;
      const { name: target, port } = addresses[0];
      return { target, port };
    } catch (err) {
      console.error(`DNS lookup failed for ${srvRecord}:`, err.message || err);
      return null;
    }
  }

  async refreshCache(domain) {
    const resolved = await this.resolveSrv(domain);
    if (!resolved) return;

    this.cacheStore.set(domain, resolved);
    this.cacheStore.markRefresh(domain);
    console.log(`Cache refreshed for ${domain}: ${resolved.target}:${resolved.port}`);
  }

  async cachePolicyTick() {
    const nowMs = Date.now();

    for (const domain of this.cacheStore.domains()) {
      const entry = this.cacheStore.get(domain);
      if (!entry) continue;

      const decision = computeCacheAction({
        nowMs,
        lastAccessedMs: entry.lastAccessedMs,
        lastRefreshMs: entry.lastRefreshMs,
      });

      if (decision.action === 'delete') {
        console.log(`Removing cached entry for ${domain} due to >24h inactivity.`);
        this.cacheStore.delete(domain);
        continue;
      }

      if (decision.action === 'refresh') {
        await this.refreshCache(domain);
      }
    }
  }

  async handleConnection(socket) {
    socket.setTimeout(2 * 60 * 1000);
    socket.on('timeout', () => socket.destroy());

    const domain = socket.servername;
    if (!domain) {
      socket.end();
      return;
    }

    // Mark access immediately on connect
    const existing = this.cacheStore.get(domain);
    if (existing) this.cacheStore.markAccess(domain);

    if (existing) {
      this.setupProxy(socket, existing);
      return;
    }

    const resolved = await this.resolveSrv(domain);
    if (!resolved) {
      socket.end();
      return;
    }

    this.cacheStore.set(domain, resolved);
    this.cacheStore.markAccess(domain);

    this.setupProxy(socket, resolved);
  }

  setupProxy(clientSocket, { target, port }) {
    const targetSocket = net.createConnection({ host: target, port }, () => {
      // connected
    });

    targetSocket.setTimeout(2 * 60 * 1000);
    targetSocket.on('timeout', () => targetSocket.destroy());

    clientSocket.on('data', data => {
      const requestData = data.toString();

      // WebSocket upgrade: pass through unchanged
      if (requestData.includes('Upgrade: websocket')) {
        targetSocket.write(data);
        this.cacheStore.markAccess(clientSocket.servername);
        return;
      }

      if (isHttpRequest(requestData)) {
        const clientIP = cleanIPAddress(clientSocket.remoteAddress);
        const updatedData = appendClientIPToHeaders(requestData, clientIP, clientSocket);
        targetSocket.write(updatedData);
      } else {
        targetSocket.write(data);
      }

      this.cacheStore.markAccess(clientSocket.servername);
    });

    targetSocket.on('data', data => {
      clientSocket.write(data);
    });

    clientSocket.on('end', () => {
      targetSocket.end();
    });

    targetSocket.on('end', () => {
      clientSocket.end();
    });

    clientSocket.on('error', () => {
      targetSocket.end();
    });

    targetSocket.on('error', () => {
      clientSocket.end();
    });
  }
}

module.exports = {
  ProxyServer,
};
