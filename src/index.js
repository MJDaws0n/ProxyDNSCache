const path = require('path');
const http = require('http');

const { ConfigManager } = require('./config/ConfigManager');
const { CacheStore } = require('./cache/CacheStore');
const { ProxyServer } = require('./proxy/ProxyServer');

function start() {
  const configPath = process.env.CONFIG_PATH
    ? path.resolve(process.env.CONFIG_PATH)
    : path.resolve(process.cwd(), 'config.yml');

  const cachePath = process.env.CACHE_PATH
    ? path.resolve(process.env.CACHE_PATH)
    : path.resolve(process.cwd(), 'cache.json');

  const configManager = new ConfigManager({ configPath });
  configManager.loadFromDisk();
  configManager.watch();

  const cacheStore = new CacheStore({ cachePath });
  cacheStore.loadFromDisk();
  cacheStore.watch();

  cacheStore.on('error', err => console.error('Cache error:', err));
  configManager.on('error', err => console.error('Config error:', err));

  const proxyServer = new ProxyServer({ configManager, cacheStore });
  proxyServer.start();

  const httpPort = Number(configManager.get().httpPort || process.env.HTTP_PORT || 80);
  const httpServer = http.createServer((req, res) => {
    const host = req.headers.host;
    res.writeHead(301, { Location: `https://${host}${req.url}` });
    res.end();
  });

  httpServer.listen(httpPort, () => {
    console.log(`HTTP redirect server listening on port ${httpPort}`);
  });

  const shutdown = () => {
    console.log('Shutting down...');
    try {
      httpServer.close();
    } catch {
      // ignore
    }

    try {
      proxyServer.stop();
    } catch {
      // ignore
    }

    try {
      cacheStore.stopWatching();
      configManager.stopWatching();
    } catch {
      // ignore
    }

    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

start();
