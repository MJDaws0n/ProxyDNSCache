const fs = require('fs');
const tls = require('tls');

const { domainMatches } = require('../utils/domainMatch');

function normalizeCertConfig(certs) {
  // Supported:
  // - array: [ { "example.com": [ {cert,key} ] }, { "*.example.com": [ ... ] } ]
  // - object: { "example.com": [ {cert,key} ], "*.example.com": [ ... ] }
  if (!certs) return [];

  if (Array.isArray(certs)) {
    const out = [];
    for (const item of certs) {
      if (!item || typeof item !== 'object') continue;
      for (const [pattern, pairs] of Object.entries(item)) {
        out.push({ pattern, pairs: Array.isArray(pairs) ? pairs : [] });
      }
    }
    return out;
  }

  if (typeof certs === 'object') {
    return Object.entries(certs).map(([pattern, pairs]) => ({
      pattern,
      pairs: Array.isArray(pairs) ? pairs : [],
    }));
  }

  return [];
}

class CertificateManager {
  constructor(config) {
    this.updateConfig(config);
  }

  updateConfig(config) {
    this._config = config || {};
    this._certs = normalizeCertConfig(this._config.certs);
    this._contextCache = new Map();
  }

  getSecureContextForHostname(hostname) {
    for (const entry of this._certs) {
      if (!domainMatches(entry.pattern, hostname)) continue;

      const pair = entry.pairs && entry.pairs[0];
      if (!pair || !pair.cert || !pair.key) return null;

      const cacheKey = `${pair.cert}|${pair.key}`;
      if (this._contextCache.has(cacheKey)) return this._contextCache.get(cacheKey);

      const ctx = tls.createSecureContext({
        cert: fs.readFileSync(pair.cert),
        key: fs.readFileSync(pair.key),
      });

      this._contextCache.set(cacheKey, ctx);
      return ctx;
    }

    return null;
  }
}

module.exports = {
  CertificateManager,
};
