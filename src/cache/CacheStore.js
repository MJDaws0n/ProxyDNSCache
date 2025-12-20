const fs = require('fs');
const EventEmitter = require('events');

const { atomicWriteFileSync } = require('../utils/atomicWrite');

class CacheStore extends EventEmitter {
  constructor({ cachePath, watchIntervalMs = 1000 }) {
    super();
    this.cachePath = cachePath;
    this.watchIntervalMs = watchIntervalMs;

    this.entries = new Map();
    this._lastMtimeMs = 0;
  }

  ensureExists() {
    if (!fs.existsSync(this.cachePath)) {
      atomicWriteFileSync(this.cachePath, JSON.stringify({}, null, 2));
    }
  }

  loadFromDisk() {
    this.ensureExists();

    let parsed;
    try {
      const raw = fs.readFileSync(this.cachePath, 'utf8');
      parsed = raw.trim() ? JSON.parse(raw) : {};
    } catch (err) {
      // If corrupted, do not crash; keep in-memory, but emit error.
      this.emit('error', err);
      return;
    }

    // Backward compatible: old format is { domain: { target, port } }
    const next = new Map();
    for (const [domain, value] of Object.entries(parsed || {})) {
      if (!value || typeof value !== 'object') continue;

      const target = value.target;
      const port = value.port;
      if (!target || !port) continue;

      const lastAccessedMs =
        typeof value.lastAccessedMs === 'number' ? value.lastAccessedMs : Date.now();
      const lastRefreshMs =
        typeof value.lastRefreshMs === 'number' ? value.lastRefreshMs : 0;

      next.set(domain, {
        target,
        port,
        lastAccessedMs,
        lastRefreshMs,
      });
    }

    // Merge: keep newest lastAccessed/lastRefresh to avoid losing runtime updates
    for (const [domain, existing] of this.entries.entries()) {
      if (!next.has(domain)) continue;
      const incoming = next.get(domain);
      next.set(domain, {
        ...incoming,
        lastAccessedMs: Math.max(incoming.lastAccessedMs || 0, existing.lastAccessedMs || 0),
        lastRefreshMs: Math.max(incoming.lastRefreshMs || 0, existing.lastRefreshMs || 0),
      });
    }

    this.entries = next;
    this.emit('loaded');
  }

  saveToDisk() {
    const obj = {};
    for (const [domain, entry] of this.entries.entries()) {
      obj[domain] = {
        target: entry.target,
        port: entry.port,
        lastAccessedMs: entry.lastAccessedMs || 0,
        lastRefreshMs: entry.lastRefreshMs || 0,
      };
    }
    atomicWriteFileSync(this.cachePath, JSON.stringify(obj, null, 2));
  }

  watch() {
    this.ensureExists();

    fs.watchFile(
      this.cachePath,
      { interval: this.watchIntervalMs },
      (curr, prev) => {
        if (!curr || curr.mtimeMs === prev.mtimeMs) return;
        if (curr.mtimeMs <= this._lastMtimeMs) return;
        this._lastMtimeMs = curr.mtimeMs;
        this.loadFromDisk();
        this.emit('changed');
      }
    );
  }

  stopWatching() {
    fs.unwatchFile(this.cachePath);
  }

  has(domain) {
    return this.entries.has(domain);
  }

  get(domain) {
    return this.entries.get(domain) || null;
  }

  set(domain, { target, port }) {
    const existing = this.entries.get(domain);
    const now = Date.now();

    this.entries.set(domain, {
      target,
      port,
      lastAccessedMs: existing?.lastAccessedMs || now,
      lastRefreshMs: now,
    });
    this.saveToDisk();
  }

  markAccess(domain) {
    const entry = this.entries.get(domain);
    if (!entry) return;
    entry.lastAccessedMs = Date.now();
    this.entries.set(domain, entry);
  }

  markRefresh(domain) {
    const entry = this.entries.get(domain);
    if (!entry) return;
    entry.lastRefreshMs = Date.now();
    this.entries.set(domain, entry);
  }

  delete(domain) {
    if (!this.entries.has(domain)) return;
    this.entries.delete(domain);
    this.saveToDisk();
  }

  domains() {
    return Array.from(this.entries.keys());
  }
}

module.exports = {
  CacheStore,
};
