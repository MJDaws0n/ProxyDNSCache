const fs = require('fs');
const EventEmitter = require('events');
const yaml = require('js-yaml');

const { atomicWriteFileSync } = require('../utils/atomicWrite');

const DEFAULT_CONFIG_YAML = `# ProxyDNSCache configuration\n#\n# Keep the same structure as previous versions so upgrades don't break.\n# Add cert/key pairs for each hostname pattern you want to serve.\n\ncerts: []\n`;

class ConfigManager extends EventEmitter {
  constructor({ configPath, watchIntervalMs = 1000 }) {
    super();
    this.configPath = configPath;
    this.watchIntervalMs = watchIntervalMs;

    this.config = null;
    this._lastMtimeMs = 0;
  }

  ensureExists() {
    if (!fs.existsSync(this.configPath)) {
      atomicWriteFileSync(this.configPath, DEFAULT_CONFIG_YAML);
    }
  }

  loadFromDisk() {
    this.ensureExists();

    try {
      const raw = fs.readFileSync(this.configPath, 'utf8');
      const loaded = yaml.load(raw) || {};
      this.config = loaded;
      this.emit('loaded', loaded);
    } catch (err) {
      this.emit('error', err);
    }
  }

  get() {
    return this.config || {};
  }

  watch() {
    this.ensureExists();

    fs.watchFile(
      this.configPath,
      { interval: this.watchIntervalMs },
      (curr, prev) => {
        if (!curr || curr.mtimeMs === prev.mtimeMs) return;
        if (curr.mtimeMs <= this._lastMtimeMs) return;
        this._lastMtimeMs = curr.mtimeMs;
        this.loadFromDisk();
        this.emit('changed', this.get());
      }
    );
  }

  stopWatching() {
    fs.unwatchFile(this.configPath);
  }
}

module.exports = {
  ConfigManager,
};
