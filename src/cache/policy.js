const ONE_MINUTE_MS = 60 * 1000;
const FIFTEEN_MINUTES_MS = 15 * 60 * 1000;
const ONE_HOUR_MS = 60 * 60 * 1000;
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

function computeCacheAction({ nowMs, lastAccessedMs, lastRefreshMs }) {
  const safeLastAccessed = typeof lastAccessedMs === 'number' ? lastAccessedMs : 0;
  const safeLastRefresh = typeof lastRefreshMs === 'number' ? lastRefreshMs : 0;

  const inactivityMs = nowMs - safeLastAccessed;

  if (inactivityMs > ONE_DAY_MS) {
    return { action: 'delete' };
  }

  const refreshIntervalMs = inactivityMs <= ONE_HOUR_MS ? ONE_MINUTE_MS : FIFTEEN_MINUTES_MS;
  const shouldRefresh = nowMs - safeLastRefresh >= refreshIntervalMs;

  return {
    action: shouldRefresh ? 'refresh' : 'noop',
    refreshIntervalMs,
  };
}

module.exports = {
  ONE_MINUTE_MS,
  FIFTEEN_MINUTES_MS,
  ONE_HOUR_MS,
  ONE_DAY_MS,
  computeCacheAction,
};
