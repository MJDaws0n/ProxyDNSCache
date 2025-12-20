const {
  computeCacheAction,
  ONE_MINUTE_MS,
  FIFTEEN_MINUTES_MS,
  ONE_HOUR_MS,
  ONE_DAY_MS,
} = require('../src/cache/policy');

describe('cache policy', () => {
  test('delete after >24h inactivity', () => {
    const now = 1_000_000;
    const res = computeCacheAction({
      nowMs: now,
      lastAccessedMs: now - ONE_DAY_MS - 1,
      lastRefreshMs: now,
    });
    expect(res.action).toBe('delete');
  });

  test('refresh every minute when accessed within last hour', () => {
    const now = 1_000_000;
    const res = computeCacheAction({
      nowMs: now,
      lastAccessedMs: now - ONE_HOUR_MS + 1000,
      lastRefreshMs: now - ONE_MINUTE_MS,
    });
    expect(res.action).toBe('refresh');
    expect(res.refreshIntervalMs).toBe(ONE_MINUTE_MS);
  });

  test('refresh every 15 minutes when inactive >1h but <=24h', () => {
    const now = 1_000_000;
    const res1 = computeCacheAction({
      nowMs: now,
      lastAccessedMs: now - ONE_HOUR_MS - 1,
      lastRefreshMs: now - FIFTEEN_MINUTES_MS + 1,
    });
    expect(res1.action).toBe('noop');
    expect(res1.refreshIntervalMs).toBe(FIFTEEN_MINUTES_MS);

    const res2 = computeCacheAction({
      nowMs: now,
      lastAccessedMs: now - ONE_HOUR_MS - 1,
      lastRefreshMs: now - FIFTEEN_MINUTES_MS,
    });
    expect(res2.action).toBe('refresh');
  });
});
