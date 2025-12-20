const { domainMatches } = require('../src/utils/domainMatch');

describe('domainMatches', () => {
  test('exact match', () => {
    expect(domainMatches('example.com', 'example.com')).toBe(true);
    expect(domainMatches('example.com', 'www.example.com')).toBe(false);
  });

  test('leading wildcard *.example.com', () => {
    expect(domainMatches('*.example.com', 'a.example.com')).toBe(true);
    expect(domainMatches('*.example.com', 'example.com')).toBe(false);
    expect(domainMatches('*.example.com', 'a.b.example.com')).toBe(true);
  });

  test('middle wildcard api.*.example.com', () => {
    expect(domainMatches('api.*.example.com', 'api.v1.example.com')).toBe(true);
    expect(domainMatches('api.*.example.com', 'api.example.com')).toBe(false);
    expect(domainMatches('api.*.example.com', 'x.v1.example.com')).toBe(false);
  });

  test('empty inputs', () => {
    expect(domainMatches('', 'example.com')).toBe(false);
    expect(domainMatches('*.example.com', '')).toBe(false);
  });
});
