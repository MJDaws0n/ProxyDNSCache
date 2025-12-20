const { appendClientIPToHeaders, cleanIPAddress, isHttpRequest } = require('../src/utils/http');

describe('http utils', () => {
  test('isHttpRequest detects common methods', () => {
    expect(isHttpRequest('GET / HTTP/1.1\r\n\r\n')).toBe(true);
    expect(isHttpRequest('POST /submit HTTP/1.1\r\n\r\n')).toBe(true);
    expect(isHttpRequest('NOTHTTPDATA')).toBe(false);
  });

  test('cleanIPAddress strips IPv4-mapped IPv6', () => {
    expect(cleanIPAddress('::ffff:127.0.0.1')).toBe('127.0.0.1');
    expect(cleanIPAddress('1.2.3.4')).toBe('1.2.3.4');
  });

  test('appendClientIPToHeaders injects forwarded headers after request line', () => {
    const req = [
      'GET / HTTP/1.1',
      'Host: example.com',
      'User-Agent: test',
      '',
      '',
    ].join('\r\n');

    const fakeSocket = { localPort: 443 };
    const updated = appendClientIPToHeaders(req, '203.0.113.10', fakeSocket);

    expect(updated).toContain('X-Forwarded-For: 203.0.113.10');
    expect(updated).toContain('X-Forwarded-Proto: https');
    expect(updated).toContain('X-Forwarded-Port: 443');
    expect(updated).toContain('X-Forwarded-Host: example.com');

    const lines = updated.split('\r\n');
    expect(lines[0]).toBe('GET / HTTP/1.1');
    expect(lines[1].startsWith('X-Forwarded-For:')).toBe(true);
  });
});
