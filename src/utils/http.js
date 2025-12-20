const HTTP_METHODS = [
  'GET',
  'POST',
  'PUT',
  'DELETE',
  'HEAD',
  'OPTIONS',
  'PATCH',
  'CONNECT',
  'TRACE',
];

function isHttpRequest(requestData) {
  return HTTP_METHODS.some(method => requestData.startsWith(method));
}

function cleanIPAddress(ip) {
  if (!ip) return '';
  if (ip.startsWith('::ffff:')) return ip.slice(7);
  return ip;
}

function appendClientIPToHeaders(requestData, clientIP, clientSocket) {
  const lines = requestData.split('\r\n');

  // Extract Host header from original request
  let hostHeader = '';
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (line === '') break;

    const colonIndex = line.indexOf(':');
    if (colonIndex > 0 && line.substring(0, colonIndex).toLowerCase() === 'host') {
      hostHeader = line.substring(colonIndex + 1).trim();
      break;
    }
  }

  const port = (clientSocket && clientSocket.localPort) || 443;

  const proxyHeaders = [
    `X-Forwarded-For: ${clientIP}`,
    'X-Forwarded-Proto: https',
    `X-Forwarded-Port: ${port}`,
  ];

  if (hostHeader) proxyHeaders.push(`X-Forwarded-Host: ${hostHeader}`);

  lines.splice(1, 0, ...proxyHeaders);
  return lines.join('\r\n');
}

module.exports = {
  HTTP_METHODS,
  isHttpRequest,
  cleanIPAddress,
  appendClientIPToHeaders,
};
