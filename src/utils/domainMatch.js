function domainMatches(wildcard, domain) {
  if (!wildcard || !domain) return false;

  const wildcardParts = String(wildcard).split('.');
  const domainParts = String(domain).split('.');

  // Leading *: *.example.com
  if (wildcardParts[0] === '*') {
    // Require at least one additional label (do not match apex).
    if (domainParts.length < wildcardParts.length) return false;
    return (
      domainParts.slice(-wildcardParts.length + 1).join('.') ===
      wildcardParts.slice(1).join('.')
    );
  }

  const starIndex = wildcardParts.indexOf('*');
  if (starIndex !== -1) {
    // Require '*' to match at least one label.
    if (domainParts.length < wildcardParts.length) return false;
    const preStar = wildcardParts.slice(0, starIndex);
    const postStar = wildcardParts.slice(starIndex + 1);

    const prefixMatches =
      domainParts.slice(0, preStar.length).join('.') === preStar.join('.');
    const suffixMatches =
      domainParts.slice(-postStar.length).join('.') === postStar.join('.');

    return prefixMatches && suffixMatches;
  }

  return wildcard === domain;
}

module.exports = {
  domainMatches,
};
