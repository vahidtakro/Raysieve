// Naming: build display names from measured exit-IP geo (flag, country, city).
// The feed author's original tag is discarded — we name from where traffic really exits.
export function flagOf(cc) {
  if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return '';
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 127397 + c.charCodeAt(0)));
}

export function shortCountryName(name) {
  const known = {
    'United States': 'US',
    'United Kingdom': 'UK',
    'United Arab Emirates': 'UAE',
    'Korea, Republic of': 'KR',
    'Russian Federation': 'RU',
    'Netherlands': 'NL',
    'Germany': 'DE',
  };
  return known[name] || name || '';
}

// Compose the display name: "🇩🇪 DE · Frankfurt · ISP" (parts omitted when unknown).
export function buildDisplayName(node, geo) {
  const parts = [];
  const cc = geo?.countryCode || '';
  const flag = flagOf(cc);
  if (flag) parts.push(flag);
  if (cc) parts.push(shortCountryName(geo?.country) || cc);
  if (geo?.city) parts.push(geo.city);
  if (geo?.isp && parts.length < 3) parts.push(String(geo.isp).slice(0, 24));
  if (parts.length === 0) return node.name || node.host;
  return parts.join(' · ');
}

// Ensure unique names: append " #2", " #3", ... on later collisions.
export function uniquifyNames(entries) {
  const seen = new Map();
  for (const e of entries) {
    const base = e.name;
    const n = (seen.get(base) || 0) + 1;
    seen.set(base, n);
    if (n > 1) e.name = `${base} #${n}`;
  }
  return entries;
}
