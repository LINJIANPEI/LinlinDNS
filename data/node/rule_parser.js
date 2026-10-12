/**
 * 共享规则解析模块。
 */

const DNS_SUPPORTED_MODIFIERS = new Set([
  "important",
  "badfilter",
  "match-case",
  "denyallow",
  "dnsrewrite",
  "dnstype",
  "client",
]);

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

const isIPv4 = (s) => {
  const m = IPV4_RE.exec(s);
  if (!m) return false;
  return m.slice(1).every((p) => {
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
};

const isBlackholeIp = (ip) =>
  ip === "0.0.0.0" || ip.startsWith("127.") || ip === "::1";

const stripWildcard = (domain) => {
  let d = domain;
  if (d.startsWith("*.")) d = d.slice(2);
  if (d.includes("*")) return null;
  return d;
};

const normalizeDomain = (value) => {
  const d = value.trim().toLowerCase().replace(/\.+$/, "").replace(/^\.+/, "");
  if (!d) return null;
  if (d === "localhost" || d === "localhost.localdomain") return null;
  if (d.includes(" ")) return null;
  if (!/^[a-z0-9.-]+$/.test(d)) return null;
  if (d.includes("..")) return null;
  if (isIPv4(d)) return null;

  const labels = d.split(".");
  if (labels.length < 2) return null;
  if (d.length > 253) return null;

  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return null;
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) return null;
  }

  return d;
};

const getModifiers = (line) => {
  const idx = line.indexOf("$");
  if (idx === -1) return [];
  return line
    .slice(idx + 1)
    .split(",")
    .map((m) => m.trim().split("=")[0].replace(/^~/, "").toLowerCase())
    .filter(Boolean);
};

const hasUnsupportedModifier = (line) =>
  getModifiers(line).some((m) => !DNS_SUPPORTED_MODIFIERS.has(m));

const hasImportant = (line) => /\$important\b/.test(line);
const hasDnsRewrite = (line) => /\$dnsrewrite\b/.test(line);

const EXTENDED_RULE_MARKERS = [
  "##",
  "#@#",
  "#$#",
  "#@$#",
  "#%#",
  "#@%#",
  "#?#",
  "#@?#",
];

const isPathRule = (t) => {
  if (/^\/(?!\/)/.test(t)) return true;

  const body = t.startsWith("@@") ? t.slice(2) : t;
  let rest = null;
  if (body.startsWith("||")) rest = body.slice(2);
  else if (body.startsWith("|")) rest = body.slice(1);
  else return false;

  rest = rest.replace(/^\^/, "");
  const beforeMod = rest.split("$")[0];
  const core = beforeMod.split("^")[0];
  return core.includes("/");
};

/**
 * 统一规则解析。
 *
 * 返回 { domain, isWhite, ip, coverSub?, original?, important?, isHosts? }
 */
const parseRule = (line, opts = {}) => {
  if (typeof line !== "string") return null;
  const t = line.trim();
  if (!t) return null;
  if (t.startsWith("!")) return null;
  if (t.startsWith("#")) {
    if (!opts.allowExtended) return null;
    if (!EXTENDED_RULE_MARKERS.some((m) => t.startsWith(m))) return null;
  }

  if (hasUnsupportedModifier(t)) return null;

  const isWhitePrefix = t.startsWith("@@");
  const body = isWhitePrefix ? t.slice(2) : t;

  const wrap = (result, extra) => {
    if (opts.keepCoverSub) result.coverSub = extra.coverSub;
    if (opts.keepOriginal) {
      result.original = t;
      result.important = hasImportant(t);
    }
    if (opts.keepIsHosts) result.isHosts = extra.isHosts;
    return result;
  };

  // ① hosts 格式
  const parts = t.split(/\s+/);
  if (parts.length === 2 && isIPv4(parts[0])) {
    const cand = stripWildcard(parts[1]);
    if (cand === null) return null;
    const domain = normalizeDomain(cand);
    if (!domain) return null;

    const blackhole = isBlackholeIp(parts[0]);
    return wrap(
      {
        domain,
        isWhite: !blackhole,
        ip: blackhole ? null : parts[0],
      },
      { coverSub: false, isHosts: true },
    );
  }

  // ② ||domain^ / |domain^
  if (body.startsWith("||") || body.startsWith("|")) {
    const isDouble = body.startsWith("||");
    let rest = body.slice(isDouble ? 2 : 1).replace(/^\^/, "");
    rest = stripWildcard(rest);
    if (rest === null) return null;

    const beforeMod = rest.split("$")[0];
    const core = beforeMod.split("^")[0];
    if (core.includes("/")) return null;

    const domain = normalizeDomain(core);
    if (!domain) return null;

    const dnsrewriteMatch = rest.match(/\$dnsrewrite=([^,;$]+)/i);
    return wrap(
      {
        domain,
        isWhite: isWhitePrefix,
        ip: dnsrewriteMatch ? dnsrewriteMatch[1] : null,
      },
      { coverSub: isDouble, isHosts: false },
    );
  }

  // ③ ★ 无锚点 + $dnsrewrite：domain^$dnsrewrite=IP
  const bareDnsrewriteMatch = body.match(
    /^([a-z0-9.-]+)\^\$dnsrewrite=([^,;$]+)$/i,
  );
  if (bareDnsrewriteMatch) {
    const domain = normalizeDomain(bareDnsrewriteMatch[1]);
    if (!domain) return null;
    return wrap(
      {
        domain,
        isWhite: true,   // ★ 无锚点 dnsrewrite 视为白名单（重写）
        ip: bareDnsrewriteMatch[2],
      },
      { coverSub: false, isHosts: false },
    );
  }

  // ④ 纯域名
  if (!body.includes("/") && !body.includes("$")) {
    const d = stripWildcard(body.replace(/\.+$/, ""));
    if (d === null) return null;
    const domain = normalizeDomain(d);
    if (!domain) return null;
    return wrap(
      { domain, isWhite: isWhitePrefix, ip: null },
      { coverSub: false, isHosts: false },
    );
  }

  return null;
};

module.exports = {
  DNS_SUPPORTED_MODIFIERS,
  isIPv4,
  isBlackholeIp,
  stripWildcard,
  normalizeDomain,
  getModifiers,
  hasUnsupportedModifier,
  hasImportant,
  hasDnsRewrite,
  isPathRule,
  parseRule,
  EXTENDED_RULE_MARKERS,
};