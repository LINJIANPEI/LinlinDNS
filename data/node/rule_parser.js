/**
 * 共享规则解析模块。
 * ★ 唯一负责解析和格式化锚点的地方。
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

const isIPv6 = (s) => {
  if (typeof s !== "string" || !s.includes(":")) return false;
  return /^[0-9a-f:]+$/i.test(s);
};

const isBlackholeIp = (ip) =>
  ip === "0.0.0.0" ||
  ip.startsWith("127.") ||
  ip === "::1" ||
  ip === "0:0:0:0:0:0:0:1";

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

const extractDnsRewrite = (modStr) => {
  if (!modStr) return null;
  const parts = modStr.split(",");
  for (const part of parts) {
    const t = part.trim();
    const eq = t.indexOf("=");
    if (eq === -1) continue;
    const name = t.slice(0, eq).trim().toLowerCase();
    if (name === "dnsrewrite") return t.slice(eq + 1);
  }
  return null;
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

const extractSuffix = (line) => {
  const idx = line.indexOf("$");
  return idx === -1 ? "" : line.slice(idx);
};

const parseRule = (line, opts = {}) => {
  if (typeof line !== "string") return null;
  const t0 = line.trim();
  if (!t0) return null;

  // ★ 剥离行尾注释
  const t = t0.replace(/\s+#.*$/, "");

  if (!t) return null;
  if (t.startsWith("!")) return null;
  if (t.startsWith("#")) {
    if (!opts.allowExtended) return null;
    if (!EXTENDED_RULE_MARKERS.some((m) => t.startsWith(m))) return null;
  }

  if (hasUnsupportedModifier(t)) return null;

  const isWhitePrefix = t.startsWith("@@");
  const body = isWhitePrefix ? t.slice(2) : t;

  const make = (domain, isWhite, anchor, ip, isHosts = false) => ({
    domain,
    // ★ $dnsrewrite 是拦截重写动作，忽略 @@（白名单不支持重写）
    isWhite: ip ? false : isWhite,
    anchor,
    ip,
    coverSub: anchor === "sub" || anchor === "star",
    isHosts,
    important: hasImportant(t),
    original: t,
  });

  // ① hosts 格式（IPv4 / IPv6）
  const parts = t.split(/\s+/);
  if (parts.length === 2 && (isIPv4(parts[0]) || isIPv6(parts[0]))) {
    const cand = stripWildcard(parts[1]);
    if (cand === null) return null;
    const domain = normalizeDomain(cand);
    if (!domain) return null;

    const blackhole = isBlackholeIp(parts[0]);
    return make(domain, !blackhole, "bare", blackhole ? null : parts[0], true);
  }

  // ② 已有锚点：|| / | / *
  if (body.startsWith("||") || body.startsWith("|") || body.startsWith("*")) {
    let anchor;
    let rest;

    if (body.startsWith("||")) {
      anchor = "sub";
      rest = body.slice(2);
    } else if (body.startsWith("*")) {
      anchor = "star";
      rest = body.slice(1);
    } else {
      anchor = "exact";
      rest = body.slice(1);
    }

    rest = rest.replace(/^\^/, "");
    rest = stripWildcard(rest);
    if (rest === null) return null;

    const beforeMod = rest.split("$")[0];
    const core = beforeMod.split("^")[0];
    if (core.includes("/")) return null;

    const domain = normalizeDomain(core);
    if (!domain) return null;

    const dollarIdx = rest.indexOf("$");
    const ip =
      dollarIdx === -1 ? null : extractDnsRewrite(rest.slice(dollarIdx + 1));

    return make(domain, isWhitePrefix, anchor, ip);
  }

  // ③ 无锚点 + 修饰符（含 dnsrewrite）
  const bareMatch = body.match(/^([a-z0-9.-]+)\^\$(.+)$/i);
  if (bareMatch) {
    const domain = normalizeDomain(bareMatch[1]);
    if (!domain) return null;
    const ip = extractDnsRewrite(bareMatch[2]);
    if (ip === null) return null;
    return make(domain, isWhitePrefix, "bare", ip);
  }

  // ④ 纯域名
  if (!body.includes("/") && !body.includes("$")) {
    const d = stripWildcard(body.replace(/\.+$/, ""));
    if (d === null) return null;
    const domain = normalizeDomain(d);
    if (!domain) return null;
    return make(domain, isWhitePrefix, "bare", null);
  }

  return null;
};

const formatRule = (rule, opts = {}) => {
  if (!rule) return null;

  const { domain, anchor, ip, isHosts } = rule;

  let isWhite = rule.isWhite;
  if (anchor === "bare" && opts.fileIsWhite !== undefined) {
    isWhite = opts.fileIsWhite;
  }

  const prefix = isWhite ? "@@" : "";
  const suffix = ip ? "" : extractSuffix(rule.original || "");

  if (isHosts) {
    if (ip) {
      const hasImpInIp = /(^|,)\s*important\s*(,|$)/i.test(ip);
      const imp = hasImpInIp ? "" : "important,";
      return `${domain}^$${imp}dnsrewrite=${ip}`;
    }
    return `|${domain}^`;
  }

  if (ip) {
    const hasImpInIp = /(^|,)\s*important\s*(,|$)/i.test(ip);
    const impPrefix = hasImpInIp ? "" : "important,";
    const suffixStr = `$${impPrefix}dnsrewrite=${ip}`;

    if (anchor === "bare") return `${domain}^${suffixStr}`;
    if (anchor === "star") return `*${domain}^${suffixStr}`;
    const bar = anchor === "sub" ? "||" : "|";
    return `${prefix}${bar}${domain}^${suffixStr}`;
  }

  if (anchor === "bare") {
    return `${prefix}|${domain}^${suffix}`;
  }
  if (anchor === "star") {
    return `*${domain}^${suffix}`;
  }
  const bar = anchor === "sub" ? "||" : "|";
  return `${prefix}${bar}${domain}^${suffix}`;
};

module.exports = {
  DNS_SUPPORTED_MODIFIERS,
  isIPv4,
  isIPv6,
  isBlackholeIp,
  stripWildcard,
  normalizeDomain,
  extractDnsRewrite,
  getModifiers,
  hasUnsupportedModifier,
  hasImportant,
  hasDnsRewrite,
  isPathRule,
  parseRule,
  formatRule,
  EXTENDED_RULE_MARKERS,
};
