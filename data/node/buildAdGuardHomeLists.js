const DOMAIN_RE =
  /^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
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

// ---------- IP 工具 ----------

function isIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return false;
  return m.slice(1).every((p) => {
    const n = Number(p);
    return n >= 0 && n <= 255 && String(n) === p.replace(/^0+(?=\d)/, "");
  });
}

function isIPv6(s) {
  if (!s.includes(":")) return false;
  try {
    new URL(`http://[${s}]/`);
    return true;
  } catch {
    return false;
  }
}

const isIP = (s) => isIPv4(s) || isIPv6(s);

const ipToBigIntV4 = (ip) =>
  ip.split(".").reduce((acc, p) => (acc << 8n) + BigInt(Number(p)), 0n);

function isBlacklistHostIp(ip) {
  if (!isIPv4(ip)) return false;
  if (ip === "0.0.0.0") return true;
  const n = ipToBigIntV4(ip);
  return n >= ipToBigIntV4("127.0.0.0") && n <= ipToBigIntV4("127.255.255.255");
}

function isGlobalV4(ip) {
  const n = ipToBigIntV4(ip);
  const inRange = (a, b) => n >= ipToBigIntV4(a) && n <= ipToBigIntV4(b);
  if (inRange("0.0.0.0", "0.255.255.255")) return false;
  if (inRange("10.0.0.0", "10.255.255.255")) return false;
  if (inRange("100.64.0.0", "100.127.255.255")) return false;
  if (inRange("127.0.0.0", "127.255.255.255")) return false;
  if (inRange("169.254.0.0", "169.254.255.255")) return false;
  if (inRange("172.16.0.0", "172.31.255.255")) return false;
  if (inRange("192.0.0.0", "192.0.0.255")) return false;
  if (inRange("192.0.2.0", "192.0.2.255")) return false;
  if (inRange("192.168.0.0", "192.168.255.255")) return false;
  if (inRange("198.18.0.0", "198.19.255.255")) return false;
  if (inRange("198.51.100.0", "198.51.100.255")) return false;
  if (inRange("203.0.113.0", "203.0.113.255")) return false;
  if (inRange("224.0.0.0", "239.255.255.255")) return false;
  if (inRange("240.0.0.0", "255.255.255.255")) return false;
  return true;
}

function isGlobalV6(ip) {
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1") return false;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return false;
  if (/^fe[89ab]/.test(lower)) return false;
  if (lower.startsWith("ff")) return false;
  if (lower.startsWith("2001:db8")) return false;
  if (lower.startsWith("::ffff:")) {
    const v4 = lower.slice("::ffff:".length);
    return isIPv4(v4) ? isGlobalV4(v4) : false;
  }
  return true;
}

function isGlobalIp(ip) {
  if (isIPv4(ip)) return isGlobalV4(ip);
  if (isIPv6(ip)) return isGlobalV6(ip);
  return false;
}

// ---------- 单条规则解析 ----------

function normalizeDomain(value) {
  const domain = value
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "")
    .replace(/^\.+/, "");
  if (domain === "localhost" || domain === "localhost.localdomain") return null;
  if (isIP(domain)) return null;
  return DOMAIN_RE.test(domain) ? domain : null;
}

function uncomment(raw) {
  const line = String(raw).trim();
  if (!line || line.startsWith("!") || line.startsWith("[")) return "";
  if (/^#{2,}\s/.test(line)) return "";
  if (
    line.startsWith("#") &&
    !EXTENDED_RULE_MARKERS.some((m) => line.startsWith(m))
  ) {
    return "";
  }
  return line.split(/\s+[#!]/, 1)[0].trim();
}

function parseRule(line) {
  const parts = line.split(/\s+/);
  if (parts.length === 2) {
    const hostIp = parts[0];
    if (isIP(hostIp)) {
      const domain = normalizeDomain(parts[1]);
      if (domain) {
        return {
          original: line,
          domain,
          isWhite: !isBlacklistHostIp(hostIp),
          formatRank: 1,
          hostIp,
        };
      }
      return null;
    }
  }

  const isWhite = line.startsWith("@@");
  const body = isWhite ? line.slice(2) : line;
  if (body.startsWith("||")) {
    const domain = normalizeDomain(body.slice(2).split("^", 1)[0]);
    return domain
      ? { original: line, domain, isWhite, formatRank: 2, hostIp: null }
      : null;
  }

  const domain = normalizeDomain(line.replace(/\^+$/, ""));
  return domain
    ? { original: line, domain, isWhite: false, formatRank: 0, hostIp: null }
    : null;
}

function isValidFinalHost(rule) {
  if (rule.hostIp === null) return true;
  if (isBlacklistHostIp(rule.hostIp)) return true;
  return isGlobalIp(rule.hostIp);
}

function removeRedundantSubdomains(domains) {
  const set = domains instanceof Set ? domains : new Set(domains);
  const ordinary = new Set();
  const wildcards = [];
  for (const d of set) {
    if (d.startsWith("*.")) wildcards.push(d);
    else ordinary.add(d);
  }
  const sorted = [...ordinary].sort((a, b) => {
    const da = (a.match(/\./g) || []).length;
    const db = (b.match(/\./g) || []).length;
    if (da !== db) return da - db;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  const kept = [];
  for (const domain of sorted) {
    const labels = domain.split(".");
    let redundant = false;
    for (let i = 1; i < labels.length; i++) {
      if (ordinary.has(labels.slice(i).join("."))) {
        redundant = true;
        break;
      }
    }
    if (!redundant) kept.push(domain);
  }
  return [...kept, ...wildcards].sort();
}

// ---------- 主函数 ----------

/**
 * 从规则字符串数组生成 AdGuard Home 黑白名单。
 *
 * 五个输出数组互斥，且并集等于输入：
 *   blacklist ∪ whitelist ∪ noblacklist ∪ nowhitelist ∪ skipped = 输入（去重后）
 *
 * @param {string[]} rawRules  原始规则数组
 * @returns {{
 *   blacklist: string[],
 *   whitelist: string[],
 *   noblacklist: string[],
 *   nowhitelist: string[],
 *   skipped: string[]
 * }}
 *   blacklist:   最终黑名单，形如 "||example.com^"
 *   whitelist:   最终白名单，形如 "@@||example.com^$important"
 *   noblacklist: 本应进黑名单但被丢弃的条目
 *   nowhitelist: 本应进白名单但被丢弃的条目
 *   skipped:     排除上面四类之后剩下的所有行（注释、空行、[xxx] 段头、
 *                被 uncomment 截断后为空的行等）
 */
function buildAdGuardHomeLists(rawRules) {
  if (!Array.isArray(rawRules)) {
    throw new TypeError("rawRules 必须是字符串数组");
  }

  const noblacklistSet = new Set();
  const nowhitelistSet = new Set();
  const skipped = [];

  // 1. 去注释 + 去重 + 排序；uncomment 返回空的行全部进 skipped
  const lineSet = new Set();
  for (const raw of rawRules) {
    const line = uncomment(raw);
    if (line) {
      lineSet.add(line);
    } else {
      skipped.push(raw);
    }
  }
  const lines = [...lineSet].sort();

  // 2. 解析（未识别的按 @@ 前缀归档）
  const rules = [];
  for (const line of lines) {
    const rule = parseRule(line);
    if (rule) {
      rules.push(rule);
    } else {
      (line.startsWith("@@") ? nowhitelistSet : noblacklistSet).add(line);
    }
  }

  rules.sort((a, b) => {
    if (a.isWhite !== b.isWhite) return a.isWhite ? 1 : -1;
    if (a.formatRank !== b.formatRank) return a.formatRank - b.formatRank;
    if (a.domain !== b.domain) return a.domain < b.domain ? -1 : 1;
    return a.original < b.original ? -1 : a.original > b.original ? 1 : 0;
  });

  // 3. 清洗：过滤非公网 host，被过滤的归档
  const validRules = [];
  for (const r of rules) {
    if (isValidFinalHost(r)) {
      validRules.push(r);
    } else {
      (r.isWhite ? nowhitelistSet : noblacklistSet).add(r.original);
    }
  }

  const blackSet = new Set();
  const whiteSet = new Set();
  for (const r of validRules) {
    if (r.isWhite) whiteSet.add(r.domain);
    else blackSet.add(r.domain);
  }

  // 白名单覆盖黑名单：被覆盖的黑名单条目归入 noblacklist
  for (const w of whiteSet) {
    if (blackSet.has(w)) {
      blackSet.delete(w);
      noblacklistSet.add(`||${w}^`);
    }
  }

  // 4. 父域去冗余，被删掉的子域归档
  const blackDomains = removeRedundantSubdomains(blackSet);
  const whiteDomains = removeRedundantSubdomains(whiteSet);

  const blackKept = new Set(blackDomains);
  for (const d of blackSet) {
    if (!blackKept.has(d)) noblacklistSet.add(`||${d}^`);
  }
  const whiteKept = new Set(whiteDomains);
  for (const d of whiteSet) {
    if (!whiteKept.has(d)) nowhitelistSet.add(`@@||${d}^$important`);
  }

  // 5. 输出
  return {
    blacklist: blackDomains.map((d) => `||${d}^`),
    whitelist: whiteDomains.map((d) => `@@||${d}^$important`),
    noblacklist: [...noblacklistSet].sort(),
    nowhitelist: [...nowhitelistSet].sort(),
    skipped,
  };
}

module.exports = { buildAdGuardHomeLists };
