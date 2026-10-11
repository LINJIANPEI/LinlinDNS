const path = require("node:path");
const { readLines, LineWriter } = require("./stream_utils");

const DNS_SUPPORTED_MODIFIERS = new Set([
  "important",
  "badfilter",
  "match-case",
  "denyallow",
  "dnsrewrite",
  "dnstype",
  "client",
]);

function isIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return false;
  return m.slice(1).every((p) => {
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

/**
 * ★ 处理通配符域名。
 */
const stripWildcard = (domain) => {
  let d = domain;
  if (d.startsWith("*.")) d = d.slice(2);
  if (d.includes("*")) return null;
  return d;
};

/**
 * 域名规范化（只做结构校验，无层级上限）。
 */
function normalizeDomain(value) {
  const domain = value
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "")
    .replace(/^\.+/, "");
  if (!domain) return null;
  if (domain === "localhost" || domain === "localhost.localdomain") return null;
  if (domain.includes(" ")) return null;
  if (!/^[a-z0-9.-]+$/.test(domain)) return null;
  if (domain.includes("..")) return null;
  if (isIPv4(domain)) return null;

  const labels = domain.split(".");
  if (labels.length < 2) return null;
  // ★ 不再限制层级上限
  if (domain.length > 253) return null;

  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return null;
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) return null;
  }

  return domain;
}

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

function parseRule(line) {
  const t = line.trim();
  if (!t) return null;
  if (t.startsWith("!") || t.startsWith("#")) return null;
  if (hasUnsupportedModifier(t)) return null;

  const isWhite = t.startsWith("@@");
  const body = isWhite ? t.slice(2) : t;

  // ||domain^
  if (body.startsWith("||")) {
    let rest = body.slice(2).replace(/^\^/, "");
    // ★ 处理通配符
    rest = stripWildcard(rest);
    if (rest === null) return null;

    const beforeMod = rest.split("$")[0];
    const core = beforeMod.split("^")[0];
    if (core.includes("/")) return null;
    const domain = normalizeDomain(core);
    return domain ? { domain, isWhite, original: t, coverSub: true } : null;
  }

  // |domain^
  if (body.startsWith("|")) {
    let rest = body.slice(1).replace(/^\^/, "");
    // ★ 处理通配符
    rest = stripWildcard(rest);
    if (rest === null) return null;

    const beforeMod = rest.split("$")[0];
    const core = beforeMod.split("^")[0];
    if (core.includes("/")) return null;
    const domain = normalizeDomain(core);
    return domain ? { domain, isWhite, original: t, coverSub: false } : null;
  }

  // hosts 格式
  const parts = t.split(/\s+/);
  if (parts.length === 2 && isIPv4(parts[0])) {
    // ★ 处理通配符
    let cand = parts[1];
    cand = stripWildcard(cand);
    if (cand === null) return null;
    const domain = normalizeDomain(cand);
    if (!domain) return null;
    const isBlacklistIp = parts[0] === "0.0.0.0" || parts[0].startsWith("127.");
    return { domain, isWhite: !isBlacklistIp, original: t, coverSub: false };
  }

  // ★ 纯域名：用 body（已去 @@），并处理通配符
  let tail = body.replace(/\^+$/, "").split("$")[0].split("/")[0];
  tail = stripWildcard(tail);
  if (tail === null) return null;
  const domain = normalizeDomain(tail);
  return domain ? { domain, isWhite, original: t, coverSub: false } : null;
}

const isImportant = (line) => /\$important\b/.test(line);
const hasDnsRewrite = (line) => /\$dnsrewrite\b/.test(line);

function canCover(wRule, bRule) {
  if (isImportant(wRule.original)) return true;
  if (isImportant(bRule.original)) return false;
  if (hasDnsRewrite(bRule.original)) return false;
  if (!wRule.coverSub && bRule.coverSub) return false;
  return true;
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
    let redundant = false;
    let idx = domain.indexOf(".");
    while (idx !== -1) {
      if (ordinary.has(domain.slice(idx + 1))) {
        redundant = true;
        break;
      }
      idx = domain.indexOf(".", idx + 1);
    }
    if (!redundant) kept.push(domain);
  }
  return [...kept, ...wildcards].sort();
}

const buildAdGuardHomeLists = async (options) => {
  const {
    cleanedFile,
    outRulesFile,
    outAllowFile,
    outNoBlacklistFile,
    outNoWhitelistFile,
    outSkippedFile,
    outRedundantFile,
  } = options;

  if (!cleanedFile) throw new TypeError("cleanedFile 必填");
  if (!outRulesFile) throw new TypeError("outRulesFile 必填");
  if (!outAllowFile) throw new TypeError("outAllowFile 必填");

  console.log("开始构建 AdGuard Home 列表");

  const noblacklistWriter = outNoBlacklistFile
    ? new LineWriter(outNoBlacklistFile)
    : null;
  const nowhitelistWriter = outNoWhitelistFile
    ? new LineWriter(outNoWhitelistFile)
    : null;
  const skippedWriter = outSkippedFile ? new LineWriter(outSkippedFile) : null;
  const redundantWriter = outRedundantFile
    ? new LineWriter(outRedundantFile)
    : null;

  const blackMap = new Map();
  const whiteMap = new Map();

  let skippedCount = 0;
  const seenLines = new Set();
  const redundantSet = new Set();

  await readLines(cleanedFile, async (raw) => {
    const line = raw.trim();
    if (!line) {
      if (skippedWriter) await skippedWriter.write(raw);
      skippedCount++;
      return;
    }
    if (seenLines.has(line)) return;
    seenLines.add(line);

    const rule = parseRule(line);
    if (!rule) {
      if (skippedWriter) await skippedWriter.write(raw);
      skippedCount++;
      return;
    }

    const map = rule.isWhite ? whiteMap : blackMap;
    const existing = map.get(rule.domain);

    if (existing === undefined) {
      map.set(rule.domain, rule);
    } else {
      const curImp = isImportant(rule.original);
      const exImp = isImportant(existing.original);

      if (curImp && !exImp) {
        redundantSet.add(existing.original);
        map.set(rule.domain, rule);
      } else if (curImp === exImp && rule.coverSub && !existing.coverSub) {
        redundantSet.add(existing.original);
        map.set(rule.domain, rule);
      } else {
        redundantSet.add(rule.original);
      }
    }
  });

  seenLines.clear();

  console.log(
    `解析完成：黑域名候选 ${blackMap.size}，白域名候选 ${whiteMap.size}`,
  );

  const noblacklistSet = new Set();
  const nowhitelistSet = new Set();

  // ★ 白名单覆盖黑名单
  for (const [wDomain, wRule] of whiteMap) {
    if (blackMap.has(wDomain)) {
      const bRule = blackMap.get(wDomain);
      if (canCover(wRule, bRule)) {
        noblacklistSet.add(bRule.original);
        blackMap.delete(wDomain);
      }
    }

    if (wRule.coverSub) {
      const suffix = `.${wDomain}`;
      for (const bDomain of [...blackMap.keys()]) {
        if (bDomain.endsWith(suffix)) {
          const bRule = blackMap.get(bDomain);
          if (canCover(wRule, bRule)) {
            noblacklistSet.add(bRule.original);
            blackMap.delete(bDomain);
          }
        }
      }
    }
  }

  const normalBlack = new Map();
  const importantBlack = new Map();
  for (const [d, rule] of blackMap) {
    if (isImportant(rule.original)) importantBlack.set(d, rule);
    else normalBlack.set(d, rule);
  }

  const normalBlackDomains = removeRedundantSubdomains(
    new Set(normalBlack.keys()),
  );
  const normalBlackKept = new Set(normalBlackDomains);
  for (const [d, rule] of normalBlack) {
    if (!normalBlackKept.has(d)) noblacklistSet.add(rule.original);
  }

  const importantBlackDomains = [...importantBlack.keys()];

  const blackDomains = [
    ...new Set([...normalBlackDomains, ...importantBlackDomains]),
  ].sort();

  const normalWhite = new Map();
  const importantWhite = new Map();
  for (const [d, rule] of whiteMap) {
    if (isImportant(rule.original)) importantWhite.set(d, rule);
    else normalWhite.set(d, rule);
  }

  const normalWhiteDomains = removeRedundantSubdomains(
    new Set(normalWhite.keys()),
  );
  const normalWhiteKept = new Set(normalWhiteDomains);
  for (const [d, rule] of normalWhite) {
    if (!normalWhiteKept.has(d)) nowhitelistSet.add(rule.original);
  }

  const importantWhiteDomains = [...importantWhite.keys()];

  const whiteDomains = [
    ...new Set([...normalWhiteDomains, ...importantWhiteDomains]),
  ].sort();

  const getBlackOriginal = (d) => {
    const rule = blackMap.get(d) || normalBlack.get(d) || importantBlack.get(d);
    return rule ? rule.original : null;
  };
  const getWhiteOriginal = (d) => {
    const rule = whiteMap.get(d) || normalWhite.get(d) || importantWhite.get(d);
    return rule ? rule.original : null;
  };

  if (noblacklistWriter) {
    for (const line of [...noblacklistSet].sort()) {
      await noblacklistWriter.write(line);
    }
    await noblacklistWriter.close();
  }

  if (nowhitelistWriter) {
    for (const line of [...nowhitelistSet].sort()) {
      await nowhitelistWriter.write(line);
    }
    await nowhitelistWriter.close();
  }

  if (skippedWriter) await skippedWriter.close();

  if (redundantWriter) {
    for (const line of [...redundantSet].sort()) {
      await redundantWriter.write(line);
    }
    await redundantWriter.close();
  }
  const redundantCount = redundantSet.size;

  const rulesWriter = new LineWriter(outRulesFile);
  for (const d of blackDomains) {
    const original = getBlackOriginal(d);
    if (original) await rulesWriter.write(original);
  }
  await rulesWriter.close();

  const allowWriter = new LineWriter(outAllowFile);
  for (const d of whiteDomains) {
    const original = getWhiteOriginal(d);
    if (original) await allowWriter.write(original);
  }
  await allowWriter.close();

  const stats = {
    blacklistCount: blackDomains.length,
    whitelistCount: whiteDomains.length,
    noblacklistCount: noblacklistSet.size,
    nowhitelistCount: nowhitelistSet.size,
    skippedCount,
    redundantCount,
  };

  console.log(
    `构建完成：黑名单 ${stats.blacklistCount} 条，` +
      `白名单 ${stats.whitelistCount} 条，` +
      `noblacklist ${stats.noblacklistCount} 条，` +
      `nowhitelist ${stats.nowhitelistCount} 条，` +
      `skipped ${stats.skippedCount} 条，` +
      `redundant ${stats.redundantCount} 条`,
  );

  return stats;
};

module.exports = { buildAdGuardHomeLists };
