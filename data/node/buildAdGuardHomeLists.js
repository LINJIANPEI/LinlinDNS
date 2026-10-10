const path = require("node:path");
const { readLines, LineWriter } = require("./stream_utils");

const DOMAIN_RE =
  /^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

function isIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return false;
  return m.slice(1).every((p) => {
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

function normalizeDomain(value) {
  const domain = value
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "")
    .replace(/^\.+/, "");
  if (!domain) return null;
  if (domain === "localhost" || domain === "localhost.localdomain") return null;
  if (isIPv4(domain)) return null;
  if (!DOMAIN_RE.test(domain)) return null;

  const labels = domain.split(".");
  if (labels.length > 5) return null;
  if (domain.length > 80) return null;

  const tld = labels[labels.length - 1];
  if (tld.length > 24) return null;
  if (!/^[a-z]+$/.test(tld)) return null;

  for (const label of labels) {
    if (label.length > 62) return null;
  }

  return domain;
}

// ★ 正则行判断
const isRegexLine = (t) => /^(@@)?\/.+\/([^/]*)$/.test(t);

function parseRule(line) {
  const t = line.trim();
  if (!t) return null;
  if (t.startsWith("!") || t.startsWith("#")) return null;

  // ★ 正则规则
  if (isRegexLine(t)) {
    return { domain: null, isWhite: t.startsWith("@@"), isRegex: true };
  }

  const isWhite = t.startsWith("@@");
  const body = isWhite ? t.slice(2) : t;

  let domain;
  if (body.startsWith("||") || body.startsWith("|")) {
    const isDouble = body.startsWith("||");
    let rest = body.slice(isDouble ? 2 : 1);
    rest = rest.replace(/^\^/, "");
    domain = normalizeDomain(
      rest.split("^")[0].split("/")[0].split("$")[0],
    );
  } else {
    domain = normalizeDomain(
      t.replace(/\^+$/, "").split("$")[0].split("/")[0],
    );
  }

  return domain ? { domain, isWhite } : null;
}

const isImportant = (original) => /\$important\b/.test(original);
const hasDnsRewrite = (original) => /\$dnsrewrite\b/.test(original);

function canCover(wOriginal, bOriginal) {
  if (isImportant(wOriginal)) return true;
  if (isImportant(bOriginal)) return false;
  if (hasDnsRewrite(bOriginal)) return false;
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

  // 普通规则：domain → original
  const blackMap = new Map();
  const whiteMap = new Map();

  // ★ 正则规则：直接存原始行
  const regexBlack = new Set();
  const regexWhite = new Set();

  let skippedCount = 0;
  const seenLines = new Set();

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

    // ★ 正则规则单独存
    if (rule.isRegex) {
      if (rule.isWhite) regexWhite.add(line);
      else regexBlack.add(line);
      return;
    }

    const map = rule.isWhite ? whiteMap : blackMap;
    if (!map.has(rule.domain)) {
      map.set(rule.domain, line);
    } else {
      const existing = map.get(rule.domain);
      if (isImportant(line) && !isImportant(existing)) {
        map.set(rule.domain, line);
      }
    }
  });

  seenLines.clear();

  console.log(
    `解析完成：黑域名候选 ${blackMap.size}，白域名候选 ${whiteMap.size}，` +
      `正则黑 ${regexBlack.size}，正则白 ${regexWhite.size}`,
  );

  const noblacklistSet = new Set();
  const nowhitelistSet = new Set();

  // 白名单覆盖黑名单
  for (const w of whiteMap.keys()) {
    const wOriginal = whiteMap.get(w);

    if (blackMap.has(w)) {
      const bOriginal = blackMap.get(w);
      if (canCover(wOriginal, bOriginal)) {
        noblacklistSet.add(bOriginal);
        blackMap.delete(w);
      }
    }

    const suffix = `.${w}`;
    for (const b of [...blackMap.keys()]) {
      if (b.endsWith(suffix)) {
        const bOriginal = blackMap.get(b);
        if (canCover(wOriginal, bOriginal)) {
          noblacklistSet.add(bOriginal);
          blackMap.delete(b);
        }
      }
    }
  }

  // 拆分普通和 important
  const normalBlack = new Map();
  const importantBlack = new Map();
  for (const [d, original] of blackMap) {
    if (isImportant(original)) importantBlack.set(d, original);
    else normalBlack.set(d, original);
  }

  const normalBlackDomains = removeRedundantSubdomains(
    new Set(normalBlack.keys()),
  );
  const normalBlackKept = new Set(normalBlackDomains);
  for (const [d, original] of normalBlack) {
    if (!normalBlackKept.has(d)) noblacklistSet.add(original);
  }

  const importantBlackDomains = [...importantBlack.keys()];
  const blackDomains = [
    ...new Set([...normalBlackDomains, ...importantBlackDomains]),
  ].sort();

  // 白名单同理
  const normalWhite = new Map();
  const importantWhite = new Map();
  for (const [d, original] of whiteMap) {
    if (isImportant(original)) importantWhite.set(d, original);
    else normalWhite.set(d, original);
  }

  const normalWhiteDomains = removeRedundantSubdomains(
    new Set(normalWhite.keys()),
  );
  const normalWhiteKept = new Set(normalWhiteDomains);
  for (const [d, original] of normalWhite) {
    if (!normalWhiteKept.has(d)) nowhitelistSet.add(original);
  }

  const importantWhiteDomains = [...importantWhite.keys()];
  const whiteDomains = [
    ...new Set([...normalWhiteDomains, ...importantWhiteDomains]),
  ].sort();

  const getBlackOriginal = (d) =>
    blackMap.get(d) || normalBlack.get(d) || importantBlack.get(d);
  const getWhiteOriginal = (d) =>
    whiteMap.get(d) || normalWhite.get(d) || importantWhite.get(d);

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

  // ★ 输出：普通规则 + 正则规则
  const rulesWriter = new LineWriter(outRulesFile);
  for (const d of blackDomains) {
    const original = getBlackOriginal(d);
    if (original) await rulesWriter.write(original);
  }
  for (const r of regexBlack) {
    await rulesWriter.write(r);
  }
  await rulesWriter.close();

  const allowWriter = new LineWriter(outAllowFile);
  for (const d of whiteDomains) {
    const original = getWhiteOriginal(d);
    if (original) await allowWriter.write(original);
  }
  for (const r of regexWhite) {
    await allowWriter.write(r);
  }
  await allowWriter.close();

  const stats = {
    blacklistCount: blackDomains.length + regexBlack.size,
    whitelistCount: whiteDomains.length + regexWhite.size,
    noblacklistCount: noblacklistSet.size,
    nowhitelistCount: nowhitelistSet.size,
    skippedCount,
    regexBlackCount: regexBlack.size,
    regexWhiteCount: regexWhite.size,
  };

  console.log(
    `构建完成：黑名单 ${stats.blacklistCount} 条（含正则 ${stats.regexBlackCount}），` +
      `白名单 ${stats.whitelistCount} 条（含正则 ${stats.regexWhiteCount}），` +
      `noblacklist ${stats.noblacklistCount} 条，` +
      `nowhitelist ${stats.nowhitelistCount} 条，` +
      `skipped ${stats.skippedCount} 条`,
  );

  return stats;
};

module.exports = { buildAdGuardHomeLists };