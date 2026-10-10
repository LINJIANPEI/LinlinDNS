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

function parseRule(line) {
  const t = line.trim();
  if (!t) return null;
  if (t.startsWith("!") || t.startsWith("#")) return null;

  const isWhite = t.startsWith("@@");
  const body = isWhite ? t.slice(2) : t;

  let domain;
  if (body.startsWith("||") || body.startsWith("|")) {
    const isDouble = body.startsWith("||");
    let rest = body.slice(isDouble ? 2 : 1);
    rest = rest.replace(/^\^/, "");
    domain = normalizeDomain(rest.split("^")[0].split("/")[0].split("$")[0]);
  } else {
    domain = normalizeDomain(t.replace(/\^+$/, "").split("$")[0].split("/")[0]);
  }

  return domain ? { domain, isWhite } : null;
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

  // ★ Map：domain → original
  const blackMap = new Map();
  const whiteMap = new Map();

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

    const map = rule.isWhite ? whiteMap : blackMap;
    if (!map.has(rule.domain)) {
      map.set(rule.domain, line); // ★ 保留原始行
    }
  });

  seenLines.clear();

  console.log(
    `解析完成：黑域名候选 ${blackMap.size}，白域名候选 ${whiteMap.size}`,
  );

  const noblacklistSet = new Set();
  const nowhitelistSet = new Set();

  // 白名单覆盖黑名单（精确匹配）
  for (const w of whiteMap.keys()) {
    if (blackMap.has(w)) {
      noblacklistSet.add(blackMap.get(w));
      blackMap.delete(w);
    }
  }

  // 父子域名收敛（按域名）
  const blackDomains = removeRedundantSubdomains(new Set(blackMap.keys()));
  const whiteDomains = removeRedundantSubdomains(new Set(whiteMap.keys()));

  const blackKept = new Set(blackDomains);
  for (const [d, original] of blackMap) {
    if (!blackKept.has(d)) noblacklistSet.add(original);
  }

  const whiteKept = new Set(whiteDomains);
  for (const [d, original] of whiteMap) {
    if (!whiteKept.has(d)) nowhitelistSet.add(original);
  }

  // ★ 不要 clear blackMap / whiteMap，后面输出要用

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

  // ★ 输出原始行
  const rulesWriter = new LineWriter(outRulesFile);
  for (const d of blackDomains) {
    await rulesWriter.write(blackMap.get(d));
  }
  await rulesWriter.close();

  const allowWriter = new LineWriter(outAllowFile);
  for (const d of whiteDomains) {
    await allowWriter.write(whiteMap.get(d));
  }
  await allowWriter.close();

  const stats = {
    blacklistCount: blackDomains.length,
    whitelistCount: whiteDomains.length,
    noblacklistCount: noblacklistSet.size,
    nowhitelistCount: nowhitelistSet.size,
    skippedCount,
  };

  console.log(
    `构建完成：黑名单 ${stats.blacklistCount} 条，` +
      `白名单 ${stats.whitelistCount} 条，` +
      `noblacklist ${stats.noblacklistCount} 条，` +
      `nowhitelist ${stats.nowhitelistCount} 条，` +
      `skipped ${stats.skippedCount} 条`,
  );

  return stats;
};

module.exports = { buildAdGuardHomeLists };
