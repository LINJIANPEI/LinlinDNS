const { readLines, LineWriter } = require("./stream_utils");
const {
  parseRule,
  formatRule,
  hasDnsRewrite,
} = require("./rule_parser");

function canCover(wRule, bRule) {
  if (wRule.important) return true;
  if (bRule.important) return false;
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

/**
 * ★ 按规则的结构字段分类（不再解析字符串前缀）。
 */
const classifyRule = (rule) => {
  if (rule.ip) {
    if (rule.anchor === "star") return "rewriteStar";
    if (rule.anchor === "bare") return "rewriteBare";
    if (rule.anchor === "sub")
      return rule.isWhite ? "rewriteWhiteSub" : "rewriteBlackSub";
    return rule.isWhite ? "rewriteWhiteExact" : "rewriteBlackExact";
  }
  if (rule.anchor === "star") return "star";
  if (rule.anchor === "sub") return "sub";
  if (rule.anchor === "exact") return "exact";
  return "other";
};

const writeBuckets = async (writer, buckets) => {
  for (const key of [
    "rewriteBlackExact",
    "rewriteBlackSub",
    "rewriteWhiteExact",
    "rewriteWhiteSub",
    "rewriteStar",
    "rewriteBare",
    "modified",
    "exact",
    "sub",
    "other",
  ]) {
    const lines = buckets[key];
    if (!lines || lines.length === 0) continue;
    lines.sort();
    for (const line of lines) {
      await writer.write(line);
    }
  }
};

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

  // ============================================================
  // 第 1 步：解析
  // ============================================================
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
      if (rule.ip && !existing.ip) {
        redundantSet.add(existing.original);
        map.set(rule.domain, rule);
      } else if (!rule.ip && existing.ip) {
        redundantSet.add(rule.original);
      } else if (rule.important && !existing.important) {
        redundantSet.add(existing.original);
        map.set(rule.domain, rule);
      } else if (
        rule.important === existing.important &&
        rule.coverSub &&
        !existing.coverSub
      ) {
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

  // 第 2 步：白名单覆盖黑名单
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

  // 第 3 步：反向排除
  const suppressedWhite = new Set();
  for (const [wDomain, wRule] of whiteMap) {
    const bRule = blackMap.get(wDomain);
    if (!bRule) continue;
    if (!wRule.important && bRule.important) {
      suppressedWhite.add(wDomain);
      continue;
    }
    if (!wRule.important && bRule.ip) {
      suppressedWhite.add(wDomain);
      continue;
    }
  }

  for (const d of suppressedWhite) {
    const rule = whiteMap.get(d);
    if (rule) {
      nowhitelistSet.add(rule.original);
      whiteMap.delete(d);
    }
  }

  console.log(
    `反向排除：被 important/dnsrewrite 黑名单压制的白名单 ${suppressedWhite.size} 条`,
  );

  // ============================================================
  // 第 4 步：$dnsrewrite 冲突检测
  // ★ 锚点转换集中在这里：|| → *，| → bare
  // ============================================================
  const dnsRewriteConflictRules = [];

  for (const [wDomain, wRule] of whiteMap) {
    if (!wRule.coverSub || wRule.important || wRule.ip) continue;

    const suffix = `.${wDomain}`;
    for (const [bDomain, bRule] of blackMap) {
      if (!bDomain.endsWith(suffix)) continue;
      if (bRule.important || bRule.ip) {
        // ★ 构造结构化规则，交给 formatRule 生成
        dnsRewriteConflictRules.push({
          domain: bDomain,
          isWhite: false,
          anchor: bRule.coverSub ? "star" : "bare",
          ip: "0.0.0.0",
          coverSub: bRule.coverSub,
          isHosts: false,
          important: false,
          original: "",
        });
      }
    }
  }

  if (dnsRewriteConflictRules.length > 0) {
    console.log(
      `$dnsrewrite 冲突：${dnsRewriteConflictRules.length} 条子域需强制重写`,
    );
  }

  // 第 5 步：拆黑名单
  const normalBlack = new Map();
  const importantBlack = new Map();
  for (const [d, rule] of blackMap) {
    if (rule.important || rule.ip) importantBlack.set(d, rule);
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

  // 第 6 步：拆白名单
  const normalWhite = new Map();
  const importantWhite = new Map();
  for (const [d, rule] of whiteMap) {
    if (rule.important || rule.ip) importantWhite.set(d, rule);
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

  const getBlackRule = (d) =>
    blackMap.get(d) || normalBlack.get(d) || importantBlack.get(d);
  const getWhiteRule = (d) =>
    whiteMap.get(d) || normalWhite.get(d) || importantWhite.get(d);

  // 第 7 步：写归档
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

  // ============================================================
  // 第 8 步：输出产物（★ 全部走 formatRule）
  // ============================================================
  const blackBuckets = {
    rewriteBlackExact: [],
    rewriteBlackSub: [],
    rewriteWhiteExact: [],
    rewriteWhiteSub: [],
    rewriteStar: [],
    rewriteBare: [],
    modified: [],
    exact: [],
    sub: [],
    other: [],
  };

  for (const d of blackDomains) {
    const rule = getBlackRule(d);
    const line = formatRule(rule);   // ★
    if (!line) continue;
    blackBuckets[classifyRule(rule)].push(line);
  }

  const rulesWriter = new LineWriter(outRulesFile);
  await writeBuckets(rulesWriter, blackBuckets);
  await rulesWriter.close();

  const whiteBuckets = {
    rewriteBlackExact: [],
    rewriteBlackSub: [],
    rewriteWhiteExact: [],
    rewriteWhiteSub: [],
    rewriteStar: [],
    rewriteBare: [],
    modified: [],
    exact: [],
    sub: [],
    other: [],
  };

  for (const d of whiteDomains) {
    const rule = getWhiteRule(d);
    const line = formatRule(rule);   // ★
    if (!line) continue;
    whiteBuckets[classifyRule(rule)].push(line);
  }

  // ★ 冲突规则也走 formatRule
  for (const conflict of dnsRewriteConflictRules) {
    const line = formatRule(conflict);
    if (line) whiteBuckets[classifyRule(conflict)].push(line);
  }

  const allowWriter = new LineWriter(outAllowFile);
  await writeBuckets(allowWriter, whiteBuckets);
  await allowWriter.close();

  const rewriteOutCount =
    whiteBuckets.rewriteBlackExact.length +
    whiteBuckets.rewriteBlackSub.length +
    whiteBuckets.rewriteWhiteExact.length +
    whiteBuckets.rewriteWhiteSub.length +
    whiteBuckets.rewriteStar.length +
    whiteBuckets.rewriteBare.length;

  const stats = {
    blacklistCount: blackDomains.length,
    whitelistCount: whiteDomains.length + dnsRewriteConflictRules.length,
    dnsRewriteCount: rewriteOutCount,
    noblacklistCount: noblacklistSet.size,
    nowhitelistCount: nowhitelistSet.size,
    suppressedWhiteCount: suppressedWhite.size,
    dnsRewriteConflictCount: dnsRewriteConflictRules.length,
    skippedCount,
    redundantCount,
  };

  console.log(
    `构建完成：黑名单 ${blackDomains.length} 条，` +
      `白名单 ${stats.whitelistCount} 条` +
      `（含重写 ${stats.dnsRewriteCount}，冲突重写 ${stats.dnsRewriteConflictCount}），` +
      `noblacklist ${stats.noblacklistCount} 条，` +
      `nowhitelist ${stats.nowhitelistCount} 条，` +
      `被压制白名单 ${stats.suppressedWhiteCount} 条，` +
      `skipped ${stats.skippedCount} 条，` +
      `redundant ${stats.redundantCount} 条`,
  );

  return stats;
};

module.exports = { buildAdGuardHomeLists };