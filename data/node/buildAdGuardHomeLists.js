const { readLines, LineWriter } = require("./stream_utils");
const { parseRule, formatRule, hasDnsRewrite } = require("./rule_parser");

function canCover(wRule, bRule) {
  if (wRule.important) return true;
  if (bRule.important) return false;
  if (hasDnsRewrite(bRule.original)) return false;
  if (!wRule.coverSub && bRule.coverSub) return false;
  return true;
}

/**
 * ★ 返回 { kept, removed }：
 *   kept    - 保留的域名（已排序）
 *   removed - Map<子域, 父域>，被父域收敛掉的子域
 */
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
  const removed = new Map(); // ★ 子域 -> 父域
  for (const domain of sorted) {
    let redundant = false;
    let idx = domain.indexOf(".");
    while (idx !== -1) {
      const parent = domain.slice(idx + 1);
      if (ordinary.has(parent)) {
        redundant = true;
        removed.set(domain, parent); // ★
        break;
      }
      idx = domain.indexOf(".", idx + 1);
    }
    if (!redundant) kept.push(domain);
  }
  return { kept: [...kept, ...wildcards].sort(), removed };
}

/**
 * ★ 分类规则到桶。
 *   所有返回值必须对应 buckets 里已存在的 key。
 */
const classifyRule = (rule) => {
  if (rule.ip) {
    if (rule.anchor === "star") return "rewriteStar";
    if (rule.anchor === "bare") return "rewriteBare";
    if (rule.anchor === "sub")
      return rule.isWhite ? "rewriteWhiteSub" : "rewriteBlackSub";
    return rule.isWhite ? "rewriteWhiteExact" : "rewriteBlackExact";
  }
  // ★ 非 dnsrewrite
  if (rule.anchor === "star") return "sub";
  if (rule.anchor === "sub") return "sub";
  if (rule.anchor === "exact") return "exact";
  if (rule.anchor === "bare") return "exact";
  return "other";
};

/**
 * ★ 防御性 push：bucket 不存在时自动创建。
 */
const pushLine = (buckets, rule, line) => {
  const key = classifyRule(rule);
  if (!buckets[key]) {
    console.warn(`⚠️ 未知 bucket key: ${key}，规则：${line}`);
    buckets[key] = [];
  }
  buckets[key].push(line);
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

/**
 * ★ 把 Map<被覆盖规则, 覆盖者> 排序后写成 "被覆盖  ->  覆盖者"
 */
const writeCoveredMap = async (writer, map) => {
  if (!writer) return;
  const entries = [...map.entries()].sort((a, b) =>
    a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0,
  );
  for (const [covered, coverBy] of entries) {
    await writer.write(`${covered}  ->  ${coverBy}`);
  }
  await writer.close();
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
    outDuplicateFile, // ★ 归档 seenLines 命中的重复行
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
  const duplicateWriter = outDuplicateFile // ★
    ? new LineWriter(outDuplicateFile)
    : null;

  const blackMap = new Map();
  const whiteMap = new Map();

  let skippedCount = 0;
  let duplicateCount = 0; // ★
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
    if (seenLines.has(line)) {
      // ★ 归档重复行
      if (duplicateWriter) await duplicateWriter.write(raw);
      duplicateCount++;
      return;
    }
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
    `解析完成：黑域名候选 ${blackMap.size}，白域名候选 ${whiteMap.size}` +
      (duplicateCount > 0 ? `，重复行 ${duplicateCount}` : ""),
  );

  // ★ 被覆盖规则 -> 覆盖者
  const noblacklistSet = new Map();
  const nowhitelistSet = new Map();

  // 第 2 步：白名单覆盖黑名单
  for (const [wDomain, wRule] of whiteMap) {
    if (blackMap.has(wDomain)) {
      const bRule = blackMap.get(wDomain);
      if (canCover(wRule, bRule)) {
        noblacklistSet.set(bRule.original, wRule.original); // ★
        blackMap.delete(wDomain);
      }
    }

    if (wRule.coverSub) {
      const suffix = `.${wDomain}`;
      for (const bDomain of [...blackMap.keys()]) {
        if (bDomain.endsWith(suffix)) {
          const bRule = blackMap.get(bDomain);
          if (canCover(wRule, bRule)) {
            noblacklistSet.set(bRule.original, wRule.original); // ★
            blackMap.delete(bDomain);
          }
        }
      }
    }
  }

  // 第 3 步：反向排除（被 important/dnsrewrite 黑名单压制的白名单）
  const suppressedWhite = new Map(); // ★ wDomain -> bRule
  for (const [wDomain, wRule] of whiteMap) {
    const bRule = blackMap.get(wDomain);
    if (!bRule) continue;
    if (!wRule.important && bRule.important) {
      suppressedWhite.set(wDomain, bRule); // ★
      continue;
    }
    if (!wRule.important && bRule.ip) {
      suppressedWhite.set(wDomain, bRule); // ★
      continue;
    }
  }

  for (const [d, bRule] of suppressedWhite) {
    const rule = whiteMap.get(d);
    if (rule) {
      nowhitelistSet.set(rule.original, bRule.original); // ★
      whiteMap.delete(d);
    }
  }

  console.log(
    `反向排除：被 important/dnsrewrite 黑名单压制的白名单 ${suppressedWhite.size} 条`,
  );

  // ============================================================
  // 第 4 步：$dnsrewrite 冲突检测
  // ============================================================
  const dnsRewriteConflictRules = [];

  for (const [wDomain, wRule] of whiteMap) {
    if (!wRule.coverSub || wRule.important || wRule.ip) continue;

    const suffix = `.${wDomain}`;
    for (const [bDomain, bRule] of blackMap) {
      if (!bDomain.endsWith(suffix)) continue;
      if (bRule.important || bRule.ip) {
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

  const { kept: normalBlackDomains, removed: normalBlackRemoved } =
    removeRedundantSubdomains(new Set(normalBlack.keys()));

  // ★ 被父域收敛的子域，记录为“被哪条父域规则覆盖”
  for (const [childDomain, parentDomain] of normalBlackRemoved) {
    const childRule = normalBlack.get(childDomain);
    const parentRule = normalBlack.get(parentDomain);
    if (!childRule) continue;
    noblacklistSet.set(
      childRule.original,
      parentRule ? parentRule.original : `(父域: ${parentDomain})`,
    );
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

  const { kept: normalWhiteDomains, removed: normalWhiteRemoved } =
    removeRedundantSubdomains(new Set(normalWhite.keys()));

  // ★ 被父域收敛的子域，记录为“被哪条父域规则覆盖”
  for (const [childDomain, parentDomain] of normalWhiteRemoved) {
    const childRule = normalWhite.get(childDomain);
    const parentRule = normalWhite.get(parentDomain);
    if (!childRule) continue;
    nowhitelistSet.set(
      childRule.original,
      parentRule ? parentRule.original : `(父域: ${parentDomain})`,
    );
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
  await writeCoveredMap(noblacklistWriter, noblacklistSet); // ★
  await writeCoveredMap(nowhitelistWriter, nowhitelistSet); // ★

  if (skippedWriter) await skippedWriter.close();
  if (duplicateWriter) await duplicateWriter.close();

  if (redundantWriter) {
    for (const line of [...redundantSet].sort()) {
      await redundantWriter.write(line);
    }
    await redundantWriter.close();
  }
  const redundantCount = redundantSet.size;

  // ============================================================
  // 第 8 步：输出产物（★ 用 pushLine 防御性 push）
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
    const line = formatRule(rule);
    if (!line) continue;
    pushLine(blackBuckets, rule, line);
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
    const line = formatRule(rule);
    if (!line) continue;
    pushLine(whiteBuckets, rule, line);
  }

  // 冲突规则也走 pushLine
  for (const conflict of dnsRewriteConflictRules) {
    const line = formatRule(conflict);
    if (line) pushLine(whiteBuckets, conflict, line);
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
    duplicateCount, // ★
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
      `duplicate ${stats.duplicateCount} 条，` +
      `redundant ${stats.redundantCount} 条`,
  );

  return stats;
};

module.exports = { buildAdGuardHomeLists };
