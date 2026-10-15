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
  const removed = new Map();
  for (const domain of sorted) {
    let redundant = false;
    let idx = domain.indexOf(".");
    while (idx !== -1) {
      const parent = domain.slice(idx + 1);
      if (ordinary.has(parent)) {
        redundant = true;
        removed.set(domain, parent);
        break;
      }
      idx = domain.indexOf(".", idx + 1);
    }
    if (!redundant) kept.push(domain);
  }
  return { kept: [...kept, ...wildcards].sort(), removed };
}

const classifyRule = (rule) => {
  if (rule.ip) {
    if (rule.anchor === "star") return "rewriteStar";
    if (rule.anchor === "bare") return "rewriteBare";
    if (rule.anchor === "sub")
      return rule.isWhite ? "rewriteWhiteSub" : "rewriteBlackSub";
    return rule.isWhite ? "rewriteWhiteExact" : "rewriteBlackExact";
  }
  if (rule.anchor === "star") return "sub";
  if (rule.anchor === "sub") return "sub";
  if (rule.anchor === "exact") return "exact";
  if (rule.anchor === "bare") return "exact";
  return "other";
};

const pushLine = (buckets, rule, line) => {
  const key = classifyRule(rule);
  if (!buckets[key]) {
    console.warn(`⚠️ 未知 bucket key: ${key}，规则：${line}`);
    buckets[key] = [];
  }
  buckets[key].push(line);
};

const BUCKET_KEYS = [
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
];

const newBuckets = () => ({
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
});

/** 统计指定 key 的行数（在 writeBuckets 之前调用） */
const countBuckets = (buckets, keys) => {
  let n = 0;
  for (const k of keys) n += buckets[k] ? buckets[k].length : 0;
  return n;
};

const writeBuckets = async (writer, buckets) => {
  for (const key of BUCKET_KEYS) {
    const lines = buckets[key];
    if (!lines || lines.length === 0) {
      buckets[key] = null; // ★ 立即释放
      continue;
    }
    lines.sort();
    for (const line of lines) {
      await writer.write(line);
    }
    buckets[key] = null; // ★ 写完立即释放
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
    outDuplicateFile,
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
  const duplicateWriter = outDuplicateFile
    ? new LineWriter(outDuplicateFile)
    : null;

  const blackMap = new Map();
  const whiteMap = new Map();

  let skippedCount = 0;
  let duplicateCount = 0;
  let redundantCount = 0;
  const seenLines = new Set();

  // ============================================================
  // 第 1 步：解析
  // ★ 冗余行直接流式写入 redundantWriter，不再用 Set 缓冲
  // ============================================================
  await readLines(cleanedFile, async (raw) => {
    const line = raw.trim();
    if (!line) {
      if (skippedWriter) await skippedWriter.write(raw);
      skippedCount++;
      return;
    }
    if (seenLines.has(line)) {
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
    } else if (rule.ip && !existing.ip) {
      if (redundantWriter) await redundantWriter.write(existing.original);
      redundantCount++;
      map.set(rule.domain, rule);
    } else if (!rule.ip && existing.ip) {
      if (redundantWriter) await redundantWriter.write(rule.original);
      redundantCount++;
    } else if (rule.important && !existing.important) {
      if (redundantWriter) await redundantWriter.write(existing.original);
      redundantCount++;
      map.set(rule.domain, rule);
    } else if (
      rule.important === existing.important &&
      rule.coverSub &&
      !existing.coverSub
    ) {
      if (redundantWriter) await redundantWriter.write(existing.original);
      redundantCount++;
      map.set(rule.domain, rule);
    } else {
      if (redundantWriter) await redundantWriter.write(rule.original);
      redundantCount++;
    }
  });

  seenLines.clear();
  if (redundantWriter) await redundantWriter.close();

  console.log(
    `解析完成：黑域名候选 ${blackMap.size}，白域名候选 ${whiteMap.size}` +
      (duplicateCount > 0 ? `，重复行 ${duplicateCount}` : "") +
      (redundantCount > 0 ? `，冗余行 ${redundantCount}` : ""),
  );

  // ★ 被覆盖规则 -> 覆盖者
  const noblacklistSet = new Map();
  const nowhitelistSet = new Map();

  // ============================================================
  // 第 2 步：白名单覆盖黑名单
  // ★ 用 toDelete 数组批量删除，避免 [...blackMap.keys()] 大数组复制
  // ============================================================
  for (const [wDomain, wRule] of whiteMap) {
    if (blackMap.has(wDomain)) {
      const bRule = blackMap.get(wDomain);
      if (canCover(wRule, bRule)) {
        noblacklistSet.set(bRule.original, wRule.original);
        blackMap.delete(wDomain);
      }
    }

    if (wRule.coverSub) {
      const suffix = `.${wDomain}`;
      const toDelete = [];
      // ★ 直接迭代 Map.keys()，不创建数组副本
      for (const bDomain of blackMap.keys()) {
        if (bDomain.endsWith(suffix)) {
          const bRule = blackMap.get(bDomain);
          if (canCover(wRule, bRule)) {
            noblacklistSet.set(bRule.original, wRule.original);
            toDelete.push(bDomain);
          }
        }
      }
      for (const d of toDelete) blackMap.delete(d);
    }
  }

  // ============================================================
  // 第 3 步：反向排除（被 important/dnsrewrite 黑名单压制的白名单）
  // ★ 去掉 suppressedWhite 中间 Map，边遍历边删
  // ============================================================
  let suppressedWhiteCount = 0;
  for (const [wDomain, wRule] of whiteMap) {
    const bRule = blackMap.get(wDomain);
    if (!bRule) continue;
    if (!wRule.important && (bRule.important || bRule.ip)) {
      nowhitelistSet.set(wRule.original, bRule.original);
      whiteMap.delete(wDomain); // ★ Map 遍历中删当前项是安全的
      suppressedWhiteCount++;
    }
  }

  console.log(
    `反向排除：被 important/dnsrewrite 黑名单压制的白名单 ${suppressedWhiteCount} 条`,
  );

  // ============================================================
  // 第 4 步：$dnsrewrite 冲突检测
  // ★ 直接在循环里 push 到 whiteBuckets，不保留 dnsRewriteConflictRules 数组
  // ============================================================
  const whiteBuckets = newBuckets();
  let dnsRewriteConflictCount = 0;

  for (const [wDomain, wRule] of whiteMap) {
    if (!wRule.coverSub || wRule.important || wRule.ip) continue;
    const suffix = `.${wDomain}`;
    for (const [bDomain, bRule] of blackMap) {
      if (!bDomain.endsWith(suffix)) continue;
      if (bRule.important || bRule.ip) {
        const conflict = {
          domain: bDomain,
          isWhite: false,
          anchor: bRule.coverSub ? "star" : "bare",
          ip: "0.0.0.0",
          coverSub: bRule.coverSub,
          isHosts: false,
          important: false,
          original: "",
        };
        const line = formatRule(conflict);
        if (line) pushLine(whiteBuckets, conflict, line);
        dnsRewriteConflictCount++;
      }
    }
  }

  if (dnsRewriteConflictCount > 0) {
    console.log(
      `$dnsrewrite 冲突：${dnsRewriteConflictCount} 条子域需强制重写`,
    );
  }

  // ============================================================
  // 第 5 步：拆黑名单
  // ★ 拆完后立即 blackMap.clear()，避免双份驻留
  // ============================================================
  const normalBlack = new Map();
  const importantBlack = new Map();
  for (const [d, rule] of blackMap) {
    if (rule.important || rule.ip) importantBlack.set(d, rule);
    else normalBlack.set(d, rule);
  }
  blackMap.clear(); // ★ 释放原 Map

  const { kept: normalBlackDomains, removed: normalBlackRemoved } =
    removeRedundantSubdomains(new Set(normalBlack.keys()));

  for (const [childDomain, parentDomain] of normalBlackRemoved) {
    const childRule = normalBlack.get(childDomain);
    const parentRule = normalBlack.get(parentDomain);
    if (!childRule) continue;
    noblacklistSet.set(
      childRule.original,
      parentRule ? parentRule.original : `(父域: ${parentDomain})`,
    );
  }
  normalBlackRemoved.clear(); // ★

  const importantBlackDomains = [...importantBlack.keys()];
  const blackDomains = [
    ...new Set([...normalBlackDomains, ...importantBlackDomains]),
  ].sort();

  // ============================================================
  // 第 6 步：拆白名单
  // ============================================================
  const normalWhite = new Map();
  const importantWhite = new Map();
  for (const [d, rule] of whiteMap) {
    if (rule.important || rule.ip) importantWhite.set(d, rule);
    else normalWhite.set(d, rule);
  }
  whiteMap.clear(); // ★ 释放原 Map

  const { kept: normalWhiteDomains, removed: normalWhiteRemoved } =
    removeRedundantSubdomains(new Set(normalWhite.keys()));

  for (const [childDomain, parentDomain] of normalWhiteRemoved) {
    const childRule = normalWhite.get(childDomain);
    const parentRule = normalWhite.get(parentDomain);
    if (!childRule) continue;
    nowhitelistSet.set(
      childRule.original,
      parentRule ? parentRule.original : `(父域: ${parentDomain})`,
    );
  }
  normalWhiteRemoved.clear(); // ★

  const importantWhiteDomains = [...importantWhite.keys()];
  const whiteDomains = [
    ...new Set([...normalWhiteDomains, ...importantWhiteDomains]),
  ].sort();

  // ★ blackMap/whiteMap 已 clear，只需查拆分后的子 Map
  const getBlackRule = (d) => normalBlack.get(d) || importantBlack.get(d);
  const getWhiteRule = (d) => normalWhite.get(d) || importantWhite.get(d);

  // ============================================================
  // 第 7 步：写归档
  // ============================================================
  await writeCoveredMap(noblacklistWriter, noblacklistSet);
  await writeCoveredMap(nowhitelistWriter, nowhitelistSet);

  if (skippedWriter) await skippedWriter.close();
  if (duplicateWriter) await duplicateWriter.close();

  // ============================================================
  // 第 8 步：输出产物
  // ============================================================
  const blackBuckets = newBuckets();
  for (const d of blackDomains) {
    const rule = getBlackRule(d);
    const line = formatRule(rule);
    if (!line) continue;
    pushLine(blackBuckets, rule, line);
  }

  const rulesWriter = new LineWriter(outRulesFile);
  await writeBuckets(rulesWriter, blackBuckets);
  await rulesWriter.close();

  // ★ 白名单普通规则（冲突规则已在第 4 步 push 进 whiteBuckets）
  for (const d of whiteDomains) {
    const rule = getWhiteRule(d);
    const line = formatRule(rule);
    if (!line) continue;
    pushLine(whiteBuckets, rule, line);
  }

  // ★ 统计必须在 writeBuckets 之前（后者会把 bucket 置 null）
  const rewriteOutCount = countBuckets(whiteBuckets, [
    "rewriteBlackExact",
    "rewriteBlackSub",
    "rewriteWhiteExact",
    "rewriteWhiteSub",
    "rewriteStar",
    "rewriteBare",
  ]);

  const allowWriter = new LineWriter(outAllowFile);
  await writeBuckets(allowWriter, whiteBuckets);
  await allowWriter.close();

  const stats = {
    blacklistCount: blackDomains.length,
    whitelistCount: whiteDomains.length + dnsRewriteConflictCount,
    dnsRewriteCount: rewriteOutCount,
    noblacklistCount: noblacklistSet.size,
    nowhitelistCount: nowhitelistSet.size,
    suppressedWhiteCount,
    dnsRewriteConflictCount,
    skippedCount,
    duplicateCount,
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
