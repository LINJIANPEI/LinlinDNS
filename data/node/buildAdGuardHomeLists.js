const { readLines, LineWriter } = require("./stream_utils");
const { parseRule: parseRuleBase, hasDnsRewrite } = require("./rule_parser");

/**
 * ★ 包装 parseRule，返回完整字段。
 */
const parseRule = (line) =>
  parseRuleBase(line, {
    keepCoverSub: true,
    keepOriginal: true,
    keepIsHosts: true,
  });

/**
 * 判断白名单规则 wRule 能否覆盖黑名单规则 bRule。
 *
 * AdGuard Home 优先级（从高到低）：
 *   1. @@...$important   白名单 important
 *   2. ...$important     黑名单 important
 *   3. @@...             普通白名单
 *   4. ...               普通黑名单
 *
 * 覆盖范围：
 *   白的范围必须 ≥ 黑的范围
 *   - 白 coverSub=true  → 可覆盖任意黑
 *   - 白 coverSub=false → 只能覆盖 bRule.coverSub=false 的黑
 */
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
 * ★ 输出格式化：
 *   - rule.ip 存在        → $dnsrewrite 规则
 *   - hosts 格式黑名单    → |domain^       （精确匹配，与原意一致）
 *   - hosts 格式白名单    → @@|domain^     （精确匹配，与原意一致）
 *   - 其它                → 保留原始行
 */
const formatOutput = (rule) => {
  if (!rule) return null;

  if (rule.ip) {
    const anchor = rule.coverSub ? "||" : "|";
    return `${anchor}${rule.domain}^$dnsrewrite=${rule.ip}`;
  }

  if (rule.isHosts && !rule.isWhite) {
    return `|${rule.domain}^`;
  }

  if (rule.isHosts && rule.isWhite) {
    return `@@|${rule.domain}^`;
  }

  return rule.original;
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
      // ★ 直接使用 rule.important
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

  // ★ 拆黑名单为普通和 important（重写归入 important 级别）
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

  // ★ 白名单同理
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

  let rewriteOutCount = 0;

  const rulesWriter = new LineWriter(outRulesFile);
  for (const d of blackDomains) {
    const rule = getBlackRule(d);
    const line = formatOutput(rule);
    if (line) await rulesWriter.write(line);
  }
  await rulesWriter.close();

  const allowWriter = new LineWriter(outAllowFile);
  for (const d of whiteDomains) {
    const rule = getWhiteRule(d);
    const line = formatOutput(rule);
    if (line) {
      await allowWriter.write(line);
      if (rule && rule.ip) rewriteOutCount++;
    }
  }
  await allowWriter.close();

  const stats = {
    blacklistCount: blackDomains.length,
    whitelistCount: whiteDomains.length,
    dnsRewriteCount: rewriteOutCount,
    noblacklistCount: noblacklistSet.size,
    nowhitelistCount: nowhitelistSet.size,
    skippedCount,
    redundantCount,
  };

  console.log(
    `构建完成：黑名单 ${stats.blacklistCount} 条，` +
      `白名单 ${stats.whitelistCount} 条（含重写 ${stats.dnsRewriteCount}），` +
      `noblacklist ${stats.noblacklistCount} 条，` +
      `nowhitelist ${stats.nowhitelistCount} 条，` +
      `skipped ${stats.skippedCount} 条，` +
      `redundant ${stats.redundantCount} 条`,
  );

  return stats;
};

module.exports = { buildAdGuardHomeLists };
