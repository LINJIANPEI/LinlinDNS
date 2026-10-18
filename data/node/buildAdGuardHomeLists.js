const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const { readLines, LineWriter } = require("./stream_utils");
const { parseRule, formatRule, hasDnsRewrite } = require("./rule_parser");

const SHARD_COUNT = 128;

const hashStr = (s) => {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  }
  return h >>> 0;
};

function canCover(wRule, bRule, prioritySet) {
  const wP = prioritySet.has(wRule.original);
  const bP = prioritySet.has(bRule.original);

  if (wP) return true;
  if (bP) return false;

  if (wRule.important) return true;
  if (bRule.important) return false;
  if (hasDnsRewrite(bRule.original)) return false;
  if (!wRule.coverSub && bRule.coverSub) return false;
  return true;
}

function removeRedundantSubdomains(domainRuleMap, prioritySet, protectedSet) {
  const ordinary = new Map();
  const wildcards = [];

  for (const [d, rule] of domainRuleMap) {
    if (d.startsWith("*.")) wildcards.push(d);
    else ordinary.set(d, rule);
  }

  const sorted = [...ordinary.keys()].sort((a, b) => {
    const da = (a.match(/\./g) || []).length;
    const db = (b.match(/\./g) || []).length;
    if (da !== db) return da - db;
    return a < b ? -1 : a > b ? 1 : 0;
  });

  const kept = [];
  const removed = new Map();

  for (const domain of sorted) {
    const rule = ordinary.get(domain);

    if (prioritySet.has(rule.original)) {
      kept.push(domain);
      continue;
    }
    // ★ 被 $denyallow 保护的子域不删
    if (protectedSet && protectedSet.has(domain)) {
      kept.push(domain);
      continue;
    }

    let redundant = false;
    let idx = domain.indexOf(".");
    while (idx !== -1) {
      const parent = domain.slice(idx + 1);
      const parentRule = ordinary.get(parent);
      if (parentRule && parentRule.coverSub) {
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

const countBuckets = (buckets, keys) => {
  let n = 0;
  for (const k of keys) n += buckets[k] ? buckets[k].length : 0;
  return n;
};

const writeBuckets = async (writer, buckets) => {
  for (const key of BUCKET_KEYS) {
    const lines = buckets[key];
    if (!lines || lines.length === 0) {
      buckets[key] = null;
      continue;
    }
    lines.sort();
    for (const line of lines) {
      await writer.write(line);
    }
    buckets[key] = null;
  }
};

const externalSortCovered = (tmpPath, outPath) => {
  if (!tmpPath || !outPath) return;
  if (!fs.existsSync(tmpPath)) {
    fs.writeFileSync(outPath, "");
    return;
  }
  execFileSync(
    "bash",
    ["-c", `awk -F' ' '!seen[$1]++' "$1" | sort > "$2"`, "_", tmpPath, outPath],
    { stdio: "inherit" },
  );
  fs.unlinkSync(tmpPath);
};

const isBlockRewrite = (ip) => {
  if (!ip) return false;
  if (ip.includes(";")) return false;
  const first = ip.split(",")[0].trim().toLowerCase();
  if (
    first === "0.0.0.0" ||
    first.startsWith("127.") ||
    first === "::1" ||
    first === "0:0:0:0:0:0:0:1"
  ) {
    return true;
  }
  return /^(noerror|nxdomain|refused|servfail)$/i.test(first);
};

/** 获取域名的所有父域后缀（不含自身） */
const getSuffixes = (domain) => {
  const suffixes = [];
  let idx = domain.indexOf(".");
  while (idx !== -1) {
    suffixes.push(domain.slice(idx + 1));
    idx = domain.indexOf(".", idx + 1);
  }
  return suffixes;
};

/**
 * 给规则的 original 追加或合并 $denyallow 修饰符
 * - 多个值用 | 分隔
 * - 已有 $denyallow 则合并
 */
const appendDenyallow = (original, children) => {
  const dollarIdx = original.indexOf("$");
  const childList = [...new Set(children)].sort();

  if (dollarIdx === -1) {
    return `${original}$denyallow=${childList.join("|")}`;
  }

  const head = original.slice(0, dollarIdx);
  const suffix = original.slice(dollarIdx + 1);
  const parts = suffix.split(",");

  const denyallowIdx = parts.findIndex((p) =>
    p.trim().toLowerCase().startsWith("denyallow="),
  );
  if (denyallowIdx !== -1) {
    const existingVal = parts[denyallowIdx].trim().slice("denyallow=".length);
    const existingList = existingVal.split("|").filter(Boolean);
    const merged = [...new Set([...existingList, ...childList])].sort();
    parts[denyallowIdx] = `denyallow=${merged.join("|")}`;
    return `${head}$${parts.join(",")}`;
  }

  return `${head}$${suffix},denyallow=${childList.join("|")}`;
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
    priorityFile = null,
    priorityProtectFile = null,
  } = options;

  if (!cleanedFile) throw new TypeError("cleanedFile 必填");
  if (!outRulesFile) throw new TypeError("outRulesFile 必填");
  if (!outAllowFile) throw new TypeError("outAllowFile 必填");

  console.log("开始构建 AdGuard Home 列表");

  const prioritySet = new Set();
  if (priorityFile && fs.existsSync(priorityFile)) {
    await readLines(priorityFile, (line) => {
      const t = line.trim();
      if (t) prioritySet.add(t);
    });
    console.log(`强制规则（priorityFile）：${prioritySet.size} 条`);
  }

  const priorityProtectWriter = priorityProtectFile
    ? new LineWriter(priorityProtectFile)
    : null;

  const noblacklistTmp = outNoBlacklistFile
    ? `${outNoBlacklistFile}.tmp`
    : null;
  const nowhitelistTmp = outNoWhitelistFile
    ? `${outNoWhitelistFile}.tmp`
    : null;

  const noblacklistWriter = noblacklistTmp
    ? new LineWriter(noblacklistTmp)
    : null;
  const nowhitelistWriter = nowhitelistTmp
    ? new LineWriter(nowhitelistTmp)
    : null;

  let noblacklistCount = 0;
  let nowhitelistCount = 0;

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

  const seenShards = Array.from({ length: SHARD_COUNT }, () => new Set());

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

    const shard = seenShards[hashStr(line) % SHARD_COUNT];
    if (shard.has(line)) {
      if (duplicateWriter) await duplicateWriter.write(raw);
      duplicateCount++;
      return;
    }
    shard.add(line);

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
    } else if (
      prioritySet.has(rule.original) &&
      !prioritySet.has(existing.original)
    ) {
      if (redundantWriter) await redundantWriter.write(existing.original);
      redundantCount++;
      map.set(rule.domain, rule);
    } else if (
      !prioritySet.has(rule.original) &&
      prioritySet.has(existing.original)
    ) {
      if (redundantWriter) await redundantWriter.write(rule.original);
      redundantCount++;
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

  for (let i = 0; i < SHARD_COUNT; i++) seenShards[i].clear();
  if (redundantWriter) await redundantWriter.close();

  console.log(
    `解析完成：黑域名候选 ${blackMap.size}，白域名候选 ${whiteMap.size}` +
      (duplicateCount > 0 ? `，重复行 ${duplicateCount}` : "") +
      (redundantCount > 0 ? `，冗余行 ${redundantCount}` : ""),
  );

  // ============================================================
  // 第 1.5 步：★ 先解决同域冲突
  // - priority 黑 + 非 priority 白 → 保留黑名单（保护自定义规则）
  // - 其他情况 → 白名单覆盖黑名单
  // ============================================================
  console.log("开始同域冲突解决...");

  const sameDomainDeleteBlack = [];
  let sameDomainPriorityProtected = 0;
  for (const [bDomain, bRule] of blackMap) {
    const wRule = whiteMap.get(bDomain);
    if (!wRule) continue;

    const bP = prioritySet.has(bRule.original);
    const wP = prioritySet.has(wRule.original);

    if (bP && !wP) {
      sameDomainPriorityProtected++;
      if (priorityProtectWriter) {
        await priorityProtectWriter.write(
          `[同域-保护] ${bRule.original}（priority 黑保留）✕ ${wRule.original}`,
        );
      }
      continue;
    }

    sameDomainDeleteBlack.push(bDomain);
    if (priorityProtectWriter) {
      await priorityProtectWriter.write(
        `[同域-覆盖] ${bRule.original} 被白名单覆盖（删除黑名单）✕ ${wRule.original}`,
      );
    }
  }
  for (const d of sameDomainDeleteBlack) {
    const rule = blackMap.get(d);
    if (rule) {
      if (noblacklistWriter) await noblacklistWriter.write(rule.original);
      blackMap.delete(d);
      noblacklistCount++;
    }
  }
  console.log(
    `同域冲突解决完成：删除黑名单 ${sameDomainDeleteBlack.length} 个，` +
      `保护 priority 黑 ${sameDomainPriorityProtected} 个`,
  );

  // ============================================================
  // 第 1.6 步：★ $denyallow 原意转换（所有规则，无 priority 限制）
  // - 白父域 + 黑子域 → 白父域加 $denyallow=黑子域，黑子域保留
  // - 黑父域 + 白子域 → 黑父域加 $denyallow=白子域，白子域保留
  // ============================================================
  console.log("开始 $denyallow 原意转换（所有规则）...");

  const denyallowParentWhite = new Map(); // 白父域 → Set<黑子域>
  const denyallowParentBlack = new Map(); // 黑父域 → Set<白子域>
  const denyallowProtectedBlack = new Set(); // 被保护的黑子域
  const denyallowProtectedWhite = new Set(); // 被保护的白子域

  // 场景 A：白父域 + 黑子域
  for (const [bDomain, bRule] of blackMap) {
    if (!bRule.coverSub || bRule.ip) continue;
    // 遍历所有父域后缀，不 break（每个匹配的白父域都加）
    for (const suffix of getSuffixes(bDomain)) {
      const w = whiteMap.get(suffix);
      if (w && w.coverSub && !w.ip) {
        if (!denyallowParentWhite.has(suffix)) {
          denyallowParentWhite.set(suffix, new Set());
        }
        denyallowParentWhite.get(suffix).add(bDomain);
        denyallowProtectedBlack.add(bDomain);
      }
    }
  }

  // 场景 B：黑父域 + 白子域
  for (const [wDomain, wRule] of whiteMap) {
    if (!wRule.coverSub || wRule.ip) continue;
    for (const suffix of getSuffixes(wDomain)) {
      const b = blackMap.get(suffix);
      if (b && b.coverSub && !b.ip) {
        if (!denyallowParentBlack.has(suffix)) {
          denyallowParentBlack.set(suffix, new Set());
        }
        denyallowParentBlack.get(suffix).add(wDomain);
        denyallowProtectedWhite.add(wDomain);
      }
    }
  }

  // 应用：白父域加 $denyallow
  let denyallowWhiteCount = 0;
  for (const [parentDomain, childSet] of denyallowParentWhite) {
    const wRule = whiteMap.get(parentDomain);
    if (!wRule) continue;
    const childList = [...childSet].sort();
    const oldOriginal = wRule.original;
    wRule.original = appendDenyallow(oldOriginal, childList);
    denyallowWhiteCount++;
    if (prioritySet.has(oldOriginal)) {
      prioritySet.delete(oldOriginal);
      prioritySet.add(wRule.original);
    }
    if (priorityProtectWriter) {
      await priorityProtectWriter.write(
        `[$denyallow-A] @@${parentDomain} 加 denyallow=[${childList.join("|")}]（放行大部分，拦截子域）`,
      );
    }
  }

  // 应用：黑父域加 $denyallow
  let denyallowBlackCount = 0;
  for (const [parentDomain, childSet] of denyallowParentBlack) {
    const bRule = blackMap.get(parentDomain);
    if (!bRule) continue;
    const childList = [...childSet].sort();
    const oldOriginal = bRule.original;
    bRule.original = appendDenyallow(oldOriginal, childList);
    denyallowBlackCount++;
    if (prioritySet.has(oldOriginal)) {
      prioritySet.delete(oldOriginal);
      prioritySet.add(bRule.original);
    }
    if (priorityProtectWriter) {
      await priorityProtectWriter.write(
        `[$denyallow-B] ||${parentDomain} 加 denyallow=[${childList.join("|")}]（拦截大部分，放行子域）`,
      );
    }
  }

  console.log(
    `$denyallow 原意转换完成：白父域 ${denyallowWhiteCount} 条，` +
      `黑父域 ${denyallowBlackCount} 条，` +
      `保护黑子域 ${denyallowProtectedBlack.size} 个，` +
      `保护白子域 ${denyallowProtectedWhite.size} 个`,
  );

  // ============================================================
  // 第 2 步：白名单覆盖黑名单（跳过被 $denyallow 保护的黑子域）
  // ============================================================
  console.log("开始白名单覆盖黑名单...");
  const toDeleteBlack = [];
  let step2Progress = 0;
  let priorityProtected = 0;

  for (const [bDomain, bRule] of blackMap) {
    if (bRule.important) {
      priorityProtected++;
      step2Progress++;
      continue;
    }
    // ★ 跳过被 $denyallow 保护的黑子域
    if (denyallowProtectedBlack.has(bDomain)) {
      step2Progress++;
      continue;
    }

    const wExact = whiteMap.get(bDomain);
    if (wExact && canCover(wExact, bRule, prioritySet)) {
      if (noblacklistWriter) {
        await noblacklistWriter.write(
          `${bRule.original}  ->  ${wExact.original}`,
        );
        noblacklistCount++;
      }
      toDeleteBlack.push(bDomain);
      continue;
    }

    let idx = bDomain.indexOf(".");
    let matched = false;
    while (idx !== -1) {
      const parent = bDomain.slice(idx + 1);
      const w = whiteMap.get(parent);
      if (w && w.coverSub && canCover(w, bRule, prioritySet)) {
        if (noblacklistWriter) {
          await noblacklistWriter.write(`${bRule.original}  ->  ${w.original}`);
          noblacklistCount++;
        }
        matched = true;
        break;
      }
      idx = bDomain.indexOf(".", idx + 1);
    }
    if (matched) toDeleteBlack.push(bDomain);

    step2Progress++;
    if (step2Progress % 500000 === 0) {
      console.log(`  白名单覆盖进度: ${step2Progress}/${blackMap.size}`);
    }
  }

  for (const d of toDeleteBlack) blackMap.delete(d);
  toDeleteBlack.length = 0;
  console.log(
    `白名单覆盖黑名单完成：移除 ${noblacklistCount} 条` +
      (priorityProtected > 0
        ? `，保护 important 黑名单 ${priorityProtected} 条`
        : ""),
  );

  // ============================================================
  // 第 3 步：反向排除（跳过被 $denyallow 保护的白子域）
  // ============================================================
  let suppressedWhiteCount = 0;
  let whitePriorityProtected = 0;
  const toDeleteWhite = [];
  for (const [wDomain, wRule] of whiteMap) {
    if (wRule.important) {
      whitePriorityProtected++;
      continue;
    }
    // ★ 跳过被 $denyallow 保护的白子域
    if (denyallowProtectedWhite.has(wDomain)) {
      whitePriorityProtected++;
      continue;
    }

    const bRule = blackMap.get(wDomain);
    if (!bRule) continue;

    if (bRule.important || prioritySet.has(bRule.original)) {
      whitePriorityProtected++;
      continue;
    }

    if (!wRule.important && (bRule.important || bRule.ip)) {
      if (nowhitelistWriter) {
        await nowhitelistWriter.write(
          `${wRule.original}  ->  ${bRule.original}`,
        );
        nowhitelistCount++;
      }
      toDeleteWhite.push(wDomain);
      suppressedWhiteCount++;
    }
  }
  for (const d of toDeleteWhite) whiteMap.delete(d);
  toDeleteWhite.length = 0;

  console.log(
    `反向排除：被 important/dnsrewrite 黑名单压制的白名单 ${suppressedWhiteCount} 条` +
      (whitePriorityProtected > 0
        ? `，保护 important 白名单 ${whitePriorityProtected} 条`
        : ""),
  );

  // ============================================================
  // 第 4 步：$dnsrewrite 冲突检测
  // ============================================================
  console.log("开始 $dnsrewrite 冲突检测...");
  const conflictRules = [];
  let dnsRewriteConflictCount = 0;

  for (const [bDomain, bRule] of blackMap) {
    if (!bRule.important && !bRule.ip) continue;

    let idx = bDomain.indexOf(".");
    while (idx !== -1) {
      const parent = bDomain.slice(idx + 1);
      const w = whiteMap.get(parent);
      if (w && w.coverSub && !w.important && !w.ip) {
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
        conflictRules.push(conflict);
        dnsRewriteConflictCount++;
        break;
      }
      idx = bDomain.indexOf(".", idx + 1);
    }
  }

  if (dnsRewriteConflictCount > 0) {
    console.log(
      `$dnsrewrite 冲突：${dnsRewriteConflictCount} 条子域需强制重写`,
    );
  }

  // ============================================================
  // 第 5 步：拆黑名单（跳过被 $denyallow 保护的黑子域）
  // ============================================================
  console.log("开始拆黑名单...");
  const normalBlack = new Map();
  const importantBlack = new Map();
  for (const [d, rule] of blackMap) {
    if (rule.important || rule.ip) importantBlack.set(d, rule);
    else normalBlack.set(d, rule);
  }
  blackMap.clear();

  const { kept: normalBlackDomains, removed: normalBlackRemoved } =
    removeRedundantSubdomains(
      normalBlack,
      prioritySet,
      denyallowProtectedBlack,
    );

  for (const [childDomain, parentDomain] of normalBlackRemoved) {
    const childRule = normalBlack.get(childDomain);
    const parentRule = normalBlack.get(parentDomain);
    if (!childRule) continue;
    if (noblacklistWriter) {
      await noblacklistWriter.write(
        `${childRule.original}  ->  ${
          parentRule ? parentRule.original : `(父域: ${parentDomain})`
        }`,
      );
      noblacklistCount++;
    }
  }
  normalBlackRemoved.clear();

  const importantBlackDomains = [...importantBlack.keys()];
  const blackDomains = [
    ...new Set([...normalBlackDomains, ...importantBlackDomains]),
  ].sort();

  // ============================================================
  // 第 6 步：拆白名单（跳过被 $denyallow 保护的白子域）
  // ============================================================
  console.log("开始拆白名单...");
  const normalWhite = new Map();
  const importantWhite = new Map();
  for (const [d, rule] of whiteMap) {
    if (rule.important || rule.ip) importantWhite.set(d, rule);
    else normalWhite.set(d, rule);
  }
  whiteMap.clear();

  const { kept: normalWhiteDomains, removed: normalWhiteRemoved } =
    removeRedundantSubdomains(
      normalWhite,
      prioritySet,
      denyallowProtectedWhite,
    );

  for (const [childDomain, parentDomain] of normalWhiteRemoved) {
    const childRule = normalWhite.get(childDomain);
    const parentRule = normalWhite.get(parentDomain);
    if (!childRule) continue;
    if (nowhitelistWriter) {
      await nowhitelistWriter.write(
        `${childRule.original}  ->  ${
          parentRule ? parentRule.original : `(父域: ${parentDomain})`
        }`,
      );
      nowhitelistCount++;
    }
  }
  normalWhiteRemoved.clear();

  const importantWhiteDomains = [...importantWhite.keys()];
  const whiteDomains = [
    ...new Set([...normalWhiteDomains, ...importantWhiteDomains]),
  ].sort();

  const getBlackRule = (d) => normalBlack.get(d) || importantBlack.get(d);
  const getWhiteRule = (d) => normalWhite.get(d) || importantWhite.get(d);

  // ============================================================
  // 第 7 步：关闭 writer + 外部排序
  // ============================================================
  console.log("开始外部排序归档文件...");
  if (noblacklistWriter) await noblacklistWriter.close();
  if (nowhitelistWriter) await nowhitelistWriter.close();
  if (priorityProtectWriter) await priorityProtectWriter.close();

  externalSortCovered(noblacklistTmp, outNoBlacklistFile);
  externalSortCovered(nowhitelistTmp, outNoWhitelistFile);

  if (skippedWriter) await skippedWriter.close();
  if (duplicateWriter) await duplicateWriter.close();

  // ============================================================
  // 第 8 步：输出产物
  // ============================================================
  console.log("开始输出产物...");
  const blackBuckets = newBuckets();
  const whiteBuckets = newBuckets();

  const rewriteByDomain = new Map();

  for (const conflict of conflictRules) {
    const line = formatRule(conflict);
    if (line) rewriteByDomain.set(conflict.domain, { rule: conflict, line });
  }

  const collectRewrite = (d, rule) => {
    if (prioritySet.has(rule.original)) {
      const line = formatRule(rule);
      if (line) rewriteByDomain.set(d, { rule, line });
      return;
    }
    const line = formatRule(rule);
    if (!line) return;
    const existing = rewriteByDomain.get(d);
    if (!existing) {
      rewriteByDomain.set(d, { rule, line });
      return;
    }
    if (isBlockRewrite(existing.rule.ip) && !isBlockRewrite(rule.ip)) {
      rewriteByDomain.set(d, { rule, line });
    }
  };

  for (const d of blackDomains) {
    const rule = getBlackRule(d);
    if (rule.ip) collectRewrite(d, rule);
  }
  for (const d of whiteDomains) {
    const rule = getWhiteRule(d);
    if (rule.ip) collectRewrite(d, rule);
  }

  // ★ 普通黑名单（含加了 $denyallow 的黑父域）
  for (const d of blackDomains) {
    const rule = getBlackRule(d);
    if (rule.ip) continue;
    const line = formatRule(rule);
    if (!line) continue;
    pushLine(blackBuckets, rule, line);
  }

  const rulesWriter = new LineWriter(outRulesFile);
  await writeBuckets(rulesWriter, blackBuckets);
  await rulesWriter.close();

  // ★ 普通白名单（含加了 $denyallow 的白父域 + 被保护的白子域）
  for (const d of whiteDomains) {
    const rule = getWhiteRule(d);
    if (rule.ip) continue;
    const line = formatRule(rule);
    if (!line) continue;
    pushLine(whiteBuckets, rule, line);
  }

  let rewriteFromBlackCount = 0;
  for (const { rule, line } of rewriteByDomain.values()) {
    pushLine(whiteBuckets, rule, line);
    if (!rule.isWhite) rewriteFromBlackCount++;
  }

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
    blacklistCount: blackDomains.length - rewriteFromBlackCount,
    whitelistCount:
      whiteDomains.length + dnsRewriteConflictCount + rewriteFromBlackCount,
    dnsRewriteCount: rewriteOutCount,
    noblacklistCount,
    nowhitelistCount,
    suppressedWhiteCount,
    dnsRewriteConflictCount,
    skippedCount,
    duplicateCount,
    redundantCount,
    rewriteFromBlackCount,
    rewriteUniqueCount: rewriteByDomain.size,
    priorityCount: prioritySet.size,
    priorityProtected,
    whitePriorityProtected,
    sameDomainDeleteBlack: sameDomainDeleteBlack.length,
    sameDomainPriorityProtected,
    denyallowWhiteCount,
    denyallowBlackCount,
    denyallowProtectedBlack: denyallowProtectedBlack.size,
    denyallowProtectedWhite: denyallowProtectedWhite.size,
    priorityProtectFile,
  };

  console.log(
    `构建完成：黑名单 ${stats.blacklistCount} 条，` +
      `白名单 ${stats.whitelistCount} 条` +
      `（含重写 ${stats.dnsRewriteCount}，` +
      `冲突重写 ${stats.dnsRewriteConflictCount}），` +
      `强制规则 ${stats.priorityCount} 条，` +
      `同域处理：删黑 ${stats.sameDomainDeleteBlack}，保护 priority 黑 ${stats.sameDomainPriorityProtected}，` +
      `$denyallow：白父 ${stats.denyallowWhiteCount}，黑父 ${stats.denyallowBlackCount}，` +
      `保护黑子 ${stats.denyallowProtectedBlack}，保护白子 ${stats.denyallowProtectedWhite}，` +
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
