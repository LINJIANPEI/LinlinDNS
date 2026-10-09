const path = require("node:path");
const { readLines, LineWriter } = require("./stream_utils");

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

// ---------- DNS 不兼容修饰符 ----------
const DNS_UNSUPPORTED_MODIFIERS = [
  "$xmlhttprequest",
  "$script",
  "$image",
  "$stylesheet",
  "$subdocument",
  "$document",
  "$font",
  "$media",
  "$object",
  "$ping",
  "$websocket",
  "$webrtc",
  "$other",
  "$popup",
  "$csp",
  "$removeparam",
  "$redirect",
  "$rewrite",
  "$cookie",
  "$header",
  "$replace",
  "$elemhide",
  "$generichide",
  "$genericblock",
  "$inline-script",
  "$inline-font",
  "$empty",
  "$mp4",
  "$app",
];

const hasUnsupportedModifier = (rule) =>
  DNS_UNSUPPORTED_MODIFIERS.some((m) => rule.includes(m));

/**
 * 从 URL 正则规则里提取域名，转成域名规则。
 * 支持：
 *   @@/xxx/*/yyy.js$script,domain=faselhd.cafe
 *   /xxx/*$xmlhttprequest,domain=example.com
 *   ||example.com^$script
 *   @@||example.com^$xmlhttprequest
 * 返回 { domain, isWhite } 或 null
 */
const extractDomainFromRule = (rule) => {
  const isWhite = rule.startsWith("@@");
  const body = isWhite ? rule.slice(2) : rule;

  // 1. 先从 $domain= 或 domain= 提取
  const domainMatch = body.match(/domain=([a-z0-9.,\-]+)/i);
  if (domainMatch && domainMatch[1]) {
    // domain= 可能有多个，逗号分隔，取第一个
    const first = domainMatch[1].split(",")[0].trim();
    // 去掉前导 ~
    const clean = first.replace(/^~/, "");
    if (clean && DOMAIN_RE.test(clean)) {
      return { domain: clean, isWhite };
    }
  }

  // 2. 从 ||domain^ 提取
  const pipeMatch = body.match(/^\|\|([a-z0-9.\-]+)\^?/i);
  if (pipeMatch && pipeMatch[1]) {
    const d = pipeMatch[1].toLowerCase().replace(/\.+$/, "");
    if (DOMAIN_RE.test(d)) {
      return { domain: d, isWhite };
    }
  }

  // 3. 从 URL 正则里尝试提取域名
  // 例如 /stream/*/*.ts  → 提取不到域名，返回 null
  // 例如 https://example.com/xxx → 提取 example.com
  const urlMatch = body.match(/(?:https?:\/\/)?([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)/i);
  if (urlMatch && urlMatch[1]) {
    const d = urlMatch[1].toLowerCase().replace(/\.+$/, "");
    if (DOMAIN_RE.test(d)) {
      return { domain: d, isWhite };
    }
  }

  return null;
};

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

// ---------- 主函数（流式版） ----------

/**
 * 从 cleaned.txt（+ 正则文件）生成 AdGuard Home 黑/白名单，直接写文件。
 *
 * @param {object} options
 * @param {string}  options.cleanedFile        - 输入：清理过死域名的规则文件
 * @param {string}  [options.regexBlackFile]   - 输入：正则黑名单文件
 * @param {string}  [options.regexWhiteFile]   - 输入：正则白名单文件
 * @param {string}  options.outRulesFile       - 输出：最终 rules.txt
 * @param {string}  options.outAllowFile       - 输出：最终 allow.txt
 * @param {string}  [options.outNoBlacklistFile]
 * @param {string}  [options.outNoWhitelistFile]
 * @param {string}  [options.outSkippedFile]
 *
 * @returns {Promise<{
 *   blacklistCount: number,
 *   whitelistCount: number,
 *   noblacklistCount: number,
 *   nowhitelistCount: number,
 *   skippedCount: number,
 *   regexBlackCount: number,
 *   regexWhiteCount: number,
 *   convertedBlackCount: number,
 *   convertedWhiteCount: number,
 *   droppedBlackCount: number,
 *   droppedWhiteCount: number
 * }>}
 */
const buildAdGuardHomeLists = async (options) => {
  const {
    cleanedFile,
    regexBlackFile,
    regexWhiteFile,
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

  // ---------- 准备 writer ----------
  const noblacklistWriter = outNoBlacklistFile
    ? new LineWriter(outNoBlacklistFile)
    : null;
  const nowhitelistWriter = outNoWhitelistFile
    ? new LineWriter(outNoWhitelistFile)
    : null;
  const skippedWriter = outSkippedFile ? new LineWriter(outSkippedFile) : null;

  // ---------- 收集过程 ----------
  const blackSet = new Set();
  const whiteSet = new Set();
  const noblacklistSet = new Set();
  const nowhitelistSet = new Set();

  // ★ 修复：补上 let 声明
  let skippedCount = 0;
  let noblacklistCount = 0;
  let nowhitelistCount = 0;

  // 用于跳过 cleanedFile 中重复出现的行
  const seenLines = new Set();

  // ---------- 流式读 cleanedFile ----------
  await readLines(cleanedFile, async (raw) => {
    // 1. 去注释；空行/注释进 skipped
    const line = uncomment(raw);
    if (!line) {
      if (skippedWriter) await skippedWriter.write(raw);
      skippedCount++;
      return;
    }

    // 2. 行级去重
    if (seenLines.has(line)) return;
    seenLines.add(line);

    // 3. 解析
    const rule = parseRule(line);
    if (!rule) {
      // 未识别的按 @@ 前缀归档
      if (line.startsWith("@@")) {
        if (!nowhitelistSet.has(line)) {
          nowhitelistSet.add(line);
          nowhitelistCount = nowhitelistSet.size;
        }
      } else {
        if (!noblacklistSet.has(line)) {
          noblacklistSet.add(line);
          noblacklistCount = noblacklistSet.size;
        }
      }
      return;
    }

    // 4. hostIp 合法性清洗
    if (!isValidFinalHost(rule)) {
      const target = rule.isWhite ? nowhitelistSet : noblacklistSet;
      if (!target.has(rule.original)) {
        target.add(rule.original);
        if (rule.isWhite) nowhitelistCount = nowhitelistSet.size;
        else noblacklistCount = noblacklistSet.size;
      }
      return;
    }

    // 5. 收集到 Set
    if (rule.isWhite) whiteSet.add(rule.domain);
    else blackSet.add(rule.domain);
  });

  // 释放 lineSet（不再需要）
  seenLines.clear();

  console.log(
    `clean 阶段解析完成：黑域名候选 ${blackSet.size}，白域名候选 ${whiteSet.size}`,
  );

  // ---------- 白名单覆盖黑名单 ----------
  for (const w of whiteSet) {
    if (blackSet.has(w)) {
      blackSet.delete(w);
      const entry = `||${w}^`;
      if (!noblacklistSet.has(entry)) {
        noblacklistSet.add(entry);
      }
    }
  }

  // ---------- 父域去冗余 ----------
  const blackDomains = removeRedundantSubdomains(blackSet);
  const whiteDomains = removeRedundantSubdomains(whiteSet);

  const blackKept = new Set(blackDomains);
  for (const d of blackSet) {
    if (!blackKept.has(d)) {
      const entry = `||${d}^`;
      if (!noblacklistSet.has(entry)) noblacklistSet.add(entry);
    }
  }

  const whiteKept = new Set(whiteDomains);
  for (const d of whiteSet) {
    if (!whiteKept.has(d)) {
      const entry = `@@||${d}^$important`;
      if (!nowhitelistSet.has(entry)) nowhitelistSet.add(entry);
    }
  }

  // 释放大 Set（后面只写文件了）
  blackSet.clear();
  whiteSet.clear();

  // ---------- 写 noblacklist / nowhitelist ----------
  if (noblacklistWriter) {
    const sorted = [...noblacklistSet].sort();
    for (const line of sorted) await noblacklistWriter.write(line);
    await noblacklistWriter.close();
  }

  if (nowhitelistWriter) {
    const sorted = [...nowhitelistSet].sort();
    for (const line of sorted) await nowhitelistWriter.write(line);
    await nowhitelistWriter.close();
  }

  if (skippedWriter) await skippedWriter.close();

  // ---------- 写最终 rules.txt ----------
  const rulesWriter = new LineWriter(outRulesFile);
  for (const d of blackDomains) {
    await rulesWriter.write(`||${d}^`);
  }

  let regexBlackCount = 0;
  let convertedBlackCount = 0;
  let droppedBlackCount = 0;

  if (regexBlackFile) {
    await readLines(regexBlackFile, async (line) => {
      const t = line.trim();
      if (!t) return;

      // ★ 带 DNS 不支持修饰符的规则，尝试转换
      if (hasUnsupportedModifier(t)) {
        const extracted = extractDomainFromRule(t);
        if (extracted && !extracted.isWhite) {
          await rulesWriter.write(`||${extracted.domain}^`);
          convertedBlackCount++;
        } else {
          droppedBlackCount++;
        }
        return;
      }

      // ★ 纯 URL 正则（无修饰符但 AdGuard Home 也不认），尝试提取域名
      if (/^(@@)?\//.test(t)) {
        const extracted = extractDomainFromRule(t);
        if (extracted && !extracted.isWhite) {
          await rulesWriter.write(`||${extracted.domain}^`);
          convertedBlackCount++;
        } else {
          droppedBlackCount++;
        }
        return;
      }

      await rulesWriter.write(t);
      regexBlackCount++;
    });
  }
  await rulesWriter.close();

  // ---------- 写最终 allow.txt ----------
  const allowWriter = new LineWriter(outAllowFile);
  for (const d of whiteDomains) {
    await allowWriter.write(`@@||${d}^$important`);
  }

  let regexWhiteCount = 0;
  let convertedWhiteCount = 0;
  let droppedWhiteCount = 0;

  if (regexWhiteFile) {
    await readLines(regexWhiteFile, async (line) => {
      const t = line.trim();
      if (!t) return;

      // ★ 带 DNS 不支持修饰符的规则，尝试转换
      if (hasUnsupportedModifier(t)) {
        const extracted = extractDomainFromRule(t);
        if (extracted && extracted.isWhite) {
          await allowWriter.write(`@@||${extracted.domain}^$important`);
          convertedWhiteCount++;
        } else {
          droppedWhiteCount++;
        }
        return;
      }

      // ★ 纯 URL 正则，尝试提取域名
      if (/^(@@)?\//.test(t)) {
        const extracted = extractDomainFromRule(t);
        if (extracted && extracted.isWhite) {
          await allowWriter.write(`@@||${extracted.domain}^$important`);
          convertedWhiteCount++;
        } else {
          droppedWhiteCount++;
        }
        return;
      }

      await allowWriter.write(t);
      regexWhiteCount++;
    });
  }
  await allowWriter.close();

  const stats = {
    blacklistCount: blackDomains.length,
    whitelistCount: whiteDomains.length,
    noblacklistCount: noblacklistSet.size,
    nowhitelistCount: nowhitelistSet.size,
    skippedCount,
    regexBlackCount,
    regexWhiteCount,
    convertedBlackCount,
    convertedWhiteCount,
    droppedBlackCount,
    droppedWhiteCount,
  };

  console.log(
    `构建完成：黑名单 ${stats.blacklistCount} 条，` +
      `白名单 ${stats.whitelistCount} 条，` +
      `noblacklist ${stats.noblacklistCount} 条，` +
      `nowhitelist ${stats.nowhitelistCount} 条，` +
      `skipped ${stats.skippedCount} 条，` +
      `正则黑 ${stats.regexBlackCount} 条，` +
      `正则白 ${stats.regexWhiteCount} 条，` +
      `转换黑 ${stats.convertedBlackCount} 条，` +
      `转换白 ${stats.convertedWhiteCount} 条，` +
      `丢弃黑 ${stats.droppedBlackCount} 条，` +
      `丢弃白 ${stats.droppedWhiteCount} 条`,
  );

  return stats;
};

module.exports = { buildAdGuardHomeLists };