const path = require("node:path");
const { readLines, LineWriter } = require("./stream_utils");

// ★ 把原来的所有辅助函数原样贴在这里：
// DOMAIN_RE, EXTENDED_RULE_MARKERS, isIPv4, isIPv6, isIP, ipToBigIntV4,
// isBlacklistHostIp, isGlobalV4, isGlobalV6, isGlobalIp,
// normalizeDomain, uncomment, parseRule, isValidFinalHost,
// removeRedundantSubdomains
// （以上全部与原来保持一致，此处省略以节省篇幅）

/**
 * 流式版本：从 cleaned.txt + 正则文件生成最终 rules.txt / allow.txt。
 */
const buildAdGuardHomeListsFromFile = async (options) => {
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

  console.log("开始构建 AdGuard Home 列表");

  const blackSet = new Set();
  const whiteSet = new Set();

  const noblacklistWriter = outNoBlacklistFile
    ? new LineWriter(outNoBlacklistFile)
    : null;
  const nowhitelistWriter = outNoWhitelistFile
    ? new LineWriter(outNoWhitelistFile)
    : null;
  const skippedWriter = outSkippedFile ? new LineWriter(outSkippedFile) : null;

  // ---------- 流式读 cleaned.txt，收集黑/白域名 ----------
  await readLines(cleanedFile, async (raw) => {
    const line = uncomment(raw);
    if (!line) {
      if (skippedWriter) await skippedWriter.write(raw);
      return;
    }
    const rule = parseRule(line);
    if (!rule) {
      if (line.startsWith("@@")) {
        if (nowhitelistWriter) await nowhitelistWriter.write(line);
      } else {
        if (noblacklistWriter) await noblacklistWriter.write(line);
      }
      return;
    }
    if (!isValidFinalHost(rule)) {
      if (rule.isWhite) {
        if (nowhitelistWriter) await nowhitelistWriter.write(rule.original);
      } else {
        if (noblacklistWriter) await noblacklistWriter.write(rule.original);
      }
      return;
    }
    if (rule.isWhite) whiteSet.add(rule.domain);
    else blackSet.add(rule.domain);
  });

  // ---------- 白名单覆盖黑名单 ----------
  for (const w of whiteSet) {
    if (blackSet.has(w)) {
      blackSet.delete(w);
      if (noblacklistWriter) await noblacklistWriter.write(`||${w}^`);
    }
  }

  // ---------- 父域去冗余 ----------
  const blackDomains = removeRedundantSubdomains(blackSet);
  const whiteDomains = removeRedundantSubdomains(whiteSet);

  const blackKept = new Set(blackDomains);
  for (const d of blackSet) {
    if (!blackKept.has(d) && noblacklistWriter)
      await noblacklistWriter.write(`||${d}^`);
  }
  const whiteKept = new Set(whiteDomains);
  for (const d of whiteSet) {
    if (!whiteKept.has(d) && nowhitelistWriter)
      await nowhitelistWriter.write(`@@||${d}^$important`);
  }

  // ---------- 写最终 rules.txt ----------
  const rulesWriter = new LineWriter(outRulesFile);
  for (const d of blackDomains) await rulesWriter.write(`||${d}^`);
  if (regexBlackFile) {
    await readLines(regexBlackFile, async (line) => {
      const t = line.trim();
      if (t) await rulesWriter.write(t);
    });
  }
  await rulesWriter.close();

  // ---------- 写最终 allow.txt ----------
  const allowWriter = new LineWriter(outAllowFile);
  for (const d of whiteDomains) await allowWriter.write(`@@||${d}^$important`);
  if (regexWhiteFile) {
    await readLines(regexWhiteFile, async (line) => {
      const t = line.trim();
      if (t) await allowWriter.write(t);
    });
  }
  await allowWriter.close();

  if (noblacklistWriter) await noblacklistWriter.close();
  if (nowhitelistWriter) await nowhitelistWriter.close();
  if (skippedWriter) await skippedWriter.close();

  console.log(
    `构建完成：黑名单 ${blackDomains.length} 条，白名单 ${whiteDomains.length} 条`,
  );

  return { blacklist: blackDomains, whitelist: whiteDomains };
};

module.exports = { buildAdGuardHomeLists: buildAdGuardHomeListsFromFile };
