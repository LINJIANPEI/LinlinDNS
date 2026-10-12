const path = require("node:path");
const { readDir } = require("./common_func");
const { readLines, LineWriter } = require("./stream_utils");
const { hasUnsupportedModifier, isPathRule } = require("./rule_parser");

const HTML_RE = /<\s*(html|head|body|div|a\s|script|style|!DOCTYPE|meta|link)/i;

const STATIC_FILE_RE =
  /\.(js|ts|css|html?|json|xml|txt|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|map|mp4|mp3|webm|m3u8)(\^|\$|$)/i;

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

const isIPv4 = (s) => {
  const m = IPV4_RE.exec(s);
  if (!m) return false;
  return m.slice(1).every((p) => {
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
};

const isHostsLine = (t) => {
  const parts = t.split(/\s+/);
  return parts.length === 2 && isIPv4(parts[0]);
};

const isBlackholeIp = (ip) =>
  ip === "0.0.0.0" || ip.startsWith("127.") || ip === "::1";

const isValidRuleLine = (t) => {
  if (!t) return false;
  if (t.length < 3) return false;
  if (t.length > 1024) return false;

  if (t.startsWith("!")) return false;
  if (t.startsWith("[")) return false;
  if (t.startsWith("#")) return false;

  if (HTML_RE.test(t)) return false;

  if (!t.includes(".") && !t.includes("/")) return false;

  if (isPathRule(t)) return false;
  if (hasUnsupportedModifier(t)) return false;
  if (STATIC_FILE_RE.test(t)) return false;

  return true;
};

/**
 * ★ 标准化一行规则。
 *
 *   ① 已带 @@|| / @@| / || / | / * → 保留
 *   ② 裸 @@ + 纯域名              → @@|domain^
 *   ③ hosts + 黑洞 IP             → |domain^          （进黑名单）
 *   ④ hosts + 公网 IP             → domain^$dnsrewrite=IP（无锚点，进白名单）
 *   ⑤ 纯域名                      → |domain^ 或 @@|domain^
 */
const normalizeLine = (line, isWhite) => {
  const t = line.trim();
  if (!t) return null;

  // ① 已带锚点 → 保留
  if (t.startsWith("@@||") || t.startsWith("@@|")) return t;
  if (t.startsWith("||") || t.startsWith("|")) return t;
  if (t.startsWith("*")) return t;   // ★ 保留 * 前缀

  // ② 裸 @@ + 纯域名 → @@|domain^
  if (t.startsWith("@@")) {
    const body = t.slice(2).trim();
    const domainPart = body.split("$")[0].split("/")[0].split("^")[0].trim();
    if (domainPart && /^[a-z0-9.-]+$/i.test(domainPart)) {
      const dollarIdx = body.indexOf("$");
      const suffix = dollarIdx !== -1 ? body.slice(dollarIdx) : "";
      return `@@|${domainPart}^${suffix}`;
    }
    return null;
  }

  // ③④ hosts 格式 → 按 IP 类型分流
  if (isHostsLine(t)) {
    const parts = t.split(/\s+/);
    const ip = parts[0];
    const domain = parts[1].toLowerCase().replace(/\.+$/, "");

    if (isBlackholeIp(ip)) {
      return `|${domain}^`;
    }
    return `${domain}^$dnsrewrite=${ip}`;
  }

  // ⑤ 纯域名 → 加 | 或 @@|
  const prefix = isWhite ? "@@" : "";
  const rawDomain = t.split("$")[0].split("/")[0].replace(/\^+$/, "").trim();
  if (rawDomain && /^[a-z0-9.-]+$/i.test(rawDomain)) {
    const dollarIdx = t.indexOf("$");
    const suffix = dollarIdx !== -1 ? t.slice(dollarIdx) : "";
    return `${prefix}|${rawDomain}^${suffix}`;
  }

  return null;
};

const mergeAll = async (directory, outputFile) => {
  console.log("开始合并所有规则（含去重 + 标准化）");
  try {
    const fileList = await readDir(directory);
    const allFiles = fileList
      .filter(
        (f) =>
          (f.startsWith("rules") || f.startsWith("allow")) &&
          f.endsWith(".txt"),
      )
      .filter((f) => !/\.part\d+\./.test(f))
      .sort();

    const writer = new LineWriter(outputFile);

    if (allFiles.length === 0) {
      console.log("没有找到规则文件");
      await writer.close();
      return { fileCount: 0, lineCount: 0, skipped: 0, duplicated: 0 };
    }

    const seen = new Set();
    let skipped = 0;
    let duplicated = 0;
    let written = 0;

    for (const file of allFiles) {
      const isWhiteFile = file.startsWith("allow");
      let fileWritten = 0;

      await readLines(path.join(directory, file), async (line) => {
        const t = line.trim();

        if (!isValidRuleLine(t)) {
          skipped++;
          return;
        }

        const normalized = normalizeLine(t, isWhiteFile);
        if (!normalized) {
          skipped++;
          return;
        }

        if (seen.has(normalized)) {
          duplicated++;
          return;
        }
        seen.add(normalized);

        await writer.write(normalized);
        written++;
        fileWritten++;
      });
      console.log(`  ${file}: 写入 ${fileWritten} 行`);
    }

    await writer.close();
    seen.clear();

    console.log(
      `合并完成：${allFiles.length} 个文件，` +
        `写入 ${written} 行，跳过 ${skipped} 行，去重 ${duplicated} 行`,
    );
    return {
      fileCount: allFiles.length,
      lineCount: written,
      skipped,
      duplicated,
    };
  } catch (error) {
    throw new Error(`合并失败: ${error.message}`);
  }
};

module.exports = { mergeAll };