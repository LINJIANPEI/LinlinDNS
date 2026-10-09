const path = require("node:path");
const { readLines, LineWriter } = require("./stream_utils");

const DOMAIN_RE =
  /^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

// DNS 层不支持的修饰符
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
  "$third-party",
  "$~third-party",
];

const hasUnsupportedModifier = (rule) =>
  DNS_UNSUPPORTED_MODIFIERS.some((m) => rule.includes(m));

/**
 * 从规则里提取域名。无法转换的返回 null。
 * 支持：
 *   ||domain^
 *   |domain^
 *   @@||domain^
 *   @@|domain^
 *   IP domain
 *   ||domain^$script（带不支持修饰符，但能提取 ||域名，黑名单保留）
 * 不支持（返回 null）：
 *   /regex/
 *   @@/regex/$domain=xxx（白名单语义会变，丢弃）
 *   @@||domain^$domain=xxx（白名单语义会变，丢弃）
 */
const extractDomain = (line) => {
  const isWhite = line.startsWith("@@");
  const body = isWhite ? line.slice(2) : line;

  // IP domain 格式
  const parts = line.split(/\s+/);
  if (parts.length === 2) {
    const hostIp = parts[0];
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostIp)) {
      const d = parts[1].toLowerCase().replace(/\.+$/, "");
      if (DOMAIN_RE.test(d)) {
        const isBlacklistIp = hostIp === "0.0.0.0" || hostIp.startsWith("127.");
        return { domain: d, isWhite: !isBlacklistIp };
      }
      return null;
    }
  }

  // 白名单带 $domain=：语义是"只在某站点放行"，DNS 层无法表达，丢弃
  if (isWhite && hasUnsupportedModifier(line)) {
    // 但 @@||domain^$important 这种是支持的，放行
    if (!line.includes("$important")) return null;
  }

  // ||domain^ 或 |domain^
  if (body.startsWith("||") || body.startsWith("|")) {
    const isDouble = body.startsWith("||");
    let rest = body.slice(isDouble ? 2 : 1);
    rest = rest.replace(/^\^/, "");
    const d = rest
      .split("^")[0]
      .split("/")[0]
      .toLowerCase()
      .replace(/\.+$/, "");
    if (d && DOMAIN_RE.test(d)) {
      return { domain: d, isWhite };
    }
  }

  // 纯域名（不带 || 和 @@）
  if (!body.includes("/") && !body.includes("$")) {
    const d = body.toLowerCase().replace(/\.+$/, "");
    if (DOMAIN_RE.test(d)) {
      return { domain: d, isWhite: false };
    }
  }

  return null;
};

const prepareDnsRules = async (inputFile, outDir) => {
  console.log("开始准备 DNS 兼容规则");

  const blackFile = path.join(outDir, "black.txt");
  const whiteFile = path.join(outDir, "white.txt");

  const blackWriter = new LineWriter(blackFile);
  const whiteWriter = new LineWriter(whiteFile);

  const seenBlack = new Set();
  const seenWhite = new Set();

  let total = 0;
  let blackCount = 0;
  let whiteCount = 0;
  let dropped = 0;

  await readLines(inputFile, async (line) => {
    const t = line.trim();
    if (!t) return;
    total++;

    const result = extractDomain(t);
    if (!result) {
      dropped++;
      return;
    }

    if (result.isWhite) {
      if (!seenWhite.has(result.domain)) {
        seenWhite.add(result.domain);
        await whiteWriter.write(`@@||${result.domain}^$important`);
        whiteCount++;
      }
    } else {
      if (!seenBlack.has(result.domain)) {
        seenBlack.add(result.domain);
        await blackWriter.write(`||${result.domain}^`);
        blackCount++;
      }
    }
  });

  await blackWriter.close();
  await whiteWriter.close();

  console.log(
    `DNS 兼容过滤完成：输入 ${total} 条 | 黑 ${blackCount} | 白 ${whiteCount} | 丢弃 ${dropped}`,
  );

  return { blackFile, whiteFile, blackCount, whiteCount, dropped };
};

module.exports = { prepareDnsRules };
