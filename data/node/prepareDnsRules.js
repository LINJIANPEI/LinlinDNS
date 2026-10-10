const path = require("node:path");
const { readLines, LineWriter } = require("./stream_utils");

const DOMAIN_RE =
  /^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

// DNS 层不支持的修饰符
const DNS_UNSUPPORTED_MODIFIERS = [
  "$xmlhttprequest", "$script", "$image", "$stylesheet", "$subdocument",
  "$document", "$font", "$media", "$object", "$ping", "$websocket",
  "$webrtc", "$other", "$popup", "$csp", "$removeparam", "$redirect",
  "$rewrite", "$cookie", "$header", "$replace", "$elemhide", "$generichide",
  "$genericblock", "$inline-script", "$inline-font", "$empty", "$mp4", "$app",
  "$third-party", "$~third-party",
  "$stealth", "$~domain", "$first-party", "$~first-party",
];

// DNS 层支持的修饰符
const DNS_SUPPORTED_MODIFIERS = [
  "$important",
  "$badfilter",
  "$dnsrewrite",
  "$dnstype",
];

const hasUnsupportedModifier = (rule) =>
  DNS_UNSUPPORTED_MODIFIERS.some((m) => {
    if (m === "$domain") return /\$domain=/.test(rule);
    const re = new RegExp(
      m.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?=[,$]|$)",
    );
    return re.test(rule);
  });

const hasSupportedModifier = (rule) =>
  DNS_SUPPORTED_MODIFIERS.some((m) => {
    const re = new RegExp(
      m.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?=[,$]|$)",
    );
    return re.test(rule);
  });

// ★ 判断是否主机名正则（不是 URL 路径正则）
const isHostnameRegex = (rule) => {
  const m = rule.match(/^(@@)?\/(.+)\/([^/]*)$/);
  if (!m) return false;
  const regexBody = m[2];
  const modifiers = m[3];

  // 未转义的 /，是 URL 路径正则
  if (/(?<!\\)\//.test(regexBody)) return false;
  // 转义的 \/，也是 URL 路径
  if (/\\\//.test(regexBody)) return false;
  // 含 : 或 ?，是 URL 相关
  if (/[:?]/.test(regexBody)) return false;
  // 修饰符检查
  if (modifiers && !hasSupportedModifier(modifiers)) return false;

  return true;
};

/**
 * 从规则里提取域名。无法转换的返回 null。
 */
const extractDomain = (line) => {
  const t = line.trim();
  if (!t) return null;
  if (/#[@$%?]?#/.test(t)) return null;

  const isWhite = t.startsWith("@@");
  const body = isWhite ? t.slice(2) : t;

  // hosts 格式
  const parts = t.split(/\s+/);
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

  if (hasUnsupportedModifier(t)) return null;

  if (body.startsWith("||") || body.startsWith("|")) {
    const isDouble = body.startsWith("||");
    let rest = body.slice(isDouble ? 2 : 1);
    rest = rest.replace(/^\^/, "");

    const domainPart = rest
      .split(/[\^/$]/)[0]
      .toLowerCase()
      .replace(/\.+$/, "");
    if (!domainPart || !DOMAIN_RE.test(domainPart)) return null;

    const afterDomain = rest.slice(domainPart.length);
    if (afterDomain.startsWith("/")) return null;
    if (afterDomain.startsWith("?")) return null;
    if (
      afterDomain &&
      !afterDomain.startsWith("^") &&
      !afterDomain.startsWith("$")
    ) {
      return null;
    }
    if (afterDomain.startsWith("$") && !hasSupportedModifier(afterDomain)) {
      return null;
    }

    return { domain: domainPart, isWhite };
  }

  if (!body.includes("/") && !body.includes("$") && !body.includes("^")) {
    const d = body.toLowerCase().replace(/\.+$/, "");
    if (DOMAIN_RE.test(d)) return { domain: d, isWhite: false };
  }

  return null;
};

const prepareDnsRules = async (inputFile, outDir) => {
  console.log("开始准备 DNS 兼容规则");

  const blackFile = path.join(outDir, "black.txt");
  const whiteFile = path.join(outDir, "white.txt");

  const blackWriter = new LineWriter(blackFile);
  const whiteWriter = new LineWriter(whiteFile);

  // 普通规则：domain → original
  const seenBlack = new Map();
  const seenWhite = new Map();

  // ★ 正则规则：直接存原始行
  const regexBlack = new Set();
  const regexWhite = new Set();

  let total = 0;
  let dropped = 0;

  await readLines(inputFile, async (line) => {
    const t = line.trim();
    if (!t) return;
    total++;

    // ★ 正则规则优先判断
    if (/^(@@)?\//.test(t)) {
      if (isHostnameRegex(t)) {
        if (t.startsWith("@@")) regexWhite.add(t);
        else regexBlack.add(t);
      } else {
        dropped++;
      }
      return;
    }

    const result = extractDomain(t);
    if (!result) {
      dropped++;
      return;
    }

    const map = result.isWhite ? seenWhite : seenBlack;
    if (!map.has(result.domain)) {
      map.set(result.domain, t);
    }
  });

  // 输出：普通规则 + 正则规则
  for (const original of seenBlack.values()) await blackWriter.write(original);
  for (const regex of regexBlack) await blackWriter.write(regex);

  for (const original of seenWhite.values()) await whiteWriter.write(original);
  for (const regex of regexWhite) await whiteWriter.write(regex);

  await blackWriter.close();
  await whiteWriter.close();

  console.log(
    `DNS 兼容过滤完成：输入 ${total} 条 | ` +
      `黑 ${seenBlack.size + regexBlack.size}（含正则 ${regexBlack.size}） | ` +
      `白 ${seenWhite.size + regexWhite.size}（含正则 ${regexWhite.size}） | ` +
      `丢弃 ${dropped}`,
  );

  return {
    blackFile,
    whiteFile,
    blackCount: seenBlack.size + regexBlack.size,
    whiteCount: seenWhite.size + regexWhite.size,
    dropped,
  };
};

module.exports = { prepareDnsRules };