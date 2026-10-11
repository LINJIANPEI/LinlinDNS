const path = require("node:path");
const { readLines, LineWriter } = require("./stream_utils");

const DOMAIN_RE =
  /^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

/**
 * ★ 处理通配符域名。
 * - *.domain.com → 剥离 *. → 'domain.com'
 * - ad*banner   → 含非前缀 * → 返回 null
 */
const stripWildcard = (domain) => {
  let d = domain;
  if (d.startsWith("*.")) d = d.slice(2);
  if (d.includes("*")) return null;
  return d;
};

/**
 * 从规则里提取域名。无法转换的返回 null。
 */
const extractDomain = (line) => {
  const isWhite = line.startsWith("@@");
  const body = isWhite ? line.slice(2) : line;

  // hosts 格式：0.0.0.0 example.com / 127.0.0.1 example.com
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

  // ||domain^ 或 |domain^
  if (body.startsWith("||") || body.startsWith("|")) {
    const isDouble = body.startsWith("||");
    let rest = body.slice(isDouble ? 2 : 1);
    rest = rest.replace(/^\^/, "");

    // ★ 先处理通配符
    rest = stripWildcard(rest);
    if (rest === null) return null;

    // 带路径的丢
    const beforeMod = rest.split("$")[0];
    const core = beforeMod.split("^")[0];
    if (core.includes("/")) return null;

    const d = core.toLowerCase().replace(/\.+$/, "");
    if (d && DOMAIN_RE.test(d)) {
      return { domain: d, isWhite };
    }
  }

  // 纯域名
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

  // domain → 原始行
  const seenBlack = new Map();
  const seenWhite = new Map();

  let total = 0;
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

    const map = result.isWhite ? seenWhite : seenBlack;
    if (!map.has(result.domain)) {
      map.set(result.domain, t); // ★ 保留原始行
    }
  });

  for (const original of seenBlack.values()) {
    await blackWriter.write(original);
  }
  for (const original of seenWhite.values()) {
    await whiteWriter.write(original);
  }

  await blackWriter.close();
  await whiteWriter.close();

  console.log(
    `DNS 兼容过滤完成：输入 ${total} 条 | 黑 ${seenBlack.size} | 白 ${seenWhite.size} | 丢弃 ${dropped}`,
  );

  return {
    blackFile,
    whiteFile,
    blackCount: seenBlack.size,
    whiteCount: seenWhite.size,
    dropped,
  };
};

module.exports = { prepareDnsRules };
