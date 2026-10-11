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
 * 判断是否为黑洞 IP（视为拦截）。
 */
const isBlackholeIp = (ip) =>
  ip === "0.0.0.0" ||
  ip.startsWith("127.") ||
  ip === "::1";

/**
 * 从规则里提取域名。
 * @returns { domain, isWhite, ip } | null
 *   ip 非空 → 该规则是 DNS 重写（$dnsrewrite）
 *   ip 为空 → 普通黑/白名单
 */
const extractDomain = (line) => {
  const isWhite = line.startsWith("@@");
  const body = isWhite ? line.slice(2) : line;

  // hosts 格式：0.0.0.0 example.com / 192.0.80.242 cdn.com / 0.0.0.0 *.domain.com
  const parts = line.split(/\s+/);
  if (parts.length === 2) {
    const hostIp = parts[0];
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostIp)) {
      let cand = parts[1].toLowerCase().replace(/\.+$/, "");
      cand = stripWildcard(cand);
      if (cand === null) return null;

      if (DOMAIN_RE.test(cand)) {
        const blackhole = isBlackholeIp(hostIp);
        return {
          domain: cand,
          isWhite: !blackhole,
          ip: blackhole ? null : hostIp,   // ★ 非黑洞 IP 记录，作 dnsrewrite
        };
      }
      return null;
    }
  }

  // ||domain^ 或 |domain^
  if (body.startsWith("||") || body.startsWith("|")) {
    const isDouble = body.startsWith("||");
    let rest = body.slice(isDouble ? 2 : 1);
    rest = rest.replace(/^\^/, "");

    rest = stripWildcard(rest);
    if (rest === null) return null;

    const beforeMod = rest.split("$")[0];
    const core = beforeMod.split("^")[0];
    if (core.includes("/")) return null;

    const d = core.toLowerCase().replace(/\.+$/, "");
    if (d && DOMAIN_RE.test(d)) {
      // 检查 $dnsrewrite 修饰符
      const dnsrewriteMatch = rest.match(/\$dnsrewrite=([^,;$]+)/i);
      return {
        domain: d,
        isWhite,
        ip: dnsrewriteMatch ? dnsrewriteMatch[1] : null,
      };
    }
  }

  // 纯域名（含 *.domain.com）
  if (!body.includes("/") && !body.includes("$")) {
    let d = body.toLowerCase().replace(/\.+$/, "");
    d = stripWildcard(d);
    if (d === null) return null;

    if (DOMAIN_RE.test(d)) {
      return { domain: d, isWhite, ip: null };
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

  const seenBlack = new Map();
  const seenWhite = new Map();

  let total = 0;
  let dropped = 0;
  let rewriteCount = 0;

  await readLines(inputFile, async (line) => {
    const t = line.trim();
    if (!t) return;
    total++;

    const result = extractDomain(t);
    if (!result) {
      dropped++;
      return;
    }

    if (result.ip) rewriteCount++;

    const map = result.isWhite ? seenWhite : seenBlack;
    if (!map.has(result.domain)) {
      map.set(result.domain, t);
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
    `DNS 兼容过滤完成：输入 ${total} 条 | 黑 ${seenBlack.size} | 白 ${seenWhite.size}（含重写 ${rewriteCount}）| 丢弃 ${dropped}`,
  );

  return {
    blackFile,
    whiteFile,
    blackCount: seenBlack.size,
    whiteCount: seenWhite.size,
    rewriteCount,
    dropped,
  };
};

module.exports = { prepareDnsRules };