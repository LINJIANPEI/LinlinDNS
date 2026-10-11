const { Resolver } = require("node:dns/promises");
const fs = require("node:fs");
const path = require("node:path");
const { finished } = require("node:stream/promises");
const { readLines, LineWriter } = require("./stream_utils");

const CACHE_TTL = 3110400; // 36 天
const DEFAULT_CONCURRENCY = 500;
const DEFAULT_NAMESERVERS = ["127.0.0.1"];
const DEFAULT_PORT = 5053;
const DNS_TIMEOUT = 800;
const DEFAULT_CACHE_FILE = "./dns-cache.json";
const DEFAULT_PROGRESS_STEP = 1000;

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

// ============================================================
// Resolver 复用池
// ============================================================
const resolverCache = new Map();

const getResolver = (nameservers, port) => {
  const key = `${nameservers.join(",")}:${port}`;
  if (!resolverCache.has(key)) {
    const r = new Resolver();
    r.setServers(nameservers.map((ns) => `${ns}:${port}`));
    resolverCache.set(key, r);
  }
  return resolverCache.get(key);
};

// ============================================================
// 工具函数
// ============================================================
const isIPv4 = (s) => {
  const m = IPV4_RE.exec(s);
  if (!m) return false;
  return m.slice(1).every((p) => {
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
};

const isBlackholeIp = (ip) =>
  ip === "0.0.0.0" || ip.startsWith("127.") || ip === "::1";

const pLimit = (concurrency) => {
  let active = 0;
  const queue = [];
  const next = () => {
    active--;
    if (queue.length) queue.shift()();
  };
  return (fn) =>
    new Promise((resolve, reject) => {
      const run = () => {
        active++;
        Promise.resolve().then(fn).then(resolve, reject).finally(next);
      };
      if (active < concurrency) run();
      else queue.push(run);
    });
};

/**
 * 处理通配符域名。
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
 * 域名规范化（只做结构校验，无层级上限、无 TLD 校验）。
 */
const normalizeDomain = (value) => {
  const d = value.trim().toLowerCase().replace(/\.+$/, "").replace(/^\.+/, "");
  if (!d) return null;
  if (d === "localhost" || d === "localhost.localdomain") return null;
  if (d.includes(" ")) return null;
  if (!/^[a-z0-9.-]+$/.test(d)) return null;
  if (d.includes("..")) return null;
  if (isIPv4(d)) return null;

  const labels = d.split(".");
  if (labels.length < 2) return null;
  if (d.length > 253) return null;

  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return null;
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) return null;
  }

  return d;
};

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

/**
 * 解析规则 → { domain, isWhite, ip }
 *   ip 非空 → DNS 重写规则
 */
const parseRule = (line) => {
  if (typeof line !== "string") return null;
  const t = line.trim();
  if (!t) return null;
  if (t.startsWith("!")) return null;
  if (t.startsWith("#") && !EXTENDED_RULE_MARKERS.some((m) => t.startsWith(m)))
    return null;

  // IP 域名格式（hosts）
  const c0 = t.charCodeAt(0);
  if (c0 >= 48 && c0 <= 57 && t.includes(" ")) {
    const parts = t.split(/\s+/);
    if (parts.length === 2 && isIPv4(parts[0])) {
      let cand = parts[1];
      cand = stripWildcard(cand);
      if (cand === null) return null;
      const domain = normalizeDomain(cand);
      if (domain) {
        const blackhole = isBlackholeIp(parts[0]);
        return {
          domain,
          isWhite: !blackhole,
          ip: blackhole ? null : parts[0],
        };
      }
      return null;
    }
  }

  const isWhite = t.startsWith("@@");
  const body = isWhite ? t.slice(2) : t;

  // ||domain^ 或 |domain^
  if (body.startsWith("||") || body.startsWith("|")) {
    const isDouble = body.startsWith("||");
    let rest = body.slice(isDouble ? 2 : 1);
    rest = rest.replace(/^\^/, "");

    rest = stripWildcard(rest);
    if (rest === null) return null;

    const d = rest
      .split("^")[0]
      .split("/")[0]
      .split("$")[0]
      .toLowerCase()
      .replace(/\.+$/, "");
    const domain = normalizeDomain(d);
    if (!domain) return null;

    const dnsrewriteMatch = rest.match(/\$dnsrewrite=([^,;$]+)/i);
    return {
      domain,
      isWhite,
      ip: dnsrewriteMatch ? dnsrewriteMatch[1] : null,
    };
  }

  // 兜底：纯域名
  let tail = body.replace(/\^+$/, "").split("$")[0].split("/")[0];
  tail = stripWildcard(tail);
  if (tail === null) return null;
  const domain = normalizeDomain(tail);
  return domain ? { domain, isWhite, ip: null } : null;
};

// ============================================================
// DNS 查询：A 优先，失败兜底 AAAA
// ============================================================
const withTimeout = (promise, ms) => {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("DNS timeout")), ms);
    }),
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
};

const resolveHost = async (domain, nameservers, port) => {
  const resolver = getResolver(nameservers, port);

  // 1. 先查 A 记录
  try {
    const v4 = await withTimeout(resolver.resolve4(domain), DNS_TIMEOUT);
    const valid = v4.filter((ip) => ip !== "0.0.0.0");
    if (valid.length > 0) return valid;
  } catch {
    // A 失败 → 继续尝试 AAAA
  }

  // 2. A 失败后兜底查 AAAA
  try {
    const v6 = await withTimeout(resolver.resolve6(domain), DNS_TIMEOUT);
    return v6.filter((ip) => ip !== "::");
  } catch {
    return [];
  }
};

const checkDomain = async (domain, { nameservers, port }) => {
  return resolveHost(domain, nameservers, port);
};

// ============================================================
// 文件缓存（NDJSON 流式读写）
// ============================================================
const createNullCache = () => ({
  get() {
    return undefined;
  },
  set() {},
  async save() {},
  size() {
    return 0;
  },
});

const createFileCache = (filePath) => {
  const store = new Map();

  if (filePath && fs.existsSync(filePath)) {
    try {
      const raw = fs.readFileSync(filePath, "utf-8");
      const t = raw.trimStart();
      if (t.startsWith("{")) {
        const data = JSON.parse(raw);
        for (const k of Object.keys(data)) store.set(k, data[k]);
      } else {
        for (const line of raw.split("\n")) {
          if (!line) continue;
          try {
            const arr = JSON.parse(line);
            if (Array.isArray(arr) && arr.length === 2)
              store.set(arr[0], arr[1]);
          } catch {}
        }
      }
    } catch {}
  }

  return {
    get: (d) => store.get(d),
    set: (d, v) => store.set(d, v),
    async save() {
      if (!filePath) return;
      const dir = path.dirname(filePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const out = fs.createWriteStream(filePath);
      for (const [domain, value] of store) {
        if (!out.write(JSON.stringify([domain, value]) + "\n")) {
          await new Promise((r) => out.once("drain", r));
        }
      }
      out.end();
      await finished(out);
    },
    size() {
      return store.size;
    },
  };
};

// ============================================================
// 主函数
// ============================================================
const removeDeadRules = async (inputFiles, options) => {
  const {
    cleanedFile,
    nocleanedFile,
    passthroughFile,
    deadDomainsFile,
    deadWhitelistReportFile, // ★ 白名单死域名报告（只报告不删除）
    concurrency = DEFAULT_CONCURRENCY,
    nameservers = DEFAULT_NAMESERVERS,
    port = DEFAULT_PORT,
    whiteSet = new Set(),
    cache,
    cacheFile = DEFAULT_CACHE_FILE,
    // ★ 白名单不参与 DNS 检测，避免"白名单死了黑名单复活"
    keepWhiteRules = true,
    autoSaveCache = true,
    onProgress,
    progressStep = DEFAULT_PROGRESS_STEP,
  } = options;

  console.log("开始剔除死域名规则");

  const cacheStore =
    cache || (cacheFile ? createFileCache(cacheFile) : createNullCache());

  // ========================================================
  // 第 1 遍：提取域名
  // 三态标记：0=黑名单，1=白名单，2=重写
  // ========================================================
  const domainMap = new Map();
  const passthroughWriter = passthroughFile
    ? new LineWriter(passthroughFile)
    : null;
  let passthroughCount = 0;
  let totalRules = 0;
  let rewriteCount = 0;
  let whiteCount = 0;

  for (const file of inputFiles) {
    await readLines(file, async (raw) => {
      totalRules++;
      const parsed = parseRule(raw);
      if (!parsed) {
        if (passthroughWriter) await passthroughWriter.write(raw);
        passthroughCount++;
        return;
      }

      if (parsed.ip) rewriteCount++;
      else if (parsed.isWhite) whiteCount++;

      const flag = parsed.ip ? 2 : parsed.isWhite ? 1 : 0;
      const prev = domainMap.get(parsed.domain);

      if (prev === undefined) {
        domainMap.set(parsed.domain, flag);
      } else {
        // 优先级：重写(2) > 白(1) > 黑(0)
        if (flag > prev) domainMap.set(parsed.domain, flag);
      }
    });
  }

  if (passthroughWriter) await passthroughWriter.close();

  const total = domainMap.size;
  console.log(
    `规则解析完成，共${totalRules}条规则，提取${total}个域名（白 ${whiteCount}，重写 ${rewriteCount}）`,
  );

  // ========================================================
  // 第 2 遍：DNS 查询
  // ★ 白名单(flag=1) 跳过查询
  // ========================================================
  const limit = pLimit(concurrency);
  const now = Math.floor(Date.now() / 1000);
  let cacheHits = 0;
  let completed = 0;
  const startTime = Date.now();

  // ★ 需要查询的域名：只有黑名单(0) 和 重写(2)
  const domainsToCheck = [];
  const aliveSet = new Set();
  const skipWhiteSet = new Set();

  for (const [domain, flag] of domainMap) {
    if (flag === 1 && keepWhiteRules) {
      // 白名单：跳过 DNS 检测
      skipWhiteSet.add(domain);
      aliveSet.add(domain); // 视为存活，参与父域判断
    } else {
      domainsToCheck.push(domain);
    }
  }

  const totalToCheck = domainsToCheck.length;

  const report = (force = false) => {
    if (!force && completed % progressStep !== 0) return;
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const percent =
      totalToCheck > 0 ? ((completed / totalToCheck) * 100).toFixed(1) : "100.0";
    const speed = completed / Math.max(elapsed, 0.001);
    const remain =
      speed > 0 ? ((totalToCheck - completed) / speed).toFixed(0) : "?";
    console.log(
      `进度: ${completed}/${totalToCheck} (${percent}%) | 缓存命中: ${cacheHits} | 已用: ${elapsed}s | 预计剩余: ${remain}s`,
    );
    if (typeof onProgress === "function") {
      onProgress({
        completed,
        total: totalToCheck,
        cacheHits,
        elapsed: Number(elapsed),
        remain: Number(remain) || 0,
        percent: Number(percent),
      });
    }
  };

  const inflight = new Set();
  const MAX_INFLIGHT = concurrency * 4;

  for (const domain of domainsToCheck) {
    let p;
    p = limit(async () => {
      const cached = cacheStore.get(domain);
      let ipList;
      if (cached && now - cached.timeStamp <= CACHE_TTL) {
        ipList = cached.ipList;
        cacheHits++;
      } else {
        ipList = await checkDomain(domain, { nameservers, port });
        cacheStore.set(domain, { ipList, timeStamp: now });
      }
      if (ipList && ipList.length > 0) aliveSet.add(domain);
      completed++;
      report();
    }).finally(() => inflight.delete(p));
    inflight.add(p);
    if (inflight.size >= MAX_INFLIGHT) await Promise.race(inflight);
  }
  await Promise.all(inflight);
  report(true);

  const deadCount = aliveSet.size - skipWhiteSet.size;

  // ========================================================
  // 计算"死且无存活父域"的集合
  // ★ 白名单(keepWhiteRules=true) 跳过判定
  // ========================================================
  const deadWithoutAliveParent = new Set();
  const deadWhitelistSet = new Set(); // ★ 白名单死域名（只报告）
  let parentAliveCount = 0;

  for (const [domain, flag] of domainMap) {
    if (aliveSet.has(domain)) continue;

    // ★ 白名单跳过（keepWhiteRules=true 时永不进这里）
    if (keepWhiteRules && flag === 1) continue;
    if (keepWhiteRules && whiteSet.has(domain)) continue;

    const labels = domain.split(".");
    let parentAlive = false;
    for (let i = 1; i < labels.length; i++) {
      if (aliveSet.has(labels.slice(i).join("."))) {
        parentAlive = true;
        break;
      }
    }
    if (parentAlive) parentAliveCount++;
    else deadWithoutAliveParent.add(domain);
  }

  // ★ 额外收集：白名单里的死域名（只用于报告）
  for (const [domain, flag] of domainMap) {
    if (flag !== 1) continue;
    if (aliveSet.has(domain)) continue;
    // 白名单被视为"已跳过"，需要单独判定
    // 由于 keepWhiteRules=true 时白名单被加入了 aliveSet，这里不会命中
    // 只有 keepWhiteRules=false 时才可能命中
    deadWhitelistSet.add(domain);
  }

  domainMap.clear();

  // ========================================================
  // 第 3 遍：分类输出
  // ========================================================
  const cleanedWriter = new LineWriter(cleanedFile);
  const nocleanedWriter = nocleanedFile ? new LineWriter(nocleanedFile) : null;
  const deadWriter = deadDomainsFile ? new LineWriter(deadDomainsFile) : null;
  const deadWhitelistWriter = deadWhitelistReportFile
    ? new LineWriter(deadWhitelistReportFile)
    : null;

  if (deadWriter) {
    for (const d of deadWithoutAliveParent) await deadWriter.write(d);
    await deadWriter.close();
  }

  // ★ 输出白名单死域名报告（如果有）
  if (deadWhitelistWriter) {
    for (const d of [...deadWhitelistSet].sort()) {
      await deadWhitelistWriter.write(d);
    }
    await deadWhitelistWriter.close();
  }

  let cleanedCount = 0;
  let nocleanedCount = 0;
  let rewriteKept = 0;
  let rewriteDropped = 0;
  let whiteKept = 0;

  for (const file of inputFiles) {
    await readLines(file, async (raw) => {
      const parsed = parseRule(raw);
      if (!parsed) return;

      const isRewrite = !!parsed.ip;
      const isWhite = parsed.isWhite || whiteSet.has(parsed.domain);
      const isDead = deadWithoutAliveParent.has(parsed.domain);

      // 重写规则：走死亡判定
      if (isRewrite) {
        if (isDead) {
          if (nocleanedWriter) await nocleanedWriter.write(raw);
          nocleanedCount++;
          rewriteDropped++;
        } else {
          await cleanedWriter.write(raw);
          cleanedCount++;
          rewriteKept++;
        }
        return;
      }

      // ★ 白名单：无条件保留
      if (isWhite && keepWhiteRules) {
        await cleanedWriter.write(raw);
        cleanedCount++;
        whiteKept++;
        return;
      }

      // 白名单 + keepWhiteRules=false：走死亡判定
      if (isWhite) {
        if (isDead) {
          if (nocleanedWriter) await nocleanedWriter.write(raw);
          nocleanedCount++;
        } else {
          await cleanedWriter.write(raw);
          cleanedCount++;
          whiteKept++;
        }
        return;
      }

      // 黑名单：走死亡判定
      if (isDead) {
        if (nocleanedWriter) await nocleanedWriter.write(raw);
        nocleanedCount++;
      } else {
        await cleanedWriter.write(raw);
        cleanedCount++;
      }
    });
  }

  await cleanedWriter.close();
  if (nocleanedWriter) await nocleanedWriter.close();

  if (autoSaveCache && cacheStore.save) await cacheStore.save();

  const stats = {
    totalRules,
    totalDomains: total,
    queriedDomains: totalToCheck,
    skippedWhite: skipWhiteSet.size,
    aliveDomains: aliveSet.size - skipWhiteSet.size,
    deadDomains: deadCount,
    deadDomainsWithParentAlive: parentAliveCount,
    removedDomains: deadWithoutAliveParent.size,
    aliveRules: cleanedCount,
    deadRules: nocleanedCount,
    passthrough: passthroughCount,
    rewriteCount,
    rewriteKept,
    rewriteDropped,
    whiteKept,
    deadWhitelistReportCount: deadWhitelistSet.size,
    cacheHits,
    cacheSize: cacheStore.size ? cacheStore.size() : 0,
  };

  console.log(
    `剔除死域名规则完成 | 输入 ${totalRules} 条` +
      ` | 查询 ${totalToCheck} 个域名（跳过白名单 ${skipWhiteSet.size}）` +
      ` | 保留 ${cleanedCount} 条` +
      ` | 剔除 ${nocleanedCount} 条` +
      ` | 白名单（保留 ${whiteKept}）` +
      ` | 重写（保留 ${rewriteKept}，剔除 ${rewriteDropped}）` +
      ` | 丢弃非域名行 ${passthroughCount} 条` +
      ` | 死域名 ${deadCount} 个` +
      `（父域存活保留 ${parentAliveCount} 个，实际剔除 ${stats.removedDomains} 个）` +
      ` | 缓存命中 ${cacheHits} 次`,
  );

  return stats;
};

module.exports = { removeDeadRules, createFileCache };