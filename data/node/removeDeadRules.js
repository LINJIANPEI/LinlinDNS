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

const DOMAIN_RE =
  /^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
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

const normalizeDomain = (value) => {
  const d = value.trim().toLowerCase().replace(/\.+$/, "").replace(/^\.+/, "");
  if (!d) return null;
  if (d === "localhost" || d === "localhost.localdomain") return null;
  if (isIPv4(d)) return null;
  if (!DOMAIN_RE.test(d)) return null;

  // ★ 新增预过滤
  const labels = d.split(".");

  // 1. 域名层级：超过 5 层基本都是假域名
  if (labels.length > 5) return null;

  // 2. 总长度：超过 80 字符的域名基本不存在
  if (d.length > 80) return null;

  // 3. TLD 长度：超过 24 字符的 TLD 不存在
  const tld = labels[labels.length - 1];
  if (tld.length > 24) return null;

  // 4. TLD 必须是字母，不能是数字
  if (!/^[a-z]+$/.test(tld)) return null;

  // 5. 过滤掉常见静态文件后缀被误当 TLD 的情况
  const FAKE_TLDS = new Set([
    "js",
    "ts",
    "css",
    "html",
    "htm",
    "json",
    "xml",
    "txt",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "ico",
    "woff",
    "woff2",
    "ttf",
    "eot",
    "otf",
    "map",
    "mp4",
    "mp3",
    "webm",
    "m3u8",
    "php",
    "asp",
    "aspx",
    "jsp",
    "cgi",
    "do",
    "action",
  ]);
  if (FAKE_TLDS.has(tld)) return null;

  // 6. 每一层标签长度不能超过 63
  for (const label of labels) {
    if (label.length > 63) return null;
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

const parseRule = (line) => {
  if (typeof line !== "string") return null;
  const t = line.trim();
  if (!t) return null;
  if (t.startsWith("!")) return null;
  if (t.startsWith("#") && !EXTENDED_RULE_MARKERS.some((m) => t.startsWith(m)))
    return null;

  // IP 域名格式
  const c0 = t.charCodeAt(0);
  if (c0 >= 48 && c0 <= 57 && t.includes(" ")) {
    const parts = t.split(/\s+/);
    if (parts.length === 2 && isIPv4(parts[0])) {
      const domain = normalizeDomain(parts[1]);
      if (domain) {
        const isWhite = !(
          parts[0] === "0.0.0.0" || parts[0].startsWith("127.")
        );
        return { domain, isWhite };
      }
      return null;
    }
  }

  const isWhite = t.startsWith("@@");
  const body = isWhite ? t.slice(2) : t;

  // ★ 同时支持 || 和 |，切 ^ / $
  if (body.startsWith("||") || body.startsWith("|")) {
    const isDouble = body.startsWith("||");
    let rest = body.slice(isDouble ? 2 : 1);
    rest = rest.replace(/^\^/, "");
    const d = rest
      .split("^")[0]
      .split("/")[0]
      .split("$")[0]
      .toLowerCase()
      .replace(/\.+$/, "");
    const domain = normalizeDomain(d);
    return domain ? { domain, isWhite } : null;
  }

  // ★ 兜底也切 $ 和 /
  const domain = normalizeDomain(
    t.replace(/\^+$/, "").split("$")[0].split("/")[0],
  );
  return domain ? { domain, isWhite } : null;
};
// ============================================================
// DNS 查询
// ============================================================
const resolveA = async (domain, nameservers, port) => {
  const resolver = getResolver(nameservers, port);
  let timer;
  try {
    const records = await Promise.race([
      resolver.resolve4(domain),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("DNS timeout")), DNS_TIMEOUT);
      }),
    ]);
    return records.filter((ip) => ip !== "0.0.0.0");
  } catch {
    return [];
  } finally {
    if (timer) clearTimeout(timer);
  }
};

const checkDomain = async (domain, { nameservers, port }) => {
  return resolveA(domain, nameservers, port);
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
        // 兼容旧 JSON 格式
        const data = JSON.parse(raw);
        for (const k of Object.keys(data)) store.set(k, data[k]);
      } else {
        // NDJSON
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
/**
 * 流式剔除死域名。
 *
 * @param {string[]} inputFiles - 输入规则文件路径（可以有多个）
 * @param {object} options
 * @param {string} options.cleanedFile
 * @param {string} [options.nocleanedFile]
 * @param {string} [options.passthroughFile]
 * @param {string} [options.deadDomainsFile]
 */
const removeDeadRules = async (inputFiles, options) => {
  const {
    cleanedFile,
    nocleanedFile,
    passthroughFile,
    deadDomainsFile,
    concurrency = DEFAULT_CONCURRENCY,
    nameservers = DEFAULT_NAMESERVERS,
    port = DEFAULT_PORT,
    whiteSet = new Set(),
    cache,
    cacheFile = DEFAULT_CACHE_FILE,
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
  // ========================================================
  const domainMap = new Map();
  const passthroughWriter = passthroughFile
    ? new LineWriter(passthroughFile)
    : null;
  let passthroughCount = 0;
  let totalRules = 0;

  for (const file of inputFiles) {
    await readLines(file, async (raw) => {
      totalRules++;
      const parsed = parseRule(raw);
      if (!parsed) {
        if (passthroughWriter) await passthroughWriter.write(raw);
        passthroughCount++;
        return;
      }
      const prev = domainMap.get(parsed.domain);
      if (prev === undefined) {
        domainMap.set(parsed.domain, parsed.isWhite ? 1 : 0);
      } else if (parsed.isWhite && prev === 0) {
        domainMap.set(parsed.domain, 1);
      }
    });
  }

  if (passthroughWriter) await passthroughWriter.close();

  const total = domainMap.size;
  console.log(`规则解析完成，共${totalRules}条规则，提取${total}个域名`);

  // ========================================================
  // 第 2 遍：DNS 查询（滑动窗口）
  // ========================================================
  const limit = pLimit(concurrency);
  const now = Math.floor(Date.now() / 1000);
  let cacheHits = 0;
  let completed = 0;
  const startTime = Date.now();

  const report = (force = false) => {
    if (!force && completed % progressStep !== 0) return;
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const percent =
      total > 0 ? ((completed / total) * 100).toFixed(1) : "100.0";
    const speed = completed / Math.max(elapsed, 0.001);
    const remain = speed > 0 ? ((total - completed) / speed).toFixed(0) : "?";
    console.log(
      `进度: ${completed}/${total} (${percent}%) | 缓存命中: ${cacheHits} | 已用: ${elapsed}s | 预计剩余: ${remain}s`,
    );
    if (typeof onProgress === "function") {
      onProgress({
        completed,
        total,
        cacheHits,
        elapsed: Number(elapsed),
        remain: Number(remain) || 0,
        percent: Number(percent),
      });
    }
  };

  const aliveSet = new Set();
  const inflight = new Set();
  const MAX_INFLIGHT = concurrency * 4;

  for (const domain of domainMap.keys()) {
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

  const deadCount = total - aliveSet.size;

  // ========================================================
  // 计算"死且无存活父域、非白名单"的集合
  // ========================================================
  const deadWithoutAliveParent = new Set();
  let parentAliveCount = 0;

  for (const [domain, isWhiteFlag] of domainMap) {
    if (aliveSet.has(domain)) continue;
    if (isWhiteFlag === 1 && keepWhiteRules) continue;
    if (whiteSet.has(domain) && keepWhiteRules) continue;

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

  domainMap.clear();

  // ========================================================
  // 第 3 遍：重新读输入文件，分类输出
  // ========================================================
  const cleanedWriter = new LineWriter(cleanedFile);
  const nocleanedWriter = nocleanedFile ? new LineWriter(nocleanedFile) : null;
  const deadWriter = deadDomainsFile ? new LineWriter(deadDomainsFile) : null;

  if (deadWriter) {
    for (const d of deadWithoutAliveParent) await deadWriter.write(d);
    await deadWriter.close();
  }

  let cleanedCount = 0;
  let nocleanedCount = 0;

  for (const file of inputFiles) {
    await readLines(file, async (raw) => {
      const parsed = parseRule(raw);
      if (!parsed) return; // passthrough 已写

      const isWhite = parsed.isWhite || whiteSet.has(parsed.domain);

      if (isWhite && keepWhiteRules) {
        await cleanedWriter.write(raw);
        cleanedCount++;
        return;
      }

      if (deadWithoutAliveParent.has(parsed.domain)) {
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
    aliveDomains: aliveSet.size,
    deadDomains: deadCount,
    deadDomainsWithParentAlive: parentAliveCount,
    removedDomains: deadWithoutAliveParent.size,
    aliveRules: cleanedCount,
    deadRules: nocleanedCount,
    passthrough: passthroughCount,
    cacheHits,
    cacheSize: cacheStore.size ? cacheStore.size() : 0,
  };

  console.log(
    `剔除死域名规则完成 | 输入 ${totalRules} 条` +
      ` | 保留 ${cleanedCount} 条` +
      ` | 剔除 ${nocleanedCount} 条` +
      ` | 丢弃非域名行 ${passthroughCount} 条` +
      ` | 死域名 ${deadCount} 个` +
      `（父域存活保留 ${parentAliveCount} 个，实际剔除 ${stats.removedDomains} 个）` +
      ` | 缓存命中 ${cacheHits} 次`,
  );

  return stats;
};

module.exports = { removeDeadRules, createFileCache };
