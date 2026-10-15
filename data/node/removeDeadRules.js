const { Resolver } = require("node:dns/promises");
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const { finished } = require("node:stream/promises");
const { readLines, LineWriter } = require("./stream_utils");
const { parseRule } = require("./rule_parser");

const CACHE_TTL = 3110400; // 36 天
const DEFAULT_CONCURRENCY = 500;
const DEFAULT_NAMESERVERS = ["127.0.0.1"];
const DEFAULT_PORT = 5053;
const DNS_TIMEOUT = 800;
const DEFAULT_CACHE_FILE = "./dns-cache.json";
const DEFAULT_PROGRESS_STEP = 1000;

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
// 并发控制
// ============================================================
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

/**
 * ★ 流式把缓存文件加载进 store。
 * - 兼容旧格式（整文件是单个 JSON 对象）
 * - 新格式：NDJSON（每行一个 JSON 数组 [domain, value]）
 *
 * 使用 readline 逐行读取，避免 fs.readFileSync + split("\n")
 * 在大缓存下造成的内存翻倍。
 */
const loadCacheInto = async (filePath, store) => {
  if (!filePath || !fs.existsSync(filePath)) return;

  // 嗅探文件头，判断是否旧格式（整文件单个 JSON 对象）
  let head = "";
  try {
    const fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(64);
    const n = fs.readSync(fd, buf, 0, 64, 0);
    fs.closeSync(fd);
    head = buf.slice(0, n).toString("utf8").trimStart();
  } catch {
    return;
  }

  // 旧格式：一次性加载（只用于迁移，通常体积已经很大时才危险，
  // 建议迁移后立即删除旧文件或改为 NDJSON）
  if (head.startsWith("{")) {
    try {
      const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
      for (const k of Object.keys(data)) store.set(k, data[k]);
    } catch {
      // 旧格式解析失败，忽略
    }
    return;
  }

  // 新格式：流式逐行读取
  const rl = readline.createInterface({
    input: fs.createReadStream(filePath, { encoding: "utf8" }),
    crlfDelay: Infinity,
  });
  for await (const line of rl) {
    if (!line) continue;
    try {
      const arr = JSON.parse(line);
      if (Array.isArray(arr) && arr.length === 2) store.set(arr[0], arr[1]);
    } catch {
      // 单行损坏，跳过
    }
  }
};

/**
 * ★ 改为 async 工厂：加载阶段流式读取，避免一次性驻留整文件。
 *
 * @param {string} filePath  缓存文件路径
 * @param {object} [options]
 * @param {boolean} [options.read=true]   是否读取已有缓存到内存
 * @param {boolean} [options.write=true]  是否允许 save() 覆盖缓存文件
 */
const createFileCache = async (filePath, options = {}) => {
  const { read = true, write = true } = options;
  const store = new Map();

  // ★ read=false 时跳过加载，旧文件原封不动
  if (read) await loadCacheInto(filePath, store);

  return {
    get: (d) => store.get(d),
    set: (d, v) => store.set(d, v),
    async save() {
      // ★ write=false 直接返回，旧文件不被覆盖
      if (!write) return;
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
    deadWhitelistReportFile,
    concurrency = DEFAULT_CONCURRENCY,
    nameservers = DEFAULT_NAMESERVERS,
    port = DEFAULT_PORT,
    whiteSet = new Set(),
    cache,
    cacheFile = DEFAULT_CACHE_FILE,
    cacheRead = true, // ★ 缓存读开关
    cacheWrite = true, // ★ 缓存写开关
    keepWhiteRules = true,
    autoSaveCache = true,
    onProgress,
    progressStep = DEFAULT_PROGRESS_STEP,
  } = options;

  console.log("开始剔除死域名规则");

  // ★ createFileCache 现在是 async 工厂
  const cacheStore =
    cache ||
    (cacheFile
      ? await createFileCache(cacheFile, { read: cacheRead, write: cacheWrite })
      : createNullCache());

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
      } else if (flag > prev) {
        domainMap.set(parsed.domain, flag);
      }
    });
  }

  if (passthroughWriter) await passthroughWriter.close();

  const total = domainMap.size;
  console.log(
    `规则解析完成，共${totalRules}条规则，提取${total}个域名（白 ${whiteCount}，重写 ${rewriteCount}）`,
  );

  // ========================================================
  // 第 2 遍：DNS 查询（白名单跳过）
  // ========================================================
  const limit = pLimit(concurrency);
  const now = Math.floor(Date.now() / 1000);
  let cacheHits = 0;
  let completed = 0;
  const startTime = Date.now();

  const domainsToCheck = [];
  const aliveSet = new Set();
  const skipWhiteSet = new Set();

  for (const [domain, flag] of domainMap) {
    if (flag === 1 && keepWhiteRules) {
      skipWhiteSet.add(domain);
      aliveSet.add(domain);
    } else {
      domainsToCheck.push(domain);
    }
  }

  const totalToCheck = domainsToCheck.length;

  const report = (force = false) => {
    if (!force && completed % progressStep !== 0) return;
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const percent =
      totalToCheck > 0
        ? ((completed / totalToCheck) * 100).toFixed(1)
        : "100.0";
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
      let alive;

      if (cached && now - cached.timeStamp <= CACHE_TTL) {
        // ★ 兼容旧格式（含 ipList）
        alive =
          cached.alive !== undefined
            ? cached.alive
            : Array.isArray(cached.ipList) && cached.ipList.length > 0;
        cacheHits++;
      } else {
        const ipList = await checkDomain(domain, { nameservers, port });
        alive = ipList && ipList.length > 0;
        // ★ 只存布尔值 + 时间戳，单条记录体积大幅缩小
        cacheStore.set(domain, { alive, timeStamp: now });
      }

      if (alive) aliveSet.add(domain);
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
  // ========================================================
  const deadWithoutAliveParent = new Set();
  const deadWhitelistSet = new Set();
  let parentAliveCount = 0;

  for (const [domain, flag] of domainMap) {
    if (aliveSet.has(domain)) continue;
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

  // 白名单死域名（只报告）
  for (const [domain, flag] of domainMap) {
    if (flag !== 1) continue;
    if (aliveSet.has(domain)) continue;
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

      if (isWhite && keepWhiteRules) {
        await cleanedWriter.write(raw);
        cleanedCount++;
        whiteKept++;
        return;
      }

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

  // ★ write=false 时 save() 内部直接 return，旧文件不被覆盖
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

module.exports = { removeDeadRules, createFileCache, createNullCache };
