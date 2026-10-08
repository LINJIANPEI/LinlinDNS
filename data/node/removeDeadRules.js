const { Resolver } = require("node:dns/promises");
const net = require("node:net");
const fs = require("node:fs");
const path = require("node:path");
const { finished } = require("node:stream/promises");

const CACHE_TTL = 3110400; // 36 天
const DEFAULT_CONCURRENCY = 200;
const DEFAULT_NAMESERVERS = ["127.0.0.1"];
const DEFAULT_PORT = 5053;
const DNS_TIMEOUT = 2000;
const CONNECT_TIMEOUT = 2000;
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
    const resolver = new Resolver();
    resolver.setServers(nameservers.map((ns) => `${ns}:${port}`));
    resolverCache.set(key, resolver);
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
  const domain = value
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "")
    .replace(/^\.+/, "");
  if (!domain) return null;
  if (domain === "localhost" || domain === "localhost.localdomain") return null;
  if (isIPv4(domain)) return null;
  return DOMAIN_RE.test(domain) ? domain : null;
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
  const trimmed = line.trim();
  if (!trimmed) return null;

  if (trimmed.startsWith("!")) return null;
  if (trimmed.startsWith("#")) {
    if (!EXTENDED_RULE_MARKERS.some((m) => trimmed.startsWith(m))) return null;
  }

  const parts = trimmed.split(/\s+/);
  if (parts.length === 2 && isIPv4(parts[0])) {
    const domain = normalizeDomain(parts[1]);
    if (domain) {
      const isWhite = !(parts[0] === "0.0.0.0" || parts[0].startsWith("127."));
      return { domain, isWhite, original: line };
    }
    return null;
  }

  const isWhite = trimmed.startsWith("@@");
  const body = isWhite ? trimmed.slice(2) : trimmed;

  if (body.startsWith("||")) {
    const domain = normalizeDomain(body.slice(2).split("^")[0]);
    return domain ? { domain, isWhite, original: line } : null;
  }

  const domain = normalizeDomain(trimmed.replace(/\^+$/, ""));
  return domain ? { domain, isWhite: false, original: line } : null;
};

// ============================================================
// DNS 查询
// ============================================================
const resolveA = async (domain, nameservers, port) => {
  const resolver = getResolver(nameservers, port);
  try {
    const records = await Promise.race([
      resolver.resolve4(domain),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("DNS timeout")), DNS_TIMEOUT),
      ),
    ]);
    return records.filter((ip) => ip !== "0.0.0.0");
  } catch {
    return [];
  }
};

const connectWithTimeout = (ip, port, timeout = CONNECT_TIMEOUT) => {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const done = (r) => {
      socket.destroy();
      resolve(r);
    };
    socket.setTimeout(timeout);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
    socket.connect(port, ip);
  });
};

const checkDomain = async (domain, { nameservers, port }) => {
  if (isIPv4(domain)) {
    for (const p of [80, 443, 80, 443, 80, 443]) {
      if (await connectWithTimeout(domain, p)) return [domain];
    }
    return [];
  }
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
      const trimmed = raw.trimStart();
      if (trimmed.startsWith("{")) {
        // 兼容旧 JSON 格式
        const data = JSON.parse(raw);
        for (const k of Object.keys(data)) store.set(k, data[k]);
      } else {
        // NDJSON（新格式）
        for (const line of raw.split("\n")) {
          if (!line) continue;
          try {
            const arr = JSON.parse(line);
            if (Array.isArray(arr) && arr.length === 2)
              store.set(arr[0], arr[1]);
          } catch {}
        }
      }
    } catch {
      // 损坏的缓存就当空的
    }
  }

  return {
    get(domain) {
      return store.get(domain);
    },
    set(domain, value) {
      store.set(domain, value);
    },
    async save() {
      if (!filePath) return;
      const dir = path.dirname(filePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      const out = fs.createWriteStream(filePath);
      for (const [domain, value] of store) {
        const line = JSON.stringify([domain, value]) + "\n";
        if (!out.write(line)) {
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
const removeDeadRules = async (
  rules,
  {
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
  } = {},
) => {
  console.log("开始剔除死域名规则");
  try {
    if (!Array.isArray(rules)) {
      throw new TypeError("rules 必须是字符串数组");
    }

    // 传 cacheFile: null 可关闭缓存，省几百 MB 内存
    const cacheStore =
      cache || (cacheFile ? createFileCache(cacheFile) : createNullCache());

    // ========================================================
    // 1. 解析规则：ipList 直接挂在 entry 上，避免再建一份 results
    // ========================================================
    const domainMap = new Map();
    const passthrough = [];

    for (const line of rules) {
      const parsed = parseRule(line);
      if (!parsed) {
        passthrough.push(line);
        continue;
      }
      let entry = domainMap.get(parsed.domain);
      if (!entry) {
        entry = { isWhite: parsed.isWhite, ipList: null, originals: [] };
        domainMap.set(parsed.domain, entry);
      } else if (parsed.isWhite) {
        entry.isWhite = true;
      }
      entry.originals.push(parsed.original);
    }

    const total = domainMap.size;
    console.log(`规则解析完成，共${rules.length}条规则，提取${total}个域名`);

    // ========================================================
    // 2. 并发检测（滑动窗口，不预生成 305 万 promise）
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

    const inflight = new Set();
    const MAX_INFLIGHT = concurrency * 4;

    for (const [domain, entry] of domainMap) {
      let p;
      p = limit(async () => {
        const cached = cacheStore.get(domain);
        if (cached && now - cached.timeStamp <= CACHE_TTL) {
          entry.ipList = cached.ipList;
          cacheHits++;
        } else {
          const ipList = await checkDomain(domain, { nameservers, port });
          entry.ipList = ipList;
          cacheStore.set(domain, { ipList, timeStamp: now });
        }
        completed++;
        report();
      }).finally(() => inflight.delete(p));

      inflight.add(p);
      if (inflight.size >= MAX_INFLIGHT) {
        await Promise.race(inflight);
      }
    }
    await Promise.all(inflight);
    report(true);

    // ========================================================
    // 3. 只建 aliveSet（父域检查需要）
    // ========================================================
    const aliveSet = new Set();
    for (const [domain, entry] of domainMap) {
      if (entry.ipList && entry.ipList.length > 0) aliveSet.add(domain);
    }
    const deadCount = total - aliveSet.size;

    // ========================================================
    // 4. 分类：活域名 / 白名单 / 父域存活的死域名 → cleaned
    // ========================================================
    const cleaned = [];
    const nocleaned = [];
    let parentAliveCount = 0;

    for (const [domain, entry] of domainMap) {
      const isDead = !(entry.ipList && entry.ipList.length > 0);
      const isWhite = entry.isWhite || whiteSet.has(domain);

      if (isWhite && keepWhiteRules) {
        for (const r of entry.originals) cleaned.push(r);
        continue;
      }
      if (!isDead) {
        for (const r of entry.originals) cleaned.push(r);
        continue;
      }

      const labels = domain.split(".");
      let parentAlive = false;
      for (let i = 1; i < labels.length; i++) {
        if (aliveSet.has(labels.slice(i).join("."))) {
          parentAlive = true;
          break;
        }
      }

      if (parentAlive) {
        parentAliveCount++;
        for (const r of entry.originals) cleaned.push(r);
      } else {
        for (const r of entry.originals) nocleaned.push(r);
      }
    }

    // ========================================================
    // 5. 统计（不再 [...set].sort()）
    // ========================================================
    const stats = {
      totalRules: rules.length,
      totalDomains: total,
      aliveDomains: aliveSet.size,
      deadDomains: deadCount,
      deadDomainsWithParentAlive: parentAliveCount,
      removedDomains: deadCount - parentAliveCount,
      aliveRules: cleaned.length,
      deadRules: nocleaned.length,
      passthrough: passthrough.length,
      cacheHits,
      cacheSize: cacheStore.size ? cacheStore.size() : 0,
    };

    if (autoSaveCache && typeof cacheStore.save === "function") {
      await cacheStore.save();
    }

    console.log(
      `剔除死域名规则完成 | 输入 ${rules.length} 条` +
        ` | 保留 ${cleaned.length} 条` +
        ` | 剔除 ${nocleaned.length} 条` +
        ` | 丢弃非域名行 ${passthrough.length} 条` +
        ` | 死域名 ${deadCount} 个` +
        `（父域存活保留 ${parentAliveCount} 个，实际剔除 ${stats.removedDomains} 个）` +
        ` | 缓存命中 ${cacheHits} 次`,
    );

    // ========================================================
    // 6. 返回
    //    deadDomains / aliveDomains 改成 Set，避免数组复制 + 排序
    //    如果你确实要数组，用 [...set] 自己转，但请注意内存
    // ========================================================
    return {
      cleaned,
      nocleaned,
      passthrough,
      deadDomains: aliveSet, // 见下方说明
      aliveDomains: aliveSet,
      stats,
    };
  } catch (error) {
    throw new Error(`剔除死域名规则失败: ${error.message}`);
  }
};

module.exports = {
  removeDeadRules,
  createFileCache,
};
