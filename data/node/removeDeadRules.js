const { Resolver } = require("node:dns/promises");
const net = require("node:net");
const fs = require("node:fs");
const path = require("node:path");

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
// 文件缓存
// ============================================================
const createFileCache = (filePath) => {
  let store = new Map();

  if (filePath && fs.existsSync(filePath)) {
    try {
      const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));
      store = new Map(Object.entries(data));
    } catch {
      store = new Map();
    }
  }

  return {
    get(domain) {
      return store.get(domain);
    },
    set(domain, value) {
      store.set(domain, value);
    },
    save() {
      if (!filePath) return;
      const dir = path.dirname(filePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(filePath, JSON.stringify(Object.fromEntries(store)));
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

    const cacheStore = cache || createFileCache(cacheFile);

    // ========================================================
    // 1. 解析规则：能解析出域名的进 domainMap，其余进 passthrough
    // ========================================================
    const domainMap = new Map();
    const passthrough = [];

    for (const line of rules) {
      const parsed = parseRule(line);
      if (!parsed) {
        // 注释、##、看不懂的行 —— 非域名行，既不是活也不是死
        passthrough.push(line);
        continue;
      }
      const entry = domainMap.get(parsed.domain) || {
        isWhite: parsed.isWhite,
        originals: [],
      };
      entry.originals.push(parsed.original);
      if (parsed.isWhite) entry.isWhite = true;
      domainMap.set(parsed.domain, entry);
    }

    const domains = [...domainMap.keys()];
    const total = domains.length;
    console.log(`规则解析完成，共${rules.length}条规则，提取${total}个域名`);

    // ========================================================
    // 2. 并发检测（带进度）
    // ========================================================
    const limit = pLimit(concurrency);
    const results = new Map();
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

    await Promise.all(
      domains.map((domain) =>
        limit(async () => {
          const cached = cacheStore.get(domain);
          if (cached && now - cached.timeStamp <= CACHE_TTL) {
            results.set(domain, cached.ipList);
            cacheHits++;
          } else {
            const ipList = await checkDomain(domain, { nameservers, port });
            cacheStore.set(domain, { ipList, timeStamp: now });
            results.set(domain, ipList);
          }
          completed++;
          report();
        }),
      ),
    );
    report(true);

    // ========================================================
    // 3. 分类：活域名 / 死域名
    // ========================================================
    const deadSet = new Set();
    const aliveSet = new Set();
    for (const domain of domains) {
      const ipList = results.get(domain);
      if (ipList.length > 0) aliveSet.add(domain);
      else deadSet.add(domain);
    }

    // ========================================================
    // 4. 剔除规则
    //    cleaned    ← 活域名规则 / 白名单规则 / 父域存活的死域名规则
    //    nocleaned  ← 死域名规则（自己死且父域也死）
    //    passthrough 不参与输出
    // ========================================================
    const cleaned = [];
    const nocleaned = [];
    let parentAliveCount = 0; // 因父域存活而被保留的死域名个数

    for (const [domain, entry] of domainMap) {
      const isDead = deadSet.has(domain);
      const isWhite = entry.isWhite || whiteSet.has(domain);

      // 白名单规则：保留
      if (isWhite && keepWhiteRules) {
        for (const r of entry.originals) cleaned.push(r);
        continue;
      }

      // 活域名规则：保留
      if (!isDead) {
        for (const r of entry.originals) cleaned.push(r);
        continue;
      }

      // 死域名：检查父域是否存活
      const labels = domain.split(".");
      let parentAlive = false;
      for (let i = 1; i < labels.length; i++) {
        if (aliveSet.has(labels.slice(i).join("."))) {
          parentAlive = true;
          break;
        }
      }

      if (parentAlive) {
        // 父域活着，规则保留
        parentAliveCount++;
        for (const r of entry.originals) cleaned.push(r);
      } else {
        // 自己死 + 父域也死，规则剔除
        for (const r of entry.originals) nocleaned.push(r);
      }
    }

    // ========================================================
    // 5. 统计信息
    // ========================================================
    const deadDomains = [...deadSet].sort();
    const aliveDomains = [...aliveSet].sort();

    const stats = {
      totalRules: rules.length,
      totalDomains: total,
      aliveDomains: aliveDomains.length,
      deadDomains: deadDomains.length,
      deadDomainsWithParentAlive: parentAliveCount,
      removedDomains: deadDomains.length - parentAliveCount,
      aliveRules: cleaned.length,
      deadRules: nocleaned.length,
      passthrough: passthrough.length,
      cacheHits,
      cacheSize: cacheStore.size ? cacheStore.size() : 0,
    };

    if (autoSaveCache && typeof cacheStore.save === "function") {
      cacheStore.save();
    }

    console.log(
      `剔除死域名规则完成 | 输入 ${rules.length} 条` +
        ` | 保留 ${cleaned.length} 条` +
        ` | 剔除 ${nocleaned.length} 条` +
        ` | 丢弃非域名行 ${passthrough.length} 条` +
        ` | 死域名 ${deadDomains.length} 个` +
        `（父域存活保留 ${parentAliveCount} 个，实际剔除 ${stats.removedDomains} 个）` +
        ` | 缓存命中 ${cacheHits} 次`,
    );

    // ========================================================
    // 6. 返回
    // ========================================================
    return {
      cleaned, // 存活的规则（活域名 + 白名单 + 父域存活的死域名规则）
      nocleaned, // 死的规则（自己死且父域也死的域名规则）
      passthrough, // 非域名行（注释、##、看不懂的），既不是活也不是死
      deadDomains, // 死域名列表
      aliveDomains, // 活域名列表
      stats, // 统计信息
    };
  } catch (error) {
    throw new Error(`剔除死域名规则失败: ${error.message}`);
  }
};

module.exports = {
  removeDeadRules,
  createFileCache,
};
