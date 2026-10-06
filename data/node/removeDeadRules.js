// removeDeadRules.js
import { Resolver } from "node:dns/promises";
import net from "node:net";

const CACHE_TTL = 3110400; // 36 天
const DEFAULT_CONCURRENCY = 500;
const DEFAULT_NAMESERVERS = ["127.0.0.1"];
const DEFAULT_PORT = 5053;
const DNS_RETRIES = 3;

const DOMAIN_RE =
  /^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isIPv4(s) {
  const m = IPV4_RE.exec(s);
  if (!m) return false;
  return m.slice(1).every((p) => {
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

function pLimit(concurrency) {
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
}

function normalizeDomain(value) {
  const domain = value
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "")
    .replace(/^\.+/, "");
  if (!domain) return null;
  if (domain === "localhost" || domain === "localhost.localdomain") return null;
  if (isIPv4(domain)) return null;
  return DOMAIN_RE.test(domain) ? domain : null;
}

function parseRule(line) {
  if (typeof line !== "string") return null;
  const trimmed = line.trim();
  if (!trimmed) return null;

  if (trimmed.startsWith("!")) return null;
  if (trimmed.startsWith("#")) {
    const extMarkers = [
      "##",
      "#@#",
      "#$#",
      "#@$#",
      "#%#",
      "#@%#",
      "#?#",
      "#@?#",
    ];
    if (!extMarkers.some((m) => trimmed.startsWith(m))) return null;
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
}

async function resolveA(domain, nameservers, port) {
  const resolver = new Resolver();
  resolver.setServers(nameservers.map((ns) => `${ns}:${port}`));
  try {
    const records = await resolver.resolve4(domain);
    return records.filter((ip) => ip !== "0.0.0.0");
  } catch {
    return [];
  }
}

function connectWithTimeout(ip, port, timeout = 5000) {
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
}

async function checkDomain(domain, { nameservers, port }) {
  const ipList = [];
  if (isIPv4(domain)) {
    const ports = [80, 443, 80, 443, 80, 443];
    for (const p of ports) {
      if (await connectWithTimeout(domain, p, 5000)) {
        ipList.push(domain);
        break;
      }
    }
  } else {
    for (let i = 0; i < DNS_RETRIES && ipList.length === 0; i++) {
      const result = await resolveA(domain, nameservers, port);
      ipList.push(...result);
    }
  }
  return ipList;
}

/**
 * 从规则数组中检测并剔除死域名对应的规则，返回处理后的规则数组。
 *
 * 返回值是数组本身，附带以下非枚举属性：
 *   - result.dead           被剔除的规则数组
 *   - result.deadDomains    死域名数组
 *   - result.aliveDomains   存活域名数组
 *   - result.stats          统计信息
 *
 * @param {string[]} rules
 * @param {object}   options
 * @param {number}   options.concurrency     并发数，默认 500
 * @param {string[]} options.nameservers     DNS 服务器，默认 ['127.0.0.1']
 * @param {number}   options.port            DNS 端口，默认 5053
 * @param {Set<string>} options.whiteSet     白名单域名集合
 * @param {Map}      options.cache           缓存：domain -> { ipList, timeStamp }
 * @param {boolean}  options.keepWhiteRules  白名单规则是否始终保留，默认 true
 * @returns {Promise<string[]>}
 */
export async function removeDeadRules(
  rules,
  {
    concurrency = DEFAULT_CONCURRENCY,
    nameservers = DEFAULT_NAMESERVERS,
    port = DEFAULT_PORT,
    whiteSet = new Set(),
    cache = new Map(),
    keepWhiteRules = true,
  } = {},
) {
  if (!Array.isArray(rules)) {
    throw new TypeError("rules 必须是字符串数组");
  }

  // 1. 解析规则，提取域名
  const domainMap = new Map();
  const passthrough = [];

  for (const line of rules) {
    const parsed = parseRule(line);
    if (!parsed) {
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

  // 2. 并发检测
  const limit = pLimit(concurrency);
  const results = new Map();
  const now = Math.floor(Date.now() / 1000);

  await Promise.all(
    domains.map((domain) =>
      limit(async () => {
        const cached = cache.get(domain);
        if (cached && now - cached.timeStamp <= CACHE_TTL) {
          results.set(domain, cached.ipList);
          return;
        }
        const ipList = await checkDomain(domain, { nameservers, port });
        cache.set(domain, { ipList, timeStamp: now });
        results.set(domain, ipList);
      }),
    ),
  );

  // 3. 分类
  const deadSet = new Set();
  const aliveSet = new Set();
  for (const domain of domains) {
    const ipList = results.get(domain);
    if (ipList.length > 0) aliveSet.add(domain);
    else deadSet.add(domain);
  }

  // 4. 剔除规则
  const alive = [];
  const dead = [];

  for (const [domain, entry] of domainMap) {
    const isDead = deadSet.has(domain);
    const isWhite = entry.isWhite || whiteSet.has(domain);

    if (isWhite && keepWhiteRules) {
      alive.push(...entry.originals);
      continue;
    }
    if (!isDead) {
      alive.push(...entry.originals);
      continue;
    }

    // 父域名存活则保留子域名规则
    const labels = domain.split(".");
    let parentAlive = false;
    for (let i = 1; i < labels.length; i++) {
      if (aliveSet.has(labels.slice(i).join("."))) {
        parentAlive = true;
        break;
      }
    }
    if (parentAlive) alive.push(...entry.originals);
    else dead.push(...entry.originals);
  }

  alive.push(...passthrough);

  // 5. 附加信息
  const deadDomains = [...deadSet].sort();
  const aliveDomains = [...aliveSet].sort();

  Object.defineProperties(alive, {
    dead: { value: dead, enumerable: false },
    deadDomains: { value: deadDomains, enumerable: false },
    aliveDomains: { value: aliveDomains, enumerable: false },
    stats: {
      value: {
        totalRules: rules.length,
        totalDomains: domains.length,
        aliveDomains: aliveDomains.length,
        deadDomains: deadDomains.length,
        aliveRules: alive.length,
        deadRules: dead.length,
        passthrough: passthrough.length,
      },
      enumerable: false,
    },
  });

  return alive;
}
