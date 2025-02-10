const { createHash } = require("crypto");

// 预编译正则表达式
const RULE_REGEX = {
  DOMAIN: /@@?\|\|([\w\-.*]+)\^/,
  HOSTS: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+([\w\-.]+)/,
  ABLOCK: /^(\|{1,2})([\w\-.*]+)\^?/,
};

class AdGuardListProcessor {
  constructor() {
    // 使用Map保持插入顺序
    this.whitelist = new Map();
    this.blacklist = new Map();
    // 域名索引树
    this.domainTree = {
      wildcards: new Set(),
      exact: new Set(),
    };
    // 哈希去重
    this.hashCache = new Set();
  }

  // 标准化域名格式
  _normalize(domain) {
    return domain.replace(/^\*\.|\.\*$/g, "").toLowerCase();
  }

  // 生成规则哈希
  _hash(rule) {
    return createHash("sha1").update(rule).digest("hex");
  }

  // 处理单条规则
  _processRule(rule, isWhitelist) {
    const trimmed = rule.trim();
    if (!trimmed || trimmed.startsWith("!")) return null;

    // 哈希去重检查
    const hash = this._hash(trimmed);
    if (this.hashCache.has(hash)) return null;
    this.hashCache.add(hash);

    let domain, converted;

    // 白名单处理流程
    if (isWhitelist) {
      const match = trimmed.match(RULE_REGEX.DOMAIN);
      if (match) {
        domain = this._normalize(match[1]);
        this._addToDomainTree(domain, true);
        return { domain, rule: trimmed, hash };
      }
      return null;
    }

    // 黑名单转换流程
    if (RULE_REGEX.HOSTS.test(trimmed)) {
      const [, domain] = trimmed.match(RULE_REGEX.HOSTS);
      converted = `||${domain}^`;
    } else if (RULE_REGEX.ABLOCK.test(trimmed)) {
      const [, prefix, domain] = trimmed.match(RULE_REGEX.ABLOCK);
      converted = prefix === "|" ? `||${domain}^` : `${prefix}${domain}^`;
    } else if (RULE_REGEX.DOMAIN.test(trimmed)) {
      converted = trimmed; // 已经是AdGuard格式
    } else {
      return null; // 无法识别的格式
    }

    // 提取转换后的域名
    const domainMatch = converted.match(RULE_REGEX.DOMAIN);
    domain = domainMatch ? this._normalize(domainMatch[1]) : null;

    return { domain, rule: converted, hash };
  }

  // 构建域名索引树
  _addToDomainTree(domain, isWhitelist) {
    if (domain.includes("*")) {
      this.domainTree.wildcards.add(domain.replace(/\*/g, ""));
    } else {
      this.domainTree.exact.add(domain);

      // 自动添加通配符检测
      const parts = domain.split(".");
      if (parts.length > 2) {
        this.domainTree.wildcards.add(parts.slice(1).join("."));
      }
    }
  }

  // 冲突检测
  _checkConflict(domain) {
    // 精确匹配检查
    if (this.domainTree.exact.has(domain)) return true;

    // 通配符匹配检查
    const parts = domain.split(".");
    for (let i = 0; i < parts.length - 1; i++) {
      const checkDomain = parts.slice(i).join(".");
      if (this.domainTree.wildcards.has(checkDomain)) return true;
    }

    return false;
  }

  // 处理白名单数组
  processWhitelist(list) {
    list.forEach((rule) => {
      const processed = this._processRule(rule, true);
      if (processed) {
        this.whitelist.set(processed.hash, processed.rule);
      }
    });
  }

  // 处理黑名单数组
  processBlacklist(list) {
    list.forEach((rule) => {
      const processed = this._processRule(rule, false);
      if (processed) {
        if (!processed.domain || !this._checkConflict(processed.domain)) {
          this.blacklist.set(processed.hash, processed.rule);
        }
      }
    });
  }

  // 获取处理结果
  getResults() {
    return {
      whitelist: Array.from(this.whitelist.values()),
      blacklist: Array.from(this.blacklist.values()),
      stats: {
        total: this.whitelist.size + this.blacklist.size,
        whitelist: this.whitelist.size,
        blacklist: this.blacklist.size,
        conflicts:
          this.hashCache.size - (this.whitelist.size + this.blacklist.size),
      },
    };
  }
}

// 使用示例
const processor = new AdGuardListProcessor();

function optimizeProcessing(blacklist, whitelist) {
  // 处理流程
  processor.processWhitelist(whitelist);
  processor.processBlacklist(blacklist);
  // 获取结果
  const result = processor.getResults();
  return result;
}

/* 输出示例：
==== 白名单规则 ====
@@||example.com^
@@||trusted.org^
@@||safe.com^

==== 黑名单规则 ====
||tracking.com^
||ads.com^

统计信息: {
  total: 5,
  whitelist: 3,
  blacklist: 2,
  conflicts: 2
}
*/

module.exports = { optimizeProcessing };
