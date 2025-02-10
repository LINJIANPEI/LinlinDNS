const { createHash } = require("crypto");

class AdvancedAdGuardProcessor {
  constructor() {
    // 有效规则存储
    this.whitelist = new Map();
    this.blacklist = new Map();

    // 排除规则存储（按类型分类）
    this.excluded = {
      whitelist: {
        conflicts: new Map(), // 白名单内部的冲突
        duplicates: new Set(),
        invalid: new Set(),
      },
      blacklist: {
        conflicts: new Map(), // 黑名单规则与白名单的冲突
        duplicates: new Set(),
        invalid: new Set(),
      },
    };

    // 辅助数据结构
    this.domainIndex = new Map(); // domain => { type: 'wl'/'bl', rule: string }
    this.wlHashes = new Set();
    this.blHashes = new Set();
  }

  process(whitelistInput, blacklistInput) {
    this._processWhiteList(whitelistInput);
    this._processBlackList(blacklistInput);
    return this._compileResults();
  }

  _processWhiteList(rules) {
    rules.forEach((rule) => {
      const parsed = this._parseWhiteRule(rule);

      if (!parsed.valid) {
        this.excluded.whitelist.invalid.add(rule);
        return;
      }

      if (this.wlHashes.has(parsed.hash)) {
        this.excluded.whitelist.duplicates.add(rule);
        return;
      }

      // 白名单内部冲突检测
      const existing = this.domainIndex.get(parsed.domain);
      if (existing) {
        this.excluded.whitelist.conflicts.set(rule, {
          reason: `与现有规则冲突: ${existing.rule}`,
          existingRule: existing.rule,
        });
        return;
      }

      this._addWhiteRule(parsed);
    });
  }

  _processBlackList(rules) {
    rules.forEach((originalRule) => {
      const parsed = this._parseBlackRule(originalRule);

      if (!parsed.valid) {
        this.excluded.blacklist.invalid.add(originalRule);
        return;
      }

      if (this.blHashes.has(parsed.hash)) {
        this.excluded.blacklist.duplicates.add(originalRule);
        return;
      }

      // 黑名单冲突检测（与白名单）
      const conflict = this._checkConflict(parsed.domain);
      if (conflict) {
        this.excluded.blacklist.conflicts.set(originalRule, {
          reason: `被白名单规则阻止: ${conflict.rule}`,
          whiteRule: conflict.rule,
        });
        return;
      }

      this._addBlackRule(parsed);
    });
  }

  _parseWhiteRule(rule) {
    const trimmed = rule.trim();
    const match = trimmed.match(/^@@\|\|([\w\-.*]+)\^/);

    if (!match) return { valid: false };

    const domain = this._normalizeDomain(match[1]);
    return {
      valid: true,
      type: "whitelist",
      domain: domain,
      rule: trimmed,
      hash: this._hash(trimmed),
    };
  }

  _parseBlackRule(originalRule) {
    const trimmed = originalRule.trim();
    let domain, converted;

    // 尝试匹配不同格式
    const adgMatch = trimmed.match(/^\|\|([\w\-.*]+)\^/);
    const hostsMatch = trimmed.match(/^\d+\.\d+\.\d+\.\d+\s+([\w\-.]+)/);
    const ablockMatch = trimmed.match(/^\|([\w\-.]+)/);

    if (adgMatch) {
      domain = adgMatch[1];
      converted = trimmed;
    } else if (hostsMatch) {
      domain = hostsMatch[1];
      converted = `||${domain}^`;
    } else if (ablockMatch) {
      domain = ablockMatch[1];
      converted = `||${domain}^`;
    } else {
      return { valid: false };
    }

    const normalized = this._normalizeDomain(domain);
    return {
      valid: true,
      type: "blacklist",
      domain: normalized,
      rule: converted,
      hash: this._hash(converted),
      original: trimmed,
    };
  }

  _addWhiteRule(parsed) {
    this.wlHashes.add(parsed.hash);
    this.whitelist.set(parsed.hash, parsed.rule);
    this.domainIndex.set(parsed.domain, {
      type: "wl",
      rule: parsed.rule,
    });
  }

  _addBlackRule(parsed) {
    this.blHashes.add(parsed.hash);
    this.blacklist.set(parsed.hash, parsed.rule);
    this.domainIndex.set(parsed.domain, {
      type: "bl",
      rule: parsed.rule,
    });
  }

  _checkConflict(domain) {
    const parts = domain.split(".");
    for (let i = 0; i < parts.length; i++) {
      const checkDomain = parts.slice(i).join(".");
      const entry = this.domainIndex.get(checkDomain);
      if (entry && entry.type === "wl") {
        return entry;
      }
    }
    return null;
  }

  _compileResults() {
    return {
      whitelist: Array.from(this.whitelist.values()),
      blacklist: Array.from(this.blacklist.values()),
      excluded: {
        whitelist: {
          conflicts: this._mapToArray(this.excluded.whitelist.conflicts),
          duplicates: Array.from(this.excluded.whitelist.duplicates),
          invalid: Array.from(this.excluded.whitelist.invalid),
        },
        blacklist: {
          conflicts: this._mapToArray(this.excluded.blacklist.conflicts),
          duplicates: Array.from(this.excluded.blacklist.duplicates),
          invalid: Array.from(this.excluded.blacklist.invalid),
        },
      },
      stats: {
        total: {
          whitelist: this.whitelist.size,
          blacklist: this.blacklist.size,
        },
        excluded: {
          whitelist: {
            conflicts: this.excluded.whitelist.conflicts.size,
            duplicates: this.excluded.whitelist.duplicates.size,
            invalid: this.excluded.whitelist.invalid.size,
          },
          blacklist: {
            conflicts: this.excluded.blacklist.conflicts.size,
            duplicates: this.excluded.blacklist.duplicates.size,
            invalid: this.excluded.blacklist.invalid.size,
          },
        },
      },
    };
  }

  _mapToArray(map) {
    return Array.from(map.entries()).map(([rule, info]) => ({
      rule,
      ...info,
    }));
  }

  _hash(rule) {
    return createHash("sha1").update(rule).digest("hex");
  }

  _normalizeDomain(domain) {
    return domain
      .replace(/^\*\.|\.\*$/g, "")
      .toLowerCase()
      .split(".")
      .filter((p) => p !== "*")
      .join(".");
  }
}

// 使用示例
function optimizeProcessing(blacklist = [], whitelist = []) {
  const processor = new AdvancedAdGuardProcessor();
  const result = processor.process(whitelist, blacklist);
  return result;
}

/* 示例输出：
生效白名单: [ '@@||example.com^' ]
生效黑名单: [ '||tracker.com^' ]

排除的白名单规则:
- 冲突: []
- 重复: [ '@@||example.com^' ]
- 无效: [ '#@ invalid-whitelist' ]

排除的黑名单规则:
- 冲突: [ { rule: '||example.com^', reason: '被白名单规则阻止: @@||example.com^', ... } ]
- 重复: [ '||tracker.com^' ]
- 无效: [ 'invalid-blacklist' ]
*/
module.exports = { optimizeProcessing };
