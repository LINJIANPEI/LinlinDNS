const { createHash } = require("crypto");

// 预编译正则表达式
const WHITELIST_REGEX = /^@@\|\|([\w\-.*]+)\^/;
const ADGUARD_REGEX   = /^\|\|([\w\-.*]+)\^/;
const HOSTS_REGEX     = /^\d+\.\d+\.\d+\.\d+\s+([\w\-.]+)/;
const ADBLOCK_REGEX   = /^(\|{1,2})([\w\-.*]+)/;

class FilteredAdGuardProcessor {
  constructor() {
    // 存储转换后的有效规则
    this.effective = {
      whitelist: new Map(), // hash => { original, converted }
      blacklist: new Map(),
    };

    // 排除规则存储
    this.excluded = {
      whitelist: {
        conflicts: new Map(), // original => { reason, conflictingRule }
        duplicates: new Map(), // original => { existingRule }
        invalid: new Set(),
      },
      blacklist: {
        conflicts: new Map(),
        duplicates: new Map(),
        invalid: new Set(),
      },
    };

    // 索引存储
    this.ruleHashes = new Set(); // 所有规则哈希
    this.domainTree = new Map(); // 域名冲突索引
  }

  process(whitelist, blacklist) {
    this._processList(whitelist, true);
    this._processList(blacklist, false);
    return this._compileResults();
  }

  _processList(rules, isWhitelist) {
    const target = isWhitelist ? "whitelist" : "blacklist";
    for (const original of rules) {
      const parsed = this._parseRule(original, isWhitelist);
      if (!parsed.valid) {
        this.excluded[target].invalid.add(original);
        continue;
      }

      if (this._isDuplicate(parsed.hash)) {
        this.excluded[target].duplicates.set(original, {
          existingRule: this._findExistingRule(parsed.hash),
        });
        continue;
      }

      // 检查与对立列表的冲突
      if (this._hasConflict(parsed.domain, !isWhitelist)) {
        this.excluded[target].conflicts.set(original, {
          reason: `与${isWhitelist ? "黑名单" : "白名单"}规则冲突`,
          conflictingRule: this._findConflictingRule(parsed.domain),
        });
        continue;
      }

      this._addEffectiveRule(parsed, original, target);
    }
  }

  _parseRule(original, isWhitelist) {
    const trimmed = original.trim();
    if (!trimmed || trimmed.startsWith("!")) return { valid: false };

    try {
      if (isWhitelist) {
        const match = trimmed.match(WHITELIST_REGEX);
        if (!match) return { valid: false };
        const domain = this._normalizeDomain(match[1]);
        const converted = `@@||${domain}^`;
        return {
          valid: true,
          domain,
          hash: this._hash(converted),
          converted,
        };
      } else {
        const { domain, rule } = this._convertBlackRule(trimmed);
        return {
          valid: true,
          domain,
          hash: this._hash(rule),
          converted: rule,
        };
      }
    } catch {
      return { valid: false };
    }
  }

  _convertBlackRule(rule) {
    const trimmed = rule.trim();
    let domain, converted;
    let match;

    // 1. 处理 AdGuard 格式：||example.com^
    if ((match = trimmed.match(ADGUARD_REGEX))) {
      domain = match[1];
      converted = trimmed; // 已经是 AdGuard 格式
    }
    // 2. 处理 Hosts 格式：127.0.0.1 example.com
    else if ((match = trimmed.match(HOSTS_REGEX))) {
      domain = match[1];
      converted = `||${domain}^`; // 转换为 AdGuard 格式
    }
    // 3. 处理 ABlock 格式：|example.com 或 ||example.com
    else if ((match = trimmed.match(ADBLOCK_REGEX))) {
      const [, prefix, rawDomain] = match;
      domain = rawDomain;
      converted = prefix === "|" ? `||${domain}^` : `${prefix}${domain}^`;
    }
    // 4. 无效格式
    else {
      throw new Error("Invalid blacklist rule format");
    }

    return {
      domain: this._normalizeDomain(domain),
      rule: converted,
    };
  }

  _isDuplicate(hash) {
    return this.ruleHashes.has(hash);
  }

  _hasConflict(domain, checkWhitelist) {
    const parts = domain.split(".");
    for (let i = 0; i < parts.length; i++) {
      const checkDomain = parts.slice(i).join(".");
      const existing = this.domainTree.get(checkDomain);
      if (existing && existing.isWhitelist === checkWhitelist) {
        return true;
      }
    }
    return false;
  }

  _addEffectiveRule(parsed, original, target) {
    this.effective[target].set(parsed.hash, {
      original,
      converted: parsed.converted,
    });
    this.ruleHashes.add(parsed.hash);
    this._updateDomainIndex(parsed.domain, target === "whitelist");
  }

  _compileResults() {
    return {
      // 转换后的有效规则
      effective: {
        whitelist: Array.from(this.effective.whitelist.values()).map(v => v.converted),
        blacklist: Array.from(this.effective.blacklist.values()).map(v => v.converted),
      },
      // 原始格式的排除规则
      excluded: {
        whitelist: {
          conflicts: Array.from(this.excluded.whitelist.conflicts.entries()).map(([original, info]) => ({ original, ...info })),
          duplicates: Array.from(this.excluded.whitelist.duplicates.entries()).map(([original, info]) => ({ original, ...info })),
          invalid: Array.from(this.excluded.whitelist.invalid),
        },
        blacklist: {
          conflicts: Array.from(this.excluded.blacklist.conflicts.entries()).map(([original, info]) => ({ original, ...info })),
          duplicates: Array.from(this.excluded.blacklist.duplicates.entries()).map(([original, info]) => ({ original, ...info })),
          invalid: Array.from(this.excluded.blacklist.invalid),
        },
      },
      // 统计信息
      stats: {
        totalProcessed:
          this.ruleHashes.size +
          this.excluded.whitelist.conflicts.size +
          this.excluded.whitelist.duplicates.size +
          this.excluded.whitelist.invalid.size +
          this.excluded.blacklist.conflicts.size +
          this.excluded.blacklist.duplicates.size +
          this.excluded.blacklist.invalid.size,
        effective: {
          total: this.effective.whitelist.size + this.effective.blacklist.size,
          whitelist: this.effective.whitelist.size,
          blacklist: this.effective.blacklist.size,
        },
        excluded: {
          total:
            this.excluded.whitelist.conflicts.size +
            this.excluded.whitelist.duplicates.size +
            this.excluded.whitelist.invalid.size +
            this.excluded.blacklist.conflicts.size +
            this.excluded.blacklist.duplicates.size +
            this.excluded.blacklist.invalid.size,
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

  // 辅助方法：生成规则哈希
  _hash(rule) {
    return createHash("sha256").update(rule).digest("hex");
  }

  // 辅助方法：标准化域名
  _normalizeDomain(domain) {
    return domain.replace(/^\*\.|\.\*$/g, "").toLowerCase();
  }

  // 更新域名索引，便于冲突检测
  _updateDomainIndex(domain, isWhitelist) {
    const parts = domain.split(".");
    for (let i = 0; i < parts.length; i++) {
      const subDomain = parts.slice(i).join(".");
      if (!this.domainTree.has(subDomain)) {
        this.domainTree.set(subDomain, { isWhitelist });
      }
    }
  }

  // 查找已存在的规则（用于重复检测）
  _findExistingRule(hash) {
    return (
      this.effective.whitelist.get(hash)?.converted ||
      this.effective.blacklist.get(hash)?.converted
    );
  }

  // 查找冲突规则（用于冲突排除）
  _findConflictingRule(domain) {
    const parts = domain.split(".");
    for (let i = 0; i < parts.length; i++) {
      const checkDomain = parts.slice(i).join(".");
      const entry = this.domainTree.get(checkDomain);
      if (entry) {
        return entry.isWhitelist
          ? this.effective.whitelist.get(this._hash(`@@||${checkDomain}^`))?.converted
          : this.effective.blacklist.get(this._hash(`||${checkDomain}^`))?.converted;
      }
    }
    return null;
  }
}

// 使用示例，保持原有入参和出参格式
const optimizeProcessing = async (blacklist = [], whitelist = []) => {
  const processor = new FilteredAdGuardProcessor();
  const result = processor.process(whitelist, blacklist);
  console.log("\n统计信息:", result.stats);
  return result;
};

module.exports = { optimizeProcessing };
