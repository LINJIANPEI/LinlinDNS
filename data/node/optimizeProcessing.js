const { createHash } = require("crypto");

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
    rules.forEach((original) => {
      const parsed = this._parseRule(original, isWhitelist);
      const target = isWhitelist ? "whitelist" : "blacklist";

      if (!parsed.valid) {
        this.excluded[target].invalid.add(original);
        return;
      }

      if (this._isDuplicate(parsed.hash)) {
        this.excluded[target].duplicates.set(original, {
          existingRule: this._findExistingRule(parsed.hash),
        });
        return;
      }

      if (this._hasConflict(parsed.domain, !isWhitelist)) {
        this.excluded[target].conflicts.set(original, {
          reason: `与${isWhitelist ? "黑名单" : "白名单"}规则冲突`,
          conflictingRule: this._findConflictingRule(parsed.domain),
        });
        return;
      }

      this._addEffectiveRule(parsed, original, target);
    });
  }

  _parseRule(original, isWhitelist) {
    const trimmed = original.trim();
    if (!trimmed || trimmed.startsWith("!")) return { valid: false };

    try {
      if (isWhitelist) {
        const match = trimmed.match(/^@@\|\|([\w\-.*]+)\^/);
        if (!match) return { valid: false };
        const domain = this._normalizeDomain(match[1]);
        return {
          valid: true,
          domain,
          hash: this._hash(`@@||${domain}^`),
          converted: `@@||${domain}^`,
        };
      } else {
        const converted = this._convertBlackRule(trimmed);
        return {
          valid: true,
          domain: converted.domain,
          hash: this._hash(converted.rule),
          converted: converted.rule,
        };
      }
    } catch {
      return { valid: false };
    }
  }

  _convertBlackRule(rule) {
    // 转换逻辑（同之前实现）
    // 返回 { domain: string, rule: string }
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
        whitelist: Array.from(this.effective.whitelist.values()).map(
          (v) => v.converted
        ),
        blacklist: Array.from(this.effective.blacklist.values()).map(
          (v) => v.converted
        ),
      },

      // 原始格式的排除规则
      excluded: {
        whitelist: {
          conflicts: Array.from(
            this.excluded.whitelist.conflicts.entries()
          ).map(([original, info]) => ({ original, ...info })),
          duplicates: Array.from(
            this.excluded.whitelist.duplicates.entries()
          ).map(([original, info]) => ({ original, ...info })),
          invalid: Array.from(this.excluded.whitelist.invalid),
        },
        blacklist: {
          conflicts: Array.from(
            this.excluded.blacklist.conflicts.entries()
          ).map(([original, info]) => ({ original, ...info })),
          duplicates: Array.from(
            this.excluded.blacklist.duplicates.entries()
          ).map(([original, info]) => ({ original, ...info })),
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

  // 辅助方法
  _hash(rule) {
    return createHash("sha256").update(rule).digest("hex");
  }

  _normalizeDomain(domain) {
    return domain.replace(/^\*\.|\.\*$/g, "").toLowerCase();
  }

  _updateDomainIndex(domain, isWhitelist) {
    const parts = domain.split(".");
    for (let i = 0; i < parts.length; i++) {
      const subDomain = parts.slice(i).join(".");
      if (!this.domainTree.has(subDomain)) {
        this.domainTree.set(subDomain, { isWhitelist });
      }
    }
  }

  _findExistingRule(hash) {
    return (
      this.effective.whitelist.get(hash)?.converted ||
      this.effective.blacklist.get(hash)?.converted
    );
  }

  _findConflictingRule(domain) {
    const parts = domain.split(".");
    for (let i = 0; i < parts.length; i++) {
      const checkDomain = parts.slice(i).join(".");
      const entry = this.domainTree.get(checkDomain);
      if (entry) {
        return entry.isWhitelist
          ? this.effective.whitelist.get(this._hash(`@@||${checkDomain}^`))
              ?.converted
          : this.effective.blacklist.get(this._hash(`||${checkDomain}^`))
              ?.converted;
      }
    }
    return null;
  }
}

// 使用示例
function optimizeProcessing(blacklist = [], whitelist = []) {
  const processor = new FilteredAdGuardProcessor();
  const result = processor.process(whitelist, blacklist);
  console.log("\n统计信息:", result.stats);
  return result;
}

// console.log('转换后的有效规则:');
// console.log('- 白名单:', result.effective.whitelist);
// console.log('- 黑名单:', result.effective.blacklist);

// console.log('\n排除的冲突规则:');
// console.log('- 白名单:', result.excluded.whitelist.conflicts);
// console.log('- 黑名单:', result.excluded.blacklist.conflicts);

// console.log('\n统计信息:', result.stats);

// {
//   effective: {
//     whitelist: ['@@||safe.com^'],
//     blacklist: ['||tracker.com^']
//   },
//   excluded: {
//     whitelist: {
//       conflicts: [{
//         original: '@@||conflict.com^',
//         reason: '与黑名单规则冲突',
//         conflictingRule: '||conflict.com^'
//       }],
//       duplicates: [{
//         original: '@@||safe.com^',
//         existingRule: '@@||safe.com^'
//       }],
//       invalid: ['invalid-whitelist']
//     },
//     blacklist: {
//       conflicts: [{
//         original: '||safe.com^',
//         reason: '与白名单规则冲突',
//         conflictingRule: '@@||safe.com^'
//       }],
//       duplicates: [{
//         original: '||tracker.com^',
//         existingRule: '||tracker.com^'
//       }],
//       invalid: ['invalid-blacklist']
//     }
//   },
//   stats: {
//     totalProcessed: 7,
//     effective: { total: 2, whitelist: 1, blacklist: 1 },
//     excluded: {
//       total: 5,
//       whitelist: { conflicts: 1, duplicates: 1, invalid: 1 },
//       blacklist: { conflicts: 1, duplicates: 1, invalid: 1 }
//     }
//   }
// }

module.exports = { optimizeProcessing };
