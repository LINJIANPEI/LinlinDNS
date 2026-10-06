/**
 * 归类并剥离黑/白名单（异步版）
 *
 * 步骤：
 *   1. 黑名单里混入的白名单规则（以 @@ 开头）→ 移到白名单
 *   2. 白名单里混入的黑名单规则（不以 @@ 开头）→ 移到黑名单
 *   3. 白名单匹配到的黑名单规则 → 从黑名单删除，同时该白名单规则也删除
 *
 * @param {string[]} blacklist - 黑名单规则数组（可能混有 @@ 白名单）
 * @param {string[]} whitelist - 白名单规则数组（可能混有非 @@ 黑名单）
 * @param {Object} [options]
 * @param {string} [options.whitelistPrefix="@@"] - 白名单前缀标识
 * @param {"exact"|"include"|"prefix"} [options.matchMode="include"] - 匹配模式
 * @returns {Promise<{
 *   blacklist: string[],
 *   whitelist: string[],
 *   removed: { blacklist: string[], whitelist: string[] },
 *   classified: { toWhitelist: string[], toBlacklist: string[] }
 * }>}
 */
const stripBlacklistByWhitelist = async (
  blacklist,
  whitelist,
  options = {},
) => {
  const { whitelistPrefix = "@@", matchMode = "include" } = options;
  console.log("开始归类剥离黑白名单");

  try {
    // ---------- 1. 归类 ----------
    const isWhitelistRule = (rule) => rule.startsWith(whitelistPrefix);

    const normalizedBlacklist = [];
    const normalizedWhitelist = [];
    const classified = { toWhitelist: [], toBlacklist: [] };

    // 黑名单里混入的白名单规则 → 移到白名单
    for (const rule of blacklist) {
      if (isWhitelistRule(rule)) {
        normalizedWhitelist.push(rule);
        classified.toWhitelist.push(rule);
      } else {
        normalizedBlacklist.push(rule);
      }
    }

    // 白名单里混入的黑名单规则 → 移到黑名单
    for (const rule of whitelist) {
      if (isWhitelistRule(rule)) {
        normalizedWhitelist.push(rule);
      } else {
        normalizedBlacklist.push(rule);
        classified.toBlacklist.push(rule);
      }
    }

    // ---------- 2. 剥离 ----------
    const normalizeWhitelist = (rule) =>
      rule.startsWith(whitelistPrefix)
        ? rule.slice(whitelistPrefix.length)
        : rule;

    const isAllowed = (blRule, wlContent) => {
      if (!wlContent) return false;
      switch (matchMode) {
        case "exact":
          return blRule === wlContent;
        case "prefix":
          return blRule.startsWith(wlContent);
        case "include":
        default:
          return blRule.includes(wlContent) || wlContent.includes(blRule);
      }
    };

    const remainingBlacklist = [];
    const matchedWhitelistSet = new Set();
    const removedBlacklist = [];

    for (const blRule of normalizedBlacklist) {
      let allowed = false;
      for (const wlRule of normalizedWhitelist) {
        const wlContent = normalizeWhitelist(wlRule);
        if (isAllowed(blRule, wlContent)) {
          allowed = true;
          matchedWhitelistSet.add(wlRule);
          break;
        }
      }
      if (allowed) {
        removedBlacklist.push(blRule);
      } else {
        remainingBlacklist.push(blRule);
      }
    }

    // 被匹配使用的白名单规则也删除
    const remainingWhitelist = normalizedWhitelist.filter(
      (wlRule) => !matchedWhitelistSet.has(wlRule),
    );
    console.log(
      `归类剥离黑白名单完成，白名单规则${remainingBlacklist.length}条，白名单规则${remainingWhitelist.length}条`,
    );

    return {
      blacklist: remainingBlacklist,
      whitelist: remainingWhitelist,
      removed: {
        blacklist: removedBlacklist,
        whitelist: [...matchedWhitelistSet],
      },
      classified,
    };
  } catch (error) {
    throw new Error(`归类剥离黑白名单失败: ${error.message}`);
  }
};

module.exports = { stripBlacklistByWhitelist };
