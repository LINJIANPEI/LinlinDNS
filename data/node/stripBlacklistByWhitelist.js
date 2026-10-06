const { filters } = require("./common_func");

/**
 * 归类并分离黑/白名单（异步版）
 *
 * 步骤：
 *   1. 黑名单里混入的白名单规则（以 @@ 开头）→ 移到白名单
 *   2. 白名单里混入的黑名单规则（不以 @@ 开头）→ 移到黑名单
 *
 * @param {string[]} blacklist - 黑名单规则数组（可能混有 @@ 白名单）
 * @param {string[]} whitelist - 白名单规则数组（可能混有非 @@ 黑名单）
 * @param {Object} [options]
 * @param {string} [options.whitelistPrefix="@@"] - 白名单前缀标识
 * @returns {Promise<{
 *   blacklist: string[],
 *   whitelist: string[],
 *   toWhitelist: string[],
 *   toBlacklist: string[]
 * }>}
 */
const stripBlacklistByWhitelist = async (
  blacklist,
  whitelist,
  options = {},
) => {
  const { whitelistPrefix = "@@" } = options;
  console.log("开始归类剥离黑白名单");

  try {
    // ---------- 归类 ----------
    const isWhitelistRule = (rule) => rule.startsWith(whitelistPrefix);

    const normalizedBlacklist = [];
    const normalizedWhitelist = [];
    const toWhitelist = [];
    const toBlacklist = [];

    // 黑名单里混入的白名单规则 → 移到白名单
    for (const rule of blacklist) {
      if (isWhitelistRule(rule)) {
        normalizedWhitelist.push(rule);
        toWhitelist.push(rule);
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
        toBlacklist.push(rule);
      }
    }

    const remainingBlacklist = filters(normalizedBlacklist);
    const remainingWhitelist = filters(normalizedWhitelist);

    console.log(
      `归类剥离黑白名单完成，黑名单规则${remainingBlacklist.length}条，白名单规则${remainingWhitelist.length}条`,
    );

    return {
      blacklists: remainingBlacklist,
      whitelists: remainingWhitelist,
      toWhitelist,
      toBlacklist,
    };
  } catch (error) {
    throw new Error(`归类剥离黑白名单失败: ${error.message}`);
  }
};

module.exports = { stripBlacklistByWhitelist };
