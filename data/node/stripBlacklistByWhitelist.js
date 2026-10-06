const { filters } = require("./common_func");

/**
 * 归类并分离黑/白名单（异步版）
 *
 * 归类规则：
 *   1. 有 @@ 前缀的规则 → 归到白名单
 *   2. 无 @@ 前缀的规则 → 留在原数组中，不移动
 *
 * @param {string[]} blacklist
 * @param {string[]} whitelist
 * @returns {Promise<{
 *   blacklist: string[],
 *   whitelist: string[],
 *   toWhitelist: string[]
 * }>}
 */
const stripBlacklistByWhitelist = async (blacklist, whitelist) => {
  console.log("开始归类剥离黑白名单");

  try {
    const WHITELIST_PREFIX = "@@";
    const isWhitelistRule = (rule) => rule.startsWith(WHITELIST_PREFIX);

    const normalizedBlacklist = [];
    const normalizedWhitelist = [];
    const toWhitelist = [];

    // ---------- 1. 黑名单数组：有 @@ 的移到白名单，其余留在黑名单 ----------
    for (const rule of blacklist) {
      if (isWhitelistRule(rule)) {
        normalizedWhitelist.push(rule);
        toWhitelist.push(rule);
      } else {
        normalizedBlacklist.push(rule);
      }
    }

    // ---------- 2. 白名单数组：全部留在白名单，无 @@ 也不移动 ----------
    for (const rule of whitelist) {
      normalizedWhitelist.push(rule);
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
    };
  } catch (error) {
    throw new Error(`归类剥离黑白名单失败: ${error.message}`);
  }
};

module.exports = { stripBlacklistByWhitelist };
