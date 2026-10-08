// 识别 /pattern/ 或 @@/pattern/，兼容尾部修饰符（如 /ads/$important）
const REGEX_LINE_RE = /^(@@)?\/.+\/[^/]*$/;

function isRegexRuleLine(line) {
  return REGEX_LINE_RE.test(String(line).trim());
}

/**
 * 从黑白名单数组里分离出正则规则。
 *
 * @param {string[]} blacklist  黑名单数组（形如 "||a.com^"、"/ads/"）
 * @param {string[]} whitelist  白名单数组（形如 "@@||a.com^$important"、"@@/ads/"）
 * @returns {{
 *   regexBlacklist: string[],
 *   regexWhitelist: string[],
 *   restBlacklist: string[],
 *   restWhitelist: string[]
 * }}
 */
function splitRegexRules(blacklist = [], whitelist = []) {
  if (!Array.isArray(blacklist) || !Array.isArray(whitelist)) {
    throw new TypeError("blacklist / whitelist 必须是字符串数组");
  }

  const regexBlacklist = [];
  const regexWhitelist = [];
  const restBlacklist = [];
  const restWhitelist = [];

  for (const line of blacklist) {
    if (line == null) continue;
    const s = String(line).trim();
    if (!s) continue;
    if (isRegexRuleLine(s)) regexBlacklist.push(s);
    else restBlacklist.push(line);
  }

  for (const line of whitelist) {
    if (line == null) continue;
    const s = String(line).trim();
    if (!s) continue;
    if (isRegexRuleLine(s)) regexWhitelist.push(s);
    else restWhitelist.push(line);
  }

  return { regexBlacklist, regexWhitelist, restBlacklist, restWhitelist };
}
module.exports = {
  splitRegexRules,
};
