/**
 * 去除黑白名单规则中的多余子域名，不区分黑白名单。
 * @param {string[]} rules - 包含黑白名单的规则数组。
 * @returns {string[]} 返回去重后的规则数组。
 */
const removeSubdomainDuplicates = (rules) => {
  const optimizedRules = [];
  const seenDomains = new Set(); // 用于存储已经处理过的主域名

  // 辅助函数：提取主域名
  const getBaseDomain = (rule) => {
    return rule
      .replace(/^(\|\|)/, "")
      .replace(/^@@(\|\|)/, "")
      .replace(/\^.*$/, ""); // 去除前缀 "||" 和修饰符 "^"
  };

  rules.forEach((rule) => {
    const baseDomain = getBaseDomain(rule);
    // 如果主域名没有出现过，则添加到优化后的规则
    if (!seenDomains.has(baseDomain)) {
      optimizedRules.push(rule);
      seenDomains.add(baseDomain); // 标记此主域名已处理
    }
  });

  return optimizedRules;
};

module.exports = {
  removeSubdomainDuplicates,
};
