/**
 * 将规则统一转换为 AdGuard 格式，并分离黑白名单规则
 * @param {string[]} rules - 输入的规则数组（可以是 hosts 或 adblock 规则）
 * @returns {Array} 包含黑名单、白名单和未识别规则的数组
 */
const adGuardRulesFun = (rules) => {
  // 定义三个数组，分别用于保存黑名单、白名单和未识别的规则
  const blacklistRules = [];
  const whitelistRules = [];
  const noadGuardRules = [];

  // 遍历规则
  rules.forEach((line) => {
    const trimmed = line.trim();

    // 排除注释和空行
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("!")) {
      return;
    }

    // 处理 hosts 规则
    if (/^\d+\.\d+\.\d+\.\d+/.test(trimmed) || /^::/.test(trimmed)) {
      const domain = trimmed.split(/\s+/)[1];
      if (domain) {
        blacklistRules.push(`||${domain}^`);
      } else {
        noadGuardRules.push(line); // 无法解析域名的规则加入未识别规则
      }
    }
    // 处理 AdBlock 规则
    else if (/^\|\|/.test(trimmed)) {
      // blacklistRules.push(
      //   trimmed.includes("$") ? trimmed.replace("$", "$important,") : trimmed
      // );
      blacklistRules.push(trimmed);
    }
    // 处理白名单规则
    else if (/^@@/.test(trimmed)) {
      whitelistRules.push(trimmed);
    }
    // 其他未识别的规则
    else {
      noadGuardRules.push(line);
    }
  });

  // 返回一个包含黑名单、白名单和未识别规则的数组
  return [blacklistRules, whitelistRules, noadGuardRules];
};

/**
 * 去除黑白名单规则中的多余子域名，不区分黑白名单。
 * @param {string[]} rules - 包含黑白名单的规则数组。
 * @returns {string[]} 返回去重后的规则数组。
 */
const removeSubdomainDuplicates = (rules) => {
  const optimizedRules = [];

  // 辅助函数：提取主域名
  const getBaseDomain = (rule) => {
    return rule
      .replace(/^(\|\|)/, "")
      .replace(/^@@(\|\|)/, "")
      .replace(/\^.*$/, ""); // 去除前缀 "||" 和修饰符 "^"
  };

  rules.forEach((rule) => {
    const baseDomain = getBaseDomain(rule);
    // 如果没有找到相同的主域名，则添加到优化后的规则
    if (!optimizedRules.some((r) => getBaseDomain(r) === baseDomain)) {
      optimizedRules.push(rule);
    }
  });

  return optimizedRules;
};

module.exports = {
  adGuardRulesFun,
  removeSubdomainDuplicates,
};
