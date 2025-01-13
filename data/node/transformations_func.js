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

/**
 * 异步处理规则数组，为符合条件的规则添加自定义前缀。
 *
 * @param {string[]} lines - 一个包含规则字符串的数组。
 * @param {string} [str=""] - 需要添加的前缀，默认为空字符串。
 * @returns {Promise<[string[], string[]]>} - 返回一个 Promise，解析为包含两部分数组的结果：[符合条件的规则数组，不符合条件的规则数组]。
 */
const processRuleLines = async (lines, str = "") => {
  return new Promise((resolve) => {
    // 用于存储不符合条件的规则
    let no = [];

    // 处理规则数组
    const yes = lines
      .map((line) => {
        // 判断是否为注释行或特定结构的行
        const isNotComment = !/^!|^＃|^！|^#[^#,^@,^%,^\$]|^\[.*\]$/.test(line);

        // 如果符合条件（不是注释行或特定结构的行），为规则添加自定义前缀
        if (isNotComment) {
          return line;
        } else {
          no.push(line);
          return null; // 确保 map 的长度与原数组一致
        }
      })
      .map((line) => {
        // 判断是否为注释行或特定结构的行
        const isNotValidStructure = !/(((^#)([^#]|$))|^#{4,}).*$/.test(line);

        // 如果符合条件（不是注释行或特定结构的行），为规则添加自定义前缀
        if (isNotValidStructure) {
          return line;
        } else {
          no.push(line);
          return null; // 确保 map 的长度与原数组一致
        }
      })
      .map((line) => {
        // 判断是否为注释行或特定结构的行
        const isNotValidStructure = !/^[\u4e00-\u9fa5]+$/.test(line);
        // 如果符合条件（不是注释行或特定结构的行），为规则添加自定义前缀
        if (isNotValidStructure) {
          return line;
        } else {
          no.push(line);
          return null; // 确保 map 的长度与原数组一致
        }
      })
      .map((line) => {
        // 判断是否为注释行或特定结构的行
        const isNotValidStructure = !/^##.*[\u4e00-\u9fa5].*$/.test(line);
        // 如果符合条件（不是注释行或特定结构的行），为规则添加自定义前缀
        if (isNotValidStructure) {
          return line;
        } else {
          no.push(line);
          return null; // 确保 map 的长度与原数组一致
        }
      })
      .map((line) => {
        // 判断是否为注释行或特定结构的行
        const isNotValidStructure = !/^##.*\[.*\].*$/.test(line);
        // 如果符合条件（不是注释行或特定结构的行），为规则添加自定义前缀
        if (isNotValidStructure) {
          return line;
        } else {
          no.push(line);
          return null; // 确保 map 的长度与原数组一致
        }
      })
      .filter(Boolean) // 移除 null 值
      .map((line) => {
        return `${str}${line}`;
      });
    resolve([yes, no]);
  });
};

module.exports = {
  removeSubdomainDuplicates,
  processRuleLines,
};
