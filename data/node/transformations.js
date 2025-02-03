// 规则转换函数
const transformations = async (...fileList) => {
  console.log("开始规则转换");
  let confilter = [];
  try {
    for (const [index, rules] of fileList.entries()) {
      try {
        // 定义三个数组，分别用于保存黑名单、白名单和未识别的规则
        const blacklistRules = [];
        const whitelistRules = [];
        const noadGuardRules = [];

        // 遍历规则
        rules.forEach((line) => {
          const trimmed = line.trim();

          // 排除注释和空行
          if (!trimmed) {
            return;
          }

          // 处理 hosts 规则
          if (/^\d+\.\d+\.\d+\.\d+/.test(trimmed) || /^::/.test(trimmed)) {
            const domain = trimmed.split(/\s+/)[1];
            if (domain) {
              // blacklistRules.push(`||${domain}^`);
              noadGuardRules.push(line); // 无法解析域名的规则加入未识别规则
            } else {
              noadGuardRules.push(line); // 无法解析域名的规则加入未识别规则
            }
          }
          // 处理 AdBlock 规则
          else if (/^\|\|/.test(trimmed)) {
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
        confilter.push([blacklistRules, whitelistRules, noadGuardRules]);
        console.log(
          `处理文件 ${index} 完成,过滤黑名单规则${blacklistRules.length}条,过滤白名单规则${whitelistRules.length}条,排除${noadGuardRules.length}条`
        );
      } catch (fileError) {
        // 捕获并打印单个文件的错误，但不中断整个流程
        console.error(`处理文件 ${index} 时出错: ${fileError.message}`);
        throw new Error(`处理文件 ${index} 时出错: ${fileError.message}`);
      }
    }
    console.log("所有文件的规则转换完成");
    return confilter;
  } catch (error) {
    // 捕获整个转换过程中的未处理错误
    throw new Error(`规则转换失败: ${error.message}`);
  }
};

module.exports = { transformations };
