const { filters, readFile, writeFile } = require("./common_func");
const { adGuardRulesFun } = require("./transformations_func");

// 规则转换函数
const transformations = async (tmpAllow, tmpRules, ...fileList) => {
  console.log("开始规则转换");

  try {
    for (const filePath of fileList) {
      try {
        const content = await readFile(filePath);
        const contentArray = content.split("\n");
        const [blacklistRules, whitelistRules, noadGuardRules] =
          adGuardRulesFun(contentArray);

        const contentRules = await readFile(tmpRules);
        const contentRulesArray = contentRules.split("\n");
        const blacklistRulesArray = filters([
          ...blacklistRules,
          ...contentRulesArray,
        ]).join("\n");
        await writeFile(tmpRules, blacklistRulesArray);

        const contentAllow = await readFile(tmpAllow);
        const contentAllowArray = contentAllow.split("\n");
        const whitelistRulesArray = filters([
          ...whitelistRules,
          ...contentAllowArray,
        ]).join("\n");
        await writeFile(tmpAllow, whitelistRulesArray);

        const noadGuardRulesArray = filters(noadGuardRules).join("\n");
        await writeFile(filePath, noadGuardRulesArray);

        console.log(`处理文件 ${filePath} 完成。`);
      } catch (fileError) {
        // 捕获并打印单个文件的错误，但不中断整个流程
        console.error(`处理文件 ${filePath} 时出错: ${fileError.message}`);
      }
    }

    console.log("所有文件的规则转换完成");
  } catch (error) {
    // 捕获整个转换过程中的未处理错误
    console.error(`规则转换过程中发生未处理的错误: ${error.message}`);
    throw new Error(`规则转换失败: ${error.message}`);
  }
};

module.exports = { transformations };
