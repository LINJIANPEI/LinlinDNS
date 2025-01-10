const { filters, compileRules, readFile, writeFile } = require("./common_func");

// 规则转换函数
const compileRulesFun = async (tmpAllow, tmpRules, ...fileList) => {
  console.log("开始官方规则转换");

  try {
    for (const filePath of fileList) {
      try {
        const contentRules = await readFile(tmpRules);
        const contentRulesArray = contentRules.split("\n");

        const contentAllow = await readFile(tmpAllow);
        const contentAllowArray = contentAllow.split("\n");

        if (/allow/.test(filePath)) {
          const contentArray = await compileRules(filePath, true);
          const filteredContentArray = filters([
            ...contentArray,
            ...contentAllowArray,
          ]).join("\n");
          await writeFile(tmpAllow, filteredContentArray, "utf8");
        } else {
          const contentArray = await compileRules(filePath);
          const filteredContentArray = filters([
            ...contentArray,
            ...contentRulesArray,
          ]).join("\n");
          await writeFile(tmpRules, filteredContentArray, "utf8");
        }

        console.log(`处理文件 ${filePath} 完成。`);
      } catch (fileError) {
        // 捕获并打印单个文件的错误，但不中断整个流程
        throw new Error(`处理文件 ${filePath} 时出错: ${fileError.message}`);
      }
    }

    console.log("所有文件的官方规则转换完成");
  } catch (error) {
    // 捕获整个转换过程中的未处理错误
    throw new Error(`官方规则转换失败: ${error.message}`);
  }
};

module.exports = { compileRulesFun };
