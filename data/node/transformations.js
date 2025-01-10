const { filters, compileRules, readFile, writeFile } = require("./common_func");
const { adGuardRulesFun } = require("./transformations_func");

// 规则转换函数
const transformations = async (tmpAllow, tmpRules, ...fileList) => {
  console.log("开始规则转换");

  try {
    for (const filePath of fileList) {
      try {
        const content = await readFile(filePath);

        const contentArray = content.split("\n");
        // 过滤出符合正则表达式的行
        // 注意：这里修改了正则表达式匹配的逻辑，确保它符合您的需求
        // const filteredContentArray = contentArray;
        let contentAllow = await readFile(tmpAllow);
        contentAllow = contentAllow.split("\n");
        let contentRules = await readFile(tmpRules);
        contentRules = contentRules.split("\n");

        const [blacklistRules, whitelistRules, noadGuardRules] =
          adGuardRulesFun(contentArray);
        const blacklistRulesArray = filters([
          ...blacklistRules,
          ...contentRules,
        ]).join("\n");
        await writeFile(tmpRules, blacklistRulesArray);
        const whitelistRulesArray = filters([
          ...whitelistRules,
          ...contentAllow,
        ]).join("\n");
        await writeFile(tmpAllow, whitelistRulesArray);
        const noadGuardRulesArray = noadGuardRules.join("\n");
        await writeFile(filePath, noadGuardRulesArray);
        // if (/allow/.test(filePath)) {
        //   const contentArray = await compileRules(filePath, true);
        //   const filteredContentArray = filters([
        //     ...contentArray,
        //     ...contentAllow,
        //   ]).join("\n");
        //   await writeFile(tmpAllow, filteredContentArray, "utf8");
        // } else {
        //   const contentArray = await compileRules(filePath);
        //   const filteredContentArray = filters([
        //     ...contentArray,
        //     ...contentRules,
        //   ]).join("\n");
        //   await writeFile(tmpRules, filteredContentArray, "utf8");
        // }

        // 将过滤后的内容重新组合成字符串
        // const filteredContentString = filteredContentArray.join("\n");

        // 将过滤后的内容写回文件
        // await writeFile(filePath, filteredContentString, "utf8");
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
