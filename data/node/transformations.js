const fs = require("fs");
const { promisify } = require("util");
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);
const compile = require("@adguard/hostlist-compiler");

// 规则转换函数
const transformations = async (...fileList) => {
  console.log("开始规则转换");

  try {
    for (const filePath of fileList) {
      try {
        // const content = await readFile(filePath, "utf8");

        // const contentArray = content.split("\n");
        // 过滤出符合正则表达式的行
        // 注意：这里修改了正则表达式匹配的逻辑，确保它符合您的需求
        // const filteredContentArray = contentArray;
        let contentAllow = await readFile("./tmp/tmp-allow.txt", "utf8");
        contentAllow = contentAllow.split("\n");
        let contentRules = await readFile("./tmp/tmp-rules.txt", "utf8");
        contentRules = contentRules.split("\n");
        if (filePath == "./tmp/tmp-allowFilter.txt") {
          // 官方规则转换工具
          const contentArray = await compile({
            name: "linlin",
            sources: [
              {
                type: "adblock",
                source: filePath,
              },
              {
                type: "hosts",
                source: filePath,
              },
            ],
            transformations: ["Compress", "Validate", "InvertAllow"],
          });
          const filteredContentArray = [...new Set(contentArray)]
            .filter((str) => !/^!/.test(str))
            .push(...contentAllow)
            .join("\n");
          await writeFile("./tmp/tmp-allow.txt", filteredContentArray, "utf8");
        } else {
          // 官方规则转换工具
          const contentArray = await compile({
            name: "linlin",
            sources: [
              {
                type: "adblock",
                source: filePath,
              },
              {
                type: "hosts",
                source: filePath,
              },
            ],
            transformations: ["Compress", "Validate"],
          });
          const filteredContentArray = [...new Set(contentArray)]
            .filter((str) => !/^!/.test(str))
            .push(...contentRules)
            .join("\n");
          await writeFile("./tmp/tmp-rules.txt", filteredContentArray, "utf8");
        }

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
