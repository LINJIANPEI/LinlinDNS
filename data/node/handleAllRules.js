const { filters, readFile, writeFile } = require("./common_func");

// 处理所有规则的函数
const handleAllRules = async (tmpAllow, tmpRules, ...fileList) => {
  console.log("开始处理所有规则");

  for (const filePath of fileList) {
    try {
      // 读取文件内容
      const content = await readFile(filePath);
      let contentAllow = await readFile(tmpAllow);
      contentAllow = contentAllow.split("\n");
      let contentRules = await readFile(tmpRules);
      contentRules = contentRules.split("\n");

      // 将文件内容按行分割成数组，并进行处理
      let processedContentArray = content.split("\n");

      processedContentArray = processedContentArray.filter((line) => {
        if (/^\|\|.*/.test(line) || /^\/.*\/$/.test(line)) {
          contentRules.push(line);
        } else if (/^@@.*/.test(line)) {
          contentAllow.push(line);
        } else {
          return line;
        }
      });
      // .filter((line) => !/^!|^#[^#,^@,^%,^\$]|^\[.*\]$/.test(line)) // 过滤掉特定格式的行
      // .filter((line) => !/(((^#)([^#]|$))|^#{4,}).*$/.test(line)) // 过滤掉更多特定格式的行

      // 将处理后的内容重新组合成字符串
      const processedContentString = filters(processedContentArray).join("\n");

      // 将处理后的内容写回文件
      await writeFile(filePath, processedContentString);
      await writeFile(tmpAllow, filters(contentAllow).join("\n"));
      await writeFile(tmpRules, filters(contentRules).join("\n"));

      console.log(`文件 ${filePath} 处理成功`);
    } catch (fileError) {
      // 捕获并打印单个文件的错误
      throw new Error(`处理文件 ${filePath} 时出错: ${fileError.message}`);
    }
  }

  console.log("所有文件的规则处理完成");
};

module.exports = { handleAllRules };
