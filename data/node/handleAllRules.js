const fs = require("fs");
const { promisify } = require("util");
const writeFile = promisify(fs.writeFile);
const readFile = promisify(fs.readFile);

// 处理所有规则的函数
const handleAllRules = async (...fileList) => {
  console.log("开始处理所有规则");

  for (const filePath of fileList) {
    try {
      // 读取文件内容
      const content = await readFile(filePath, "utf8");

      // 将文件内容按行分割成数组，并进行处理
      let processedContentArray = content.split("\n");

      processedContentArray = [...new Set(processedContentArray)]
        .map((line) => line.trim()) // 修剪每行的空白
        .filter((line) => line !== "") // 过滤掉空行
        .filter((line) => !/^!|^#[^#,^@,^%,^\$]|^\[.*\]$/.test(line)) // 过滤掉特定格式的行
        .filter((line) => !/(((^#)([^#]|$))|^#{4,}).*$/.test(line)) // 过滤掉更多特定格式的行
        .sort(); // 对行进行排序

      // 将处理后的内容重新组合成字符串
      const processedContentString = processedContentArray.join("\n");

      // 将处理后的内容写回文件
      await writeFile(filePath, processedContentString, "utf8");

      console.log(`文件 ${filePath} 处理成功`);
    } catch (fileError) {
      // 捕获并打印单个文件的错误
      console.error(`处理文件 ${filePath} 时出错: ${fileError.message}`);
    }
  }

  console.log("所有文件的规则处理完成");
};

module.exports = { handleAllRules };
