const fs = require("fs");
const { promisify } = require("util");
const writeFile = promisify(fs.writeFile);
const readFile = promisify(fs.readFile);
const handleAllRules = async (...fileList) => {
  console.log("开始处理所有规则");

  try {
    for (let i = 0; i < fileList.length; i++) {
      const content = await readFile(`${fileList[i]}`, "utf8");
      let contentArray = content.split("\n");
      // 将文件内容去重，排序，过滤
      contentArray = [...new Set(contentArray)]
        .sort()
        .filter((line) => !/^!|^#[^#,^@,^%,^\$]|^\[.*\]$/.test(line))
        .filter((line) => line.trim() !== "")
        .map((line) => line.trim())
        .filter((line) => !/(((^#)([^#]|$))|^#{4,}).*$/.test(line));

      const contentString = contentArray.join("\n");
      await writeFile(`${fileList[i]}`, contentString, "utf8");
      console.log("处理所有规则成功");
    }
  } catch (error) {
    throw `处理所有规则失败:${error}`;
  }
};
module.exports = {
  handleAllRules,
};
