const fs = require("fs");
const { promisify } = require("util");
const writeFile = promisify(fs.writeFile);
const readFile = promisify(fs.readFile);
const handleAllRules = async (...fileList) => {
  for (let i = 0; i < fileList.length; i++) {
    const fileLists = path.join(__dirname, fileList[i]);
    const content = await readFile(`${fileLists}`, "utf8");
    const contentArray = content.split("\n");
    // 将文件内容去重，过滤，排序
    contentArray = [...new Set(contentArray)]
      .sort()
      .filter((line) => !/^!|^#[^#,^@,^%,^\$]|^\[.*\]$/.test(line))
      .filter((line) => line.trim() !== "")
      .map((line) => line.trim())
      .filter((line) => !/(((^#)([^#]|$))|^#{4,}).*$/.test(line));

    const contentString = contentArray.join("\n");
    await writeFile(`${fileLists}`, contentString, "utf8");
  }
};
module.exports = {
  handleAllRules,
};
