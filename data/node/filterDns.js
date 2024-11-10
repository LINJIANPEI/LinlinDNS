const fs = require("fs");
const { promisify } = require("util");
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);
//过滤DNS
const filterDns = async (directory) => {
  console.log("开始过滤DNS");

  try {
    // 读取文件
    const data = await readFile(`${directory}/rules.txt`, "utf8");
    // 处理数据
    const lines = data
      .split("\n")
      .map((line) => line.trim())
      .filter(
        (line) =>
          line.length >= 2 && line.startsWith("||") && line.endsWith("^")
      )
      .join("\n");
    // 写入文件
    await writeFile(`${directory}/dns.txt`, lines, "utf8");

    console.log("过滤DNS成功");
  } catch (error) {
    throw `过滤DNS失败:${error}`;
  }
};
module.exports = {
  filterDns,
};
