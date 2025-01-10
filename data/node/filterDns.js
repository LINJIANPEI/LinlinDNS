const { readFile, writeFile } = require("./common_func");
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
    console.error(`过滤DNS规则失败: ${error.message}`);
    throw new Error(`过滤DNS规则时发生错误: ${error.message}`);
  }
};
module.exports = {
  filterDns,
};
