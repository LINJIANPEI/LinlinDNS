const fs = require("fs");
const { promisify } = require("util");
const readDir = promisify(fs.readdir);
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);

// 合并规则
const mergeBlacklists = async (directory) => {
  console.log("开始合并黑名单规则");
  try {
    // 读取列表文件名
    const fileList = await readDir(directory);
    // 过滤出以"rules"开头且以".txt"结尾的文件
    const rulesFiles = fileList.filter(
      (file) => file.startsWith("rules") && file.endsWith(".txt")
    );

    // 如果没有找到符合条件的文件，打印消息并返回
    if (rulesFiles.length === 0) {
      console.log("没有找到符合条件的黑名单文件");
      return;
    }

    // 读取所有文件内容
    const allFileData = await Promise.all(
      rulesFiles.map((file) => readFile(`${directory}/${file}`, "utf8"))
    );

    // 处理文件规则
    const allFileDatas = allFileData
      .join("\n")
      .split("\n")
      .filter((line) => !/^((\!)|(\[)).*/.test(line))
      .join("\n");
    // 写入文件
    await writeFile(`${directory}/tmp-rules.txt`, allFileDatas, "utf8");

    console.log(`合并白名单规则完成，共处理了${rulesFiles.length}个文件`);
  } catch (error) {
    console.error(`合并黑名单规则失败: ${error.message}`);
    throw new Error(`合并黑名单规则失败: ${error.message}`);
  }
};
module.exports = {
  mergeBlacklists,
};
