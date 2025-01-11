const { filters, readFile, writeFile, readDir } = require("./common_func");

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
      rulesFiles.map((file) => readFile(`${directory}/${file}`))
    );

    let allFileDataFilter = [];
    // 处理文件规则
    let allFileDatas = allFileData
      .join("\n")
      .split("\n")
      // .filter((line) => {
      //   if (!/^((\!)|(\[)).*/.test(line)) {
      //     return line;
      //   } else {
      //     allFileDataFilter.push(line);
      //   }
      // })
      .filter((line) => {
        if (/^\|\|.*/.test(line) || /^\/.*\/$/.test(line)) {
          return line;
        } else {
          allFileDataFilter.push(line);
        }
      });

    console.log(`合并白名单规则完成，共处理了${rulesFiles.length}个文件`);
    return [filters(allFileDatas), filters(allFileDataFilter)];
  } catch (error) {
    throw new Error(`合并黑名单规则失败: ${error.message}`);
  }
};
module.exports = {
  mergeBlacklists,
};
