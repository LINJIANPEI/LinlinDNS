const fs = require("fs");
const { promisify } = require("util");
const path = require("path");
const readDir = promisify(fs.readdir);
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);

// 合并规则
const mergeWhitelist = async (directory) => {
  console.log("开始合并白名单规则");

  try {
    // 读取列表文件名
    const fileList = await readDir(directory);
    // 过滤rules开头的txt文件
    const fileLists = fileList.filter(
      (file) => file.startsWith("allow") && file.endsWith(".txt")
    );
    // 读取所有文件内容
    const allFileData = await Promise.all(
      fileLists.map((file) => readFile(`${directory}/${file}`, "utf8"))
    );
    // 处理文件规则
    const allFileDatas = allFileData
      .join("\n")
      .split("\n")
      .filter((line) => line.startsWith("@"))
      .join("\n");
    // 写入文件
    await writeFile(`${directory}/tmp-allow.txt`, allFileDatas, "utf8");

    console.log("合并白名单规则完成");
  } catch (error) {
    throw `合并白名单规则失败:${error}`;
  }
};
module.exports = {
  mergeWhitelist,
};
