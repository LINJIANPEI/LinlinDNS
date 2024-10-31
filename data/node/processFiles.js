const fs = require("fs");
const { promisify } = require("util");
const path = require("path");
const readDir = promisify(fs.readdir);
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);

// 合并规则
const processFiles = async (directory) => {
  console.log("开始合并规则");

  try {
    directory = path.join(__dirname, directory);
    // 读取列表文件名
    const files = await readDir(directory);
    // 过滤rules开头的txt文件
    const ruleFiles = files.filter(
      (file) => file.startsWith("rules") && file.endsWith(".txt")
    );
    // 读取所有文件内容
    const allruleData = await Promise.all(
      ruleFiles.map((file) => readFile(`${directory}/${file}`, "utf8"))
    );
    // 处理文件规则
    let allruleDatas = allruleData
      .join("\n")
      .split("\n")
      .filter((line) => !/^((\!)|(\[)).*/.test(line))
      .filter((line) => !/^!|^#[^#,^@,^%,^\$]|^\[.*\]$/.test(line))
      .join("\n");
    allruleDatas = [...new Set(allruleDatas.split("\n"))].join("\n");
    // 写入文件
    await writeFile(`${directory}/tmp-rules.txt`, allruleDatas, "utf8");

    // 读取列表文件名
    const filess = await readDir(directory);
    // 读取所有文件内容
    const allallowData = await Promise.all(
      filess.map((file) => readFile(`${directory}/${file}`, "utf8"))
    );
    // 处理文件规则
    let allallowDatas = allallowData
      .join("\n")
      .split("\n")
      .filter((line) => line.startsWith("@"))
      .filter((line) => !/^!|^#[^#,^@,^%,^\$]|^\[.*\]$/.test(line))
      .join("\n");
    allallowDatas = [...new Set(allallowDatas.split("\n"))].join("\n");
    // 写入文件
    await writeFile(`${directory}/tmp-allow.txt`, allallowDatas, "utf8");

    console.log("合并规则完成");
  } catch (error) {
    throw `合并规则失败:${error}`;
  }
};
module.exports = {
  processFiles,
};
