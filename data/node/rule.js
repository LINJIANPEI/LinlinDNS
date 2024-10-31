const fs = require("fs");
const { promisify } = require("util");
const readDir = promisify(fs.readdir);
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);

// 规则去重
const rule = async (directory) => {
  console.log("开始规则去重");
  try {
    // 读取当前目录下的所有文件
    const files = await readDir(directory).then((files) =>
      files.filter((file) => file.endsWith(".txt"))
    );
    for (let index = 0; index < files.length; index++) {
      const file = files[index];
      // 读取文件内容
      const data = await readFile(file, "utf8");
      const linesdata = lines
        .split("\n")
        .sort()
        .filter((line) => line.trim() !== "")
        .map((line) => line.trim())
        .filter((line) => !/(((^#)([^#]|$))|^#{4,}).*$/.test(line))
        .join("\n");
      await writeFile(file, linesdata, "utf8");
    }

    console.log("规则去重成功");
  } catch (error) {
    throw `规则去重失败:${error}`;
  }
};
module.exports = {
  rule,
};
