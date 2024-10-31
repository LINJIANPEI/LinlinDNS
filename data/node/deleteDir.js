const fs = require("fs");
const path = require("path");
const { promisify } = require("util");
const mkdir = promisify(fs.rm);

async function directoryExistsAsync(dirPath) {
  try {
    const stat = promisify(fs.stat);
    const stats = await stat(dirPath);
    return stats.isDirectory();
  } catch (error) {
    return false;
  }
}
// 删除临时文件夹
const deleteDir = async (directory) => {
  console.log("开始删除临时文件夹");
  try {
    if (await directoryExistsAsync(directory)) {
      await mkdir(directory, { recursive: true, force: true });
      console.log("删除临时文件夹成功");
    }
  } catch (error) {
    throw `删除临时文件夹失败:${error}`;
  }
};

module.exports = {
  deleteDir,
};
