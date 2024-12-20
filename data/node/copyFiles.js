const fs = require("fs");
const { promisify } = require("util");
const copyFile = promisify(fs.copyFile);
const access = promisify(fs.access);

// 检查文件是否存在
const fileExistsAsync = async (filePath) => {
  try {
    await access(filePath, fs.constants.F_OK);
    return true;
  } catch (error) {
    return false;
  }
};

// 复制文件
const copyFiles = async (oldPath, newPath) => {
  try {
    console.log("开始复制文件");
    // 检查源文件是否存在
    if (await fileExistsAsync(oldPath)) {
      // 复制文件并等待完成
      await copyFile(oldPath, newPath);
      console.log("文件复制成功");
    } else {
      console.error("源文件不存在");
    }
  } catch (error) {
    throw `复制文件失败: ${error}`;
  }
};

module.exports = { copyFiles };
