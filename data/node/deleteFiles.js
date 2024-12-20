const fs = require("fs");
const { promisify } = require("util");
const path = require("path");
const deleteFile = promisify(fs.unlink);
const access = promisify(fs.access);

/**
 * 获取不带扩展名的文件名。
 * @param {string} filepath - 要获取的文件名路径。
 * @return {string} 获取的文件名。
 */
const getFilenameWithoutExtension = (filepath) => {
  const filenameWithExtension = path.basename(filepath);
  return path.parse(filenameWithExtension).name;
};

/**
 * 检查文件是否存在。
 * @param {string} filepath - 检查文件是否存在的文件名路径。
 * @return {boolean} 存在返回true，不存在返回false。
 */
async function fileExistsAsync(filePath) {
  try {
    await access(filePath, fs.constants.F_OK);
    return true;
  } catch (error) {
    return false;
  }
}

// 删除文件
/**
 * 检查文件是否存在。
 * @param {string} filePaths - 文件路径。
 */
const deleteFiles = async (...filePaths) => {
  console.log("开始删除文件");

  for (let filePath of filePaths) {
    try {
      if (await fileExistsAsync(filePath)) {
        await deleteFile(filePath);
        const fileName = getFilenameWithoutExtension(filePath);
        console.log(`删除文件${fileName}成功`);
      } else {
        console.log(`文件${filePath}不存在，无需删除`);
      }
    } catch (error) {
      console.error(`删除文件${filePath}失败: ${error.message}`);
    }
  }
};

module.exports = {
  deleteFiles,
};
