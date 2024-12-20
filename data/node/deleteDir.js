const fs = require("fs");
const { promisify } = require("util");
const stat = promisify(fs.stat);
const rmdir = promisify(fs.rm);

/**
 * 检查文件夹是否存在。
 * @param {string} dirPath - 要检查的文件夹路径。
 * @return {boolean} 存在返回true，不存在返回false。
 */
const directoryExistsAsync = async (dirPath) => {
  try {
    const stats = await stat(dirPath);
    return stats.isDirectory();
  } catch (error) {
    // 如果文件/文件夹不存在或无法访问，返回false
    return false;
  }
};

/**
 * 创建一个指定的文件夹。
 * @param {string} directory - 要删除的文件夹路径。
 * @throws {Error} 如果文件夹删除失败，则抛出错误。
 */
const deleteDir = async (directory) => {
  console.log("开始删除临时文件夹:", directory);

  try {
    // 检查文件夹是否存在
    if (await directoryExistsAsync(directory)) {
      // 使用正确的函数来删除文件夹，并传递正确的选项
      await rmdir(directory, { recursive: true, force: true });
      console.log("删除临时文件夹成功:", directory);
    } else {
      console.log("文件夹不存在，无需删除:", directory);
    }
  } catch (error) {
    // 改进错误消息，提供更具体的错误原因
    const errorMessage = `删除临时文件夹失败: ${error.message} (路径: ${directory})`;
    console.error(errorMessage);
    throw new Error(errorMessage);
  }
};

module.exports = { deleteDir };
