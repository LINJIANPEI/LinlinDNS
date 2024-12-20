const fs = require("fs");
const { promisify } = require("util");
const mkdir = promisify(fs.mkdir);

/**
 * 创建一个指定的文件夹。
 * @param {string} directory - 要创建的文件夹路径。
 * @throws {Error} 如果文件夹创建失败，则抛出错误。
 */
const createDir = async (directory) => {
  console.log("开始创建临时文件夹:", directory);

  try {
    // 尝试创建文件夹，如果需要则递归创建父文件夹
    await mkdir(directory, { recursive: true });
    console.log("创建临时文件夹成功:", directory);
  } catch (error) {
    // 改进错误消息，提供更具体的错误原因
    const errorMessage = `创建临时文件夹失败: ${error.message} (路径: ${directory})`;
    console.error(errorMessage);
    throw new Error(errorMessage);
  }
};

module.exports = { createDir };
