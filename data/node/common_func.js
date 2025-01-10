const fs = require("fs");
const path = require("path");
const { promisify } = require("util");
const deleteFile = promisify(fs.unlink);
const mkdir = promisify(fs.mkdir);
const copyFile = promisify(fs.copyFile);
const access = promisify(fs.access);
const stat = promisify(fs.stat);
const rmdir = promisify(fs.rm);

// ----------------------------------------

/**
 * 过滤无效字符。
 * @param {array} arr - 要过滤的数据。
 * @return {array} 返回过滤后的数据。
 */
const filters = (arr) => {
  try {
    console.log("开始过滤无效字符");
    const arrs = [...new Set(arr)]
      .map((line) => line.trim()) // 修剪每行的空白
      .filter((line) => line !== "") // 过滤掉空行
      .sort();
    console.log("过滤无效字符成功");
    return arrs;
  } catch (error) {
    throw `过滤无效字符失败: ${error}`;
  }
};

// ----------------------------------------

/**
 * 检查文件是否存在。
 * @param {string} filepath - 检查文件是否存在的文件名路径。
 * @return {boolean} 存在返回true，不存在返回false。
 */
const fileExistsAsync = async (filePath) => {
  try {
    await access(filePath, fs.constants.F_OK);
    return true;
  } catch (error) {
    return false;
  }
};

// ----------------------------------------

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

// ----------------------------------------

/**
 * 获取不带扩展名的文件名。
 * @param {string} filepath - 要获取的文件名路径。
 * @return {string} 获取的文件名。
 */
const getFilenameWithoutExtension = (filepath) => {
  const filenameWithExtension = path.basename(filepath);
  return path.parse(filenameWithExtension).name;
};

// ----------------------------------------

/**
 * 复制文件。
 * @param {array} fileList  - 要复制的文件路径:[[旧，新]]。
 * @throws {Error} 如果复制文件失败，则抛出错误。
 */
const copyFiles = async (...fileList) => {
  for (const filePath of fileList) {
    try {
      console.log("开始复制文件");
      // 检查源文件是否存在
      if (await fileExistsAsync(filePath[0])) {
        // 复制文件并等待完成
        await copyFile(filePath[0], filePath[1]);
        console.log(`文件复制：${filePath[0]}=>${filePath[1]}成功`);
      } else {
        console.error(`源文件:${filePath[0]}不存在`);
      }
    } catch (error) {
      throw `复制文件：${filePath[0]}=>${filePath[1]}失败: ${error}`;
    }
  }
};

// ----------------------------------------

/**
 * 创建一个指定的文件夹。
 * @param {string} directory - 要创建的文件夹路径。
 *  如果文件夹创建失败，则抛出错误。
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

// ----------------------------------------

/**
 * 删除文件。
 * @param {array} filePaths - 文件路径。
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

// ----------------------------------------

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

// ----------------------------------------

module.exports = {
  filters,
  copyFiles,
  createDir,
  deleteFiles,
  deleteDir,
  fileExistsAsync,
  getFilenameWithoutExtension,
  directoryExistsAsync,
};
