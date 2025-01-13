const fs = require("fs");
const path = require("path");
const { promisify } = require("util");
const compile = require("@adguard/hostlist-compiler");
const deleteFile = promisify(fs.unlink);
const mkdir = promisify(fs.mkdir);
const copyFile = promisify(fs.copyFile);
const access = promisify(fs.access);
const stat = promisify(fs.stat);
const rmdir = promisify(fs.rm);
const readFileContent = promisify(fs.readFile);
const writeFileContent = promisify(fs.writeFile);
const readDirContent = promisify(fs.readdir);
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
      .filter(Boolean)
      .map((line) => line.trim()) // 修剪每行的空白
      .filter((line) => line !== "") // 过滤掉空行
      .sort();
    console.log("过滤无效字符成功");
    return arrs;
  } catch (error) {
    throw new Error(`过滤无效字符失败: ${error}`);
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
 * @param {...Array<string>} fileList  - 要复制的文件路径:[[旧，新]]。
 * @throws {Error} 如果复制文件失败，则抛出错误。
 */
const copyFiles = async (...fileList) => {
  if (
    !fileList.every(
      (filePair) => Array.isArray(filePair) && filePair.length === 2
    )
  ) {
    throw new Error("所有参数必须是包含 [旧路径, 新路径] 的数组。");
  }
  for (const [src, dest] of fileList) {
    try {
      console.log("开始复制文件");
      // 检查源文件是否存在
      if (await fileExistsAsync(src)) {
        // 复制文件并等待完成
        await copyFile(src, dest);
        console.log(`文件复制：${src}=>${dest}成功`);
      } else {
        console.error(`源文件:${src}不存在`);
      }
    } catch (error) {
      throw new Error(`复制文件：${src}=>${dest}失败: ${error}`);
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

/**
 * 官方规则转换工具
 * 编译规则文件
 * @param {string} filePath - 要编译的文件路径
 * @param {boolean} invertAllow - 是否启用 "InvertAllow" 转换
 * @returns {Promise<Array<string>>} - 返回编译后的内容数组
 */
const compileRules = async (filePath, invertAllow = false) => {
  const transformations = ["RemoveComments", "Compress", "Validate"];
  const name = invertAllow ? "linlinAllow" : "linlinRules";

  // 如果需要添加 "InvertAllow" 转换，加入转换数组
  if (invertAllow) {
    transformations.push("InvertAllow");
  }

  try {
    // 编译规则文件
    const compiledContent = await compile({
      name,
      sources: [
        { type: "adblock", source: filePath },
        { type: "hosts", source: filePath },
      ],
      transformations,
    });

    // 过滤掉以 "!" 开头的行（注释）
    const filteredContent = compiledContent.filter((str) => !/^!/.test(str));
    return filteredContent;
  } catch (error) {
    console.error(`编译规则文件失败: ${filePath}, 错误: ${error.message}`);
    throw new Error(`编译失败: ${error.message}`);
  }
};

// ----------------------------------------

/**
 * 读取文件内容
 * @param {string} filePath - 文件路径
 * @param {string} decoded - 编码格式
 * @returns {Promise<string>} - 返回文件内容的 Promise
 */
const readFile = async (filePath, decoded = "utf8") => {
  try {
    const content = await readFileContent(filePath, decoded);
    return content;
  } catch (error) {
    console.error(`读取文件失败: ${filePath}, 错误: ${error.message}`);
    throw new Error(`读取文件失败: ${error.message}`);
  }
};

// ----------------------------------------

/**
 * 写入内容到指定文件
 * @param {string} filePath - 文件路径
 * @param {string} content - 要写入的内容
 * @param {string} decoded - 编码格式
 * @returns {Promise<void>} - 返回一个 Promise，表示写入操作完成
 */
const writeFile = async (filePath, content, decoded = "utf8") => {
  try {
    await writeFileContent(filePath, content, decoded);
    console.log(`成功写入文件: ${filePath}`);
  } catch (error) {
    console.error(`写入文件失败: ${filePath}, 错误: ${error.message}`);
    throw new Error(`写入文件失败: ${error.message}`);
  }
};

// ----------------------------------------

/**
 * 读取目录内容
 * @param {string} dirPath - 目录路径
 * @returns {Promise<Array<string>>} - 返回目录中的文件和子目录列表
 */
const readDir = async (dirPath) => {
  try {
    const files = await readDirContent(dirPath);
    console.log(`成功读取目录: ${dirPath}`);
    return files;
  } catch (error) {
    console.error(`读取目录失败: ${dirPath}, 错误: ${error.message}`);
    throw new Error(`读取目录失败: ${error.message}`);
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
  compileRules,
  readFile,
  writeFile,
  readDir,
};
