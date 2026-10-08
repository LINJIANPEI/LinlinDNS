const fs = require("fs");
const path = require("path");
const { promisify } = require("util");
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
      (filePair) => Array.isArray(filePair) && filePair.length === 2,
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
 *
 * 文件名规则：filePath 去掉扩展名后拼 .partNN + 原扩展名
 *   例：writeFile("./out/passthrough.txt", ["a","b",...])
 *   产出：./out/passthrough.part01.txt
 *         ./out/passthrough.part02.txt
 *
 * @param {string} filePath - 目标文件路径（作为基础名）
 * @param {string[]} content - 要写入的数组，每个元素占一行
 * @param {string} [decoded="utf8"] - 编码格式
 * @returns {Promise<void>}
 */
const writeFileArray = async (filePath, content, decoded = "utf8") => {
  if (!Array.isArray(content)) {
    throw new TypeError("content 必须是数组");
  }

  const CHUNK_SIZE = 100000; // 每片行数，可按需调整

  const ext = path.extname(filePath);
  const base = ext ? filePath.slice(0, -ext.length) : filePath;
  const totalChunks = Math.ceil(content.length / CHUNK_SIZE);
  const pad = String(totalChunks).length;

  const results = { success: [], failed: [] };

  for (let i = 0; i < totalChunks; i++) {
    const chunk = content.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
    const name = `${base}.part${String(i + 1).padStart(pad, "0")}${ext}`;
    try {
      await writeFile(name, chunk.join("\n"), decoded);
      results.success.push(name);
    } catch (error) {
      results.failed.push({ filePath: name, error });
    }
  }

  console.log(
    `拆分写入完成：${content.length} 行 → ${totalChunks} 个文件，` +
      `成功 ${results.success.length}，失败 ${results.failed.length}`,
  );

  return results;
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
  copyFiles,
  createDir,
  deleteFiles,
  deleteDir,
  fileExistsAsync,
  getFilenameWithoutExtension,
  directoryExistsAsync,
  readFile,
  writeFile,
  readDir,
  writeFileArray,
};
