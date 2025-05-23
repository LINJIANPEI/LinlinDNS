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

// 分割文件
/**
 * 将数据写入文件，如果文件大小超过限制，则将其拆分为较小的块。
 * @param {string} filePath - 文件的路径（包括文件名）。
 * @param {string} data - 要写入文件的数据。
 * @param {number} [sizeLimit=100] - 文件大小限制，单位为 MB（默认：100 MB）。
 */
const writeFileWithSizeCheck = async (filePath, data, sizeLimit = 100) => {
  const chunkSize = sizeLimit * 1024 * 1024; // 将 MB 转换为字节
  const directory = path.dirname(filePath); // 从文件路径中提取目录
  const fileName = path.basename(filePath, path.extname(filePath)); // 提取文件名（不带扩展名）
  const fileExtension = path.extname(filePath); // 提取文件扩展名
  const textEncoder = new TextEncoder();

  try {
    // 确保目录存在
    await mkdir(directory, { recursive: true });

    // 如果数据小于块大小，直接写入文件
    if (textEncoder.encode(data).length <= chunkSize) {
      await writeFileContent(filePath, data, "utf8");
      console.log(`文件写入成功: ${filePath}`);
      return;
    }

    // 将数据拆分为块，并确保每一行是完整的
    let chunkIndex = 1;
    let startIndex = 0;

    while (startIndex < data.length) {
      // 计算当前块的结束位置
      let endIndex = startIndex + chunkSize;
      if (endIndex > data.length) {
        endIndex = data.length;
      }

      // 查找最后一个换行符的位置
      const lastNewlineIndex = data.lastIndexOf("\n", endIndex);
      if (lastNewlineIndex > startIndex) {
        endIndex = lastNewlineIndex + 1; // 包含换行符
      }

      // 获取当前块的数据
      const chunk = data.slice(startIndex, endIndex);

      // 写入当前块
      const chunkFilePath = path.join(
        directory,
        `${fileName}-part-${chunkIndex}${fileExtension}`
      );
      await writeFileContent(chunkFilePath, chunk, "utf8");
      console.log(`块文件写入成功: ${chunkFilePath}`);

      // 更新起始位置和块索引
      startIndex = endIndex;
      chunkIndex++;
    }
  } catch (error) {
    console.error("写入文件时出错:", error);
  }
};

// ----------------------------------------

// 获取文件夹的文件名
const getFileNamesWithSuffixAsync = async (folderPath, paths = "") => {
  try {
    await access(folderPath);
    const items = await readDirContent(folderPath);
    const fileNames = await Promise.all(
      items.map(async (item) => {
        const itemPath = path.join(folderPath, item);
        const stats = await stat(itemPath);
        return stats.isFile() ? item : null;
      })
    );
    return fileNames
      .filter((fileName) => fileName !== null)
      .map((line) => `${paths}${line}`);
  } catch (error) {
    console.error(`Error reading folder: ${folderPath}`, error);
    return [];
  }
};

// ----------------------------------------

// 处理 hosts 规则
const processHostsRule = (rules, str) => {
  const arr = rules
    .map((line) => {
      const trimmed = line.trim();
      // 检查是否是有效的 IPv4 地址和后续的域名，或是 IPv6 地址（以 :: 开头）
      if (/^\d+\.\d+\.\d+\.\d+\s+.*$/.test(trimmed) || /^::/.test(trimmed)) {
        // 从 trimmed 字符串中提取域名部分
        const domain = trimmed.split(/\s+/)[1];
        if (domain) {
          return `${str}${domain}`;
        }
        return domain;
      }
      return trimmed;
    })
    .filter(Boolean);
  return arr;
};

// ----------------------------------------

/**
 * 去除黑白名单规则中的多余子域名，不区分黑白名单。
 * @param {string[]} rules - 包含黑白名单的规则数组。
 * @returns {string[]} 返回去重后的规则数组。
 */
const removeSubdomainDuplicates = (rules) => {
  const optimizedRules = [];
  const seenDomains = new Set(); // 用于存储已经处理过的主域名

  // 辅助函数：提取主域名
  const getBaseDomain = (rule) => {
    return rule
      .replace(/^(\|\|)/, "")
      .replace(/^@@(\|\|)/, "")
      .replace(/\^.*$/, ""); // 去除前缀 "||" 和修饰符 "^"
  };

  rules.forEach((rule) => {
    const baseDomain = getBaseDomain(rule);
    // 如果主域名没有出现过，则添加到优化后的规则
    if (!seenDomains.has(baseDomain)) {
      optimizedRules.push(rule);
      seenDomains.add(baseDomain); // 标记此主域名已处理
    }
  });

  return optimizedRules;
};

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
  processHostsRule,
  removeSubdomainDuplicates,
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
  getFileNamesWithSuffixAsync,
  writeFileWithSizeCheck,
};
