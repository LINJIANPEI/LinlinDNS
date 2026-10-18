const fs = require("node:fs");
const readline = require("node:readline");
const path = require("node:path");
const { finished } = require("node:stream/promises");

const DEFAULT_MAX_SIZE = 100 * 1024 * 1024; // 100MB

/**
 * 把单个大文件切成多个 <100MB 的分片。
 * - 每片保证以完整行结尾
 * - keepOriginal=true 时保留原文件；false 时删除原文件
 *
 * @param {string} filePath
 * @param {number} [maxSize]
 * @param {boolean} [keepOriginal=false]
 * @returns {Promise<string[]>} 分片路径；未超限时返回 [原路径]
 */
const splitOneFile = async (
  filePath,
  maxSize = DEFAULT_MAX_SIZE,
  keepOriginal = false,
) => {
  if (!fs.existsSync(filePath)) return [];

  const stat = fs.statSync(filePath);
  const sizeMB = (stat.size / 1024 / 1024).toFixed(1);

  if (stat.size <= maxSize) {
    console.log(`  [跳过] ${filePath} (${sizeMB}MB)`);
    return [filePath];
  }

  console.log(
    `  [分片] ${filePath} (${sizeMB}MB)${keepOriginal ? "，保留原文件" : ""}`,
  );

  const ext = path.extname(filePath);
  const base = filePath.slice(0, -ext.length);
  const pad = 3;

  const parts = [];
  let partIndex = 1;
  let currentSize = 0;
  let currentWriter = null;

  const openNext = () => {
    const name = `${base}.part${String(partIndex).padStart(pad, "0")}${ext}`;
    parts.push(name);
    currentSize = 0;
    currentWriter = fs.createWriteStream(name, { encoding: "utf8" });
  };

  openNext();

  const rl = readline.createInterface({
    input: fs.createReadStream(filePath, { encoding: "utf8" }),
    crlfDelay: Infinity,
  });

  for await (const line of rl) {
    const lineSize = Buffer.byteLength(line, "utf8") + 1;

    if (currentSize + lineSize > maxSize && currentSize > 0) {
      currentWriter.end();
      await finished(currentWriter);
      partIndex++;
      openNext();
    }

    if (!currentWriter.write(line + "\n")) {
      await new Promise((r) => currentWriter.once("drain", r));
    }
    currentSize += lineSize;
  }

  currentWriter.end();
  await finished(currentWriter);

  // 只有 keepOriginal=false 时才删除原文件
  if (!keepOriginal) {
    fs.unlinkSync(filePath);
  }

  console.log(`  [分片完成] ${filePath} → ${parts.length} 片`);
  return parts;
};

/**
 * 扫描目录下所有匹配的 .txt 文件，逐个分片。
 *
 * @param {string} dir - 目录
 * @param {object} [options]
 * @param {number} [options.maxSize] - 阈值（字节），默认 100MB
 * @param {RegExp} [options.pattern] - 匹配的文件名，默认 /\.txt$/
 * @param {string[]} [options.exclude] - 要排除的文件名
 * @param {boolean} [options.keepOriginals=false] - 是否保留原文件
 * @returns {Promise<{file: string, parts: string[]}[]>}
 */
const splitLargeFilesInDir = async (dir, options = {}) => {
  const {
    maxSize = DEFAULT_MAX_SIZE,
    pattern = /\.txt$/,
    exclude = [],
    keepOriginals = false,
  } = options;

  if (!fs.existsSync(dir)) {
    console.log(`目录不存在，跳过: ${dir}`);
    return [];
  }

  console.log(
    `开始扫描目录分片: ${dir}（阈值 ${(maxSize / 1024 / 1024).toFixed(0)}MB${keepOriginals ? "，保留原文件" : ""}）`,
  );

  const files = fs
    .readdirSync(dir)
    .filter((f) => pattern.test(f))
    .filter((f) => !exclude.includes(f))
    .filter((f) => !/\.part\d+\./.test(f))
    .sort();

  const results = [];

  for (const file of files) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (!stat.isFile()) continue;

    const parts = await splitOneFile(fullPath, maxSize, keepOriginals);
    results.push({ file: fullPath, parts });
  }

  const totalParts = results.reduce((s, r) => s + r.parts.length, 0);
  console.log(`目录分片完成: ${results.length} 个文件 → ${totalParts} 个分片`);

  return results;
};

module.exports = { splitOneFile, splitLargeFilesInDir };
