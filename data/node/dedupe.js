const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const fs = require("node:fs");
const execFileAsync = promisify(execFile);

/**
 * 用系统 sort -u 对文件去重（原地替换）。
 * - 内存占用极低（外部排序）
 * - 会改变行顺序（变字典序）
 *
 * @param {string} filePath
 * @returns {Promise<{ before: number, after: number, lines: number }>}
 */
const dedupeFile = async (filePath) => {
  console.log(`开始去重: ${filePath}`);

  if (!fs.existsSync(filePath)) {
    console.log(`文件不存在，跳过去重: ${filePath}`);
    return { before: 0, after: 0, lines: 0 };
  }

  const tmp = `${filePath}.sorted`;

  try {
    // sort -u 去重，-o 直接输出到目标文件
    await execFileAsync("sort", ["-u", filePath, "-o", tmp], {
      maxBuffer: 1024 * 1024 * 1024, // 1GB
    });

    const beforeSize = fs.statSync(filePath).size;
    const afterSize = fs.statSync(tmp).size;

    // 原子替换
    fs.renameSync(tmp, filePath);

    // 统计行数（用 wc -l，比再读一遍文件快）
    let lines = 0;
    try {
      const { stdout } = await execFileAsync("wc", ["-l", filePath]);
      lines = parseInt(stdout.trim().split(/\s+/)[0], 10) || 0;
    } catch {}

    console.log(
      `去重完成: ${(beforeSize / 1024 / 1024).toFixed(1)}MB → ` +
        `${(afterSize / 1024 / 1024).toFixed(1)}MB, ${lines} 行`,
    );

    return { before: beforeSize, after: afterSize, lines };
  } catch (error) {
    console.error(`去重失败: ${filePath} - ${error.message}`);
    // 清理残留的临时文件
    if (fs.existsSync(tmp)) {
      try {
        fs.unlinkSync(tmp);
      } catch {}
    }
    throw new Error(`去重失败: ${error.message}`);
  }
};

module.exports = { dedupeFile };
