const path = require("node:path");
const { readDir } = require("./common_func");
const { readLines, LineWriter } = require("./stream_utils");
const {
  parseRule,
  formatRule,
  hasUnsupportedModifier,
  isPathRule,
} = require("./rule_parser");

const HTML_RE = /<\s*(html|head|body|div|a\s|script|style|!DOCTYPE|meta|link)/i;

const STATIC_FILE_RE =
  /\.(js|ts|css|html?|json|xml|txt|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|map|mp4|mp3|webm|m3u8)(\^|\$|$)/i;

const isValidRuleLine = (t) => {
  if (!t) return false;
  if (t.length < 3) return false;
  if (t.length > 1024) return false;

  if (t.startsWith("!")) return false;
  if (t.startsWith("[")) return false;
  if (t.startsWith("#")) return false;

  if (HTML_RE.test(t)) return false;

  if (!t.includes(".") && !t.includes("/")) return false;

  if (isPathRule(t)) return false;
  if (hasUnsupportedModifier(t)) return false;
  if (STATIC_FILE_RE.test(t)) return false;

  return true;
};

// ============================================================
// ★ 分片去重
// ------------------------------------------------------------
// V8 对单个 Set 有 2^24 - 1 ≈ 1677 万元素上限。
// 把 seen 拆成 SHARD_COUNT 个小 Set，每个分片独立去重。
// 总容量 = SHARD_COUNT × 1677 万，彻底避开上限。
// ============================================================
const SHARD_COUNT = 128;

/** djb2 字符串哈希，返回 uint32 */
const hashStr = (s) => {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  }
  return h >>> 0;
};

/**
 * 合并所有 rules*.txt / allow*.txt 到一个文件。
 * - 过滤注释 / 无效行 / URL 规则 / 不支持的修饰符
 * - 使用 rule_parser.parseRule + formatRule 标准化
 * - ★ 分片 Set 去重，突破单 Set 1677 万上限
 * - 每一类过滤都写入 archiveDir 下的独立归档
 *
 * @param {string} directory  临时目录
 * @param {string} outputFile 输出 all.txt
 * @param {string} [archiveDir] 归档目录（可选，不传则不归档）
 */
const mergeAll = async (directory, outputFile, archiveDir) => {
  console.log("开始合并所有规则（含去重 + 标准化）");
  try {
    const fileList = await readDir(directory);
    const allFiles = fileList
      .filter(
        (f) =>
          (f.startsWith("rules") || f.startsWith("allow")) &&
          f.endsWith(".txt"),
      )
      .filter((f) => !/\.part\d+\./.test(f))
      .sort();

    const writer = new LineWriter(outputFile);

    // ★ 四类归档
    const invalidWriter = archiveDir
      ? new LineWriter(path.join(archiveDir, "合并-无效行.txt"))
      : null;
    const parseFailWriter = archiveDir
      ? new LineWriter(path.join(archiveDir, "合并-解析失败.txt"))
      : null;
    const formatFailWriter = archiveDir
      ? new LineWriter(path.join(archiveDir, "合并-格式化失败.txt"))
      : null;
    const duplicateWriter = archiveDir
      ? new LineWriter(path.join(archiveDir, "合并-重复行.txt"))
      : null;

    const closeArchives = async () => {
      if (invalidWriter) await invalidWriter.close();
      if (parseFailWriter) await parseFailWriter.close();
      if (formatFailWriter) await formatFailWriter.close();
      if (duplicateWriter) await duplicateWriter.close();
    };

    if (allFiles.length === 0) {
      console.log("没有找到规则文件");
      await writer.close();
      await closeArchives();
      return {
        fileCount: 0,
        lineCount: 0,
        skipped: 0,
        duplicated: 0,
      };
    }

    // ★ 分片 Set（替代原来的单个 seen）
    const shards = Array.from({ length: SHARD_COUNT }, () => new Set());

    let skippedInvalid = 0;
    let skippedParse = 0;
    let skippedFormat = 0;
    let duplicated = 0;
    let written = 0;

    for (const file of allFiles) {
      const isWhiteFile = file.startsWith("allow");
      let fileWritten = 0;

      await readLines(path.join(directory, file), async (line) => {
        const t = line.trim();

        if (!isValidRuleLine(t)) {
          if (invalidWriter) await invalidWriter.write(line);
          skippedInvalid++;
          return;
        }

        // ★ 解析 + 格式化（唯一处理锚点的地方）
        const rule = parseRule(t);
        if (!rule) {
          if (parseFailWriter) await parseFailWriter.write(line);
          skippedParse++;
          return;
        }

        const normalized = formatRule(rule, { fileIsWhite: isWhiteFile });
        if (!normalized) {
          if (formatFailWriter) await formatFailWriter.write(line);
          skippedFormat++;
          return;
        }

        // ★ 分片查重
        const idx = hashStr(normalized) % SHARD_COUNT;
        const shard = shards[idx];

        if (shard.has(normalized)) {
          if (duplicateWriter) await duplicateWriter.write(line);
          duplicated++;
          return;
        }
        shard.add(normalized);

        await writer.write(normalized);
        written++;
        fileWritten++;
      });
      console.log(`  ${file}: 写入 ${fileWritten} 行`);
    }

    await writer.close();
    await closeArchives();

    // ★ 释放分片 Set
    for (let i = 0; i < SHARD_COUNT; i++) {
      shards[i].clear();
    }

    const skipped = skippedInvalid + skippedParse + skippedFormat;
    console.log(
      `合并完成：${allFiles.length} 个文件，` +
        `写入 ${written} 行，跳过 ${skipped} 行` +
        `（无效 ${skippedInvalid}，解析失败 ${skippedParse}，格式化失败 ${skippedFormat}），` +
        `去重 ${duplicated} 行`,
    );

    return {
      fileCount: allFiles.length,
      lineCount: written,
      skipped,
      skippedInvalid,
      skippedParse,
      skippedFormat,
      duplicated,
    };
  } catch (error) {
    throw new Error(`合并失败: ${error.message}`);
  }
};

module.exports = { mergeAll };
