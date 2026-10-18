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

const SHARD_COUNT = 128;

const hashStr = (s) => {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  }
  return h >>> 0;
};

/**
 * options.forceSkipDnsFiles：这些文件的规则原文额外写入 forcedRulesFile
 * 供 prepareDnsRules / removeDeadRules 优先保留 + 跳过 DNS 查询
 */
const mergeAll = async (directory, outputFile, archiveDir, options = {}) => {
  const { forceSkipDnsFiles = [], forcedRulesFile = null } = options;

  console.log("开始合并所有规则（含去重 + 标准化）");
  if (forceSkipDnsFiles.length > 0) {
    console.log(`强制判活文件：${forceSkipDnsFiles.join(", ")}`);
  }

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
    const forcedWriter = forcedRulesFile
      ? new LineWriter(forcedRulesFile)
      : null;

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
      if (forcedWriter) await forcedWriter.close();
    };

    if (allFiles.length === 0) {
      console.log("没有找到规则文件");
      await writer.close();
      await closeArchives();
      return { fileCount: 0, lineCount: 0, skipped: 0, duplicated: 0 };
    }

    const shards = Array.from({ length: SHARD_COUNT }, () => new Set());

    let skippedInvalid = 0;
    let skippedParse = 0;
    let skippedFormat = 0;
    let duplicated = 0;
    let written = 0;
    let forcedWritten = 0;

    for (const file of allFiles) {
      const isWhiteFile = file.startsWith("allow");
      const skipDns = forceSkipDnsFiles.includes(file);
      let fileWritten = 0;

      await readLines(path.join(directory, file), async (line) => {
        const t = line.trim();

        if (!isValidRuleLine(t)) {
          if (invalidWriter) await invalidWriter.write(line);
          skippedInvalid++;
          return;
        }

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

        // ★ 强制跳过 DNS：额外写入 forcedWriter（标准化后的规则）
        if (skipDns && forcedWriter) {
          await forcedWriter.write(normalized);
          forcedWritten++;
        }

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

      const mark = skipDns ? " [强制判活]" : "";
      console.log(`  ${file}: 写入 ${fileWritten} 行${mark}`);
    }

    await writer.close();
    await closeArchives();

    for (let i = 0; i < SHARD_COUNT; i++) {
      shards[i].clear();
    }

    const skipped = skippedInvalid + skippedParse + skippedFormat;
    console.log(
      `合并完成：${allFiles.length} 个文件，` +
        `写入 ${written} 行，跳过 ${skipped} 行` +
        `（无效 ${skippedInvalid}，解析失败 ${skippedParse}，格式化失败 ${skippedFormat}），` +
        `去重 ${duplicated} 行` +
        (forcedWritten > 0 ? `，强制判活 ${forcedWritten} 行` : ""),
    );

    return {
      fileCount: allFiles.length,
      lineCount: written,
      skipped,
      skippedInvalid,
      skippedParse,
      skippedFormat,
      duplicated,
      forcedWritten,
    };
  } catch (error) {
    throw new Error(`合并失败: ${error.message}`);
  }
};

module.exports = { mergeAll };
