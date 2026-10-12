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

/**
 * 合并所有 rules*.txt / allow*.txt 到一个文件。
 * - 过滤注释 / 无效行 / URL 规则 / 不支持的修饰符
 * - ★ 使用 rule_parser.parseRule + formatRule 标准化
 * - 用 Set 去重
 */
const mergeAll = async (directory, outputFile) => {
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

    if (allFiles.length === 0) {
      console.log("没有找到规则文件");
      await writer.close();
      return { fileCount: 0, lineCount: 0, skipped: 0, duplicated: 0 };
    }

    const seen = new Set();
    let skipped = 0;
    let duplicated = 0;
    let written = 0;

    for (const file of allFiles) {
      const isWhiteFile = file.startsWith("allow");
      let fileWritten = 0;

      await readLines(path.join(directory, file), async (line) => {
        const t = line.trim();

        if (!isValidRuleLine(t)) {
          skipped++;
          return;
        }

        // ★ 解析 + 格式化（唯一处理锚点的地方）
        const rule = parseRule(t);
        if (!rule) {
          skipped++;
          return;
        }

        const normalized = formatRule(rule, { fileIsWhite: isWhiteFile });
        if (!normalized) {
          skipped++;
          return;
        }

        if (seen.has(normalized)) {
          duplicated++;
          return;
        }
        seen.add(normalized);

        await writer.write(normalized);
        written++;
        fileWritten++;
      });
      console.log(`  ${file}: 写入 ${fileWritten} 行`);
    }

    await writer.close();
    seen.clear();

    console.log(
      `合并完成：${allFiles.length} 个文件，` +
        `写入 ${written} 行，跳过 ${skipped} 行，去重 ${duplicated} 行`,
    );
    return {
      fileCount: allFiles.length,
      lineCount: written,
      skipped,
      duplicated,
    };
  } catch (error) {
    throw new Error(`合并失败: ${error.message}`);
  }
};

module.exports = { mergeAll };