const path = require("node:path");
const { readDir } = require("./common_func");
const { readLines, LineWriter } = require("./stream_utils");

const HTML_RE = /<\s*(html|head|body|div|a\s|script|style|!DOCTYPE|meta|link)/i;

const EXTENDED_RULE_MARKERS = [
  "##",
  "#@#",
  "#$#",
  "#@$#",
  "#%#",
  "#@%#",
  "#?#",
  "#@?#",
];

const isValidRuleLine = (t) => {
  if (!t) return false;
  if (t.length > 300) return false;
  if (t.length < 3) return false;
  if (t.startsWith("!")) return false;
  if (t.startsWith("[")) return false;
  if (HTML_RE.test(t)) return false;
  if (t.startsWith("#")) {
    if (!EXTENDED_RULE_MARKERS.some((m) => t.startsWith(m))) return false;
  }
  if (!t.includes(".") && !t.includes("/")) return false;
  return true;
};

/**
 * 把所有 rules*.txt 和 allow*.txt 合并到一个文件。
 * 不区分黑白，只做基础过滤。
 */
const mergeAll = async (directory, outputFile) => {
  console.log("开始合并所有规则");
  try {
    const fileList = await readDir(directory);
    const allFiles = fileList
      .filter(
        (f) =>
          (f.startsWith("rules") || f.startsWith("allow")) &&
          f.endsWith(".txt"),
      )
      .sort();

    const writer = new LineWriter(outputFile);

    if (allFiles.length === 0) {
      console.log("没有找到规则文件");
      await writer.close();
      return { fileCount: 0, lineCount: 0 };
    }

    let skipped = 0;
    let written = 0;
    for (const file of allFiles) {
      let fileWritten = 0;
      await readLines(path.join(directory, file), async (line) => {
        const t = line.trim();
        if (!isValidRuleLine(t)) {
          skipped++;
          return;
        }
        await writer.write(t);
        written++;
        fileWritten++;
      });
      console.log(`  ${file}: 写入 ${fileWritten} 行`);
    }

    await writer.close();

    console.log(
      `合并完成：${allFiles.length} 个文件，写入 ${written} 行，跳过 ${skipped} 行`,
    );
    return { fileCount: allFiles.length, lineCount: written };
  } catch (error) {
    throw new Error(`合并失败: ${error.message}`);
  }
};

module.exports = { mergeAll };
