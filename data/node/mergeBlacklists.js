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

  // 以 # 开头：只允许扩展标记（## 等）
  if (t.startsWith("#")) {
    if (!EXTENDED_RULE_MARKERS.some((m) => t.startsWith(m))) return false;
  }

  // 必须包含点（域名/IP）或 /（正则）
  if (!t.includes(".") && !t.includes("/")) return false;
  return true;
};

const mergeBlacklists = async (directory, outputFile) => {
  console.log("开始合并黑名单规则");
  try {
    const fileList = await readDir(directory);
    const rulesFiles = fileList
      .filter((f) => f.startsWith("rules") && f.endsWith(".txt"))
      .sort();

    const writer = new LineWriter(outputFile);

    if (rulesFiles.length === 0) {
      console.log("没有找到符合条件的黑名单文件");
      await writer.close();
      return { fileCount: 0, lineCount: 0 };
    }

    let skipped = 0;
    let written = 0;
    for (const file of rulesFiles) {
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
      `合并黑名单规则完成，共处理了${rulesFiles.length}个文件，` +
        `写入 ${written} 行，跳过 ${skipped} 行`,
    );
    return { fileCount: rulesFiles.length, lineCount: written };
  } catch (error) {
    throw new Error(`合并黑名单规则失败: ${error.message}`);
  }
};

module.exports = { mergeBlacklists };
