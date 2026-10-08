const path = require("node:path");
const { readDir } = require("./common_func");
const { readLines, LineWriter } = require("./stream_utils");

// 过滤规则
const HTML_RE = /<\s*(html|head|body|div|a\s|script|style|!DOCTYPE|meta|link)/i;

const isValidRuleLine = (t) => {
  if (!t) return false;
  if (t.length > 300) return false; // 超长行
  if (t.length < 3) return false; // 太短
  if (t.startsWith("!")) return false; // 注释
  if (t.startsWith("#")) return false; // 注释 / CSS 选择器
  if (t.startsWith("[")) return false; // 段头 [Adblock Plus 2.0]
  if (HTML_RE.test(t)) return false; // HTML 标签
  if (!t.includes(".")) return false; // 不含点，肯定不是域名
  return true;
};

const mergeWhitelists = async (directory, outputFile) => {
  console.log("开始合并白名单规则");
  try {
    const fileList = await readDir(directory);
    const allowFiles = fileList
      .filter((f) => f.startsWith("allow") && f.endsWith(".txt"))
      .sort();

    const writer = new LineWriter(outputFile);

    if (allowFiles.length === 0) {
      console.log("没有找到符合条件的白名单文件");
      await writer.close();
      return { fileCount: 0, lineCount: 0 };
    }

    let skipped = 0;
    let written = 0;
    for (const file of allowFiles) {
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
      `合并白名单规则完成，共处理了${allowFiles.length}个文件，` +
        `写入 ${written} 行，跳过 ${skipped} 行`,
    );
    return { fileCount: allowFiles.length, lineCount: written };
  } catch (error) {
    throw new Error(`合并白名单规则失败: ${error.message}`);
  }
};

module.exports = { mergeWhitelists };
