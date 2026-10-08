const path = require("node:path");
const { readDir } = require("./common_func");
const { readLines, LineWriter } = require("./stream_utils");

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

    for (const file of rulesFiles) {
      await readLines(path.join(directory, file), async (line) => {
        const t = line.trim();
        if (t) await writer.write(t);
      });
    }

    await writer.close();

    console.log(
      `合并黑名单规则完成，共处理了${rulesFiles.length}个文件，合并规则${writer.count}条`,
    );
    return { fileCount: rulesFiles.length, lineCount: writer.count };
  } catch (error) {
    throw new Error(`合并黑名单规则失败: ${error.message}`);
  }
};

module.exports = { mergeBlacklists };
