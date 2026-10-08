const path = require("node:path");
const { readDir } = require("./common_func");
const { readLines, LineWriter } = require("./stream_utils");

const mergeWhitelist = async (directory, outputFile) => {
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

    for (const file of allowFiles) {
      await readLines(path.join(directory, file), async (line) => {
        const t = line.trim();
        if (t) await writer.write(t);
      });
    }

    await writer.close();

    console.log(
      `合并白名单规则完成，共处理了${allowFiles.length}个文件，合并规则${writer.count}条`,
    );
    return { fileCount: allowFiles.length, lineCount: writer.count };
  } catch (error) {
    throw new Error(`合并白名单规则失败: ${error.message}`);
  }
};

module.exports = { mergeWhitelist };
