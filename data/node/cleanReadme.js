const fs = require("node:fs");
const readline = require("node:readline");
const moment = require("moment-timezone");
const { readFile, writeFile } = require("./common_func");

/**
 * 流式统计行数。
 * ★ error 和 close 都处理，避免 race，错误信息完整。
 */
const countLines = (filePath) =>
  new Promise((resolve, reject) => {
    let n = 0;
    let settled = false;

    const stream = fs.createReadStream(filePath, { encoding: "utf8" });
    const rl = readline.createInterface({
      input: stream,
      crlfDelay: Infinity,
    });

    const fail = (e) => {
      if (settled) return;
      settled = true;
      reject(e);
    };

    stream.on("error", fail);
    rl.on("error", fail);
    rl.on("line", () => n++);
    rl.on("close", () => {
      if (settled) return;
      settled = true;
      resolve(n);
    });
  });

const extractCount = async (filename) => {
  console.log(`开始统计${filename}行数`);

  // ★ 先检查文件是否存在
  if (!fs.existsSync(filename)) {
    console.warn(`⚠️ ${filename} 不存在，返回 0`);
    return "0";
  }

  try {
    const total = await countLines(filename);
    const match = total - 7; // 减去 title 的 7 行头部
    console.log(`统计${filename}行数成功：${match}`);
    return match > 0 ? match : "0";
  } catch (error) {
    // ★ 抛出 Error 对象，保留完整信息
    throw new Error(
      `统计${filename}行数失败:${error?.message || error || "未知错误"}`,
    );
  }
};

const cleanReadme = async () => {
  console.log("开始更新md文件");
  try {
    const numRules = await extractCount("rules.txt");
    const numAllow = await extractCount("allow.txt");
    const beijingTime = moment()
      .tz("Asia/Shanghai")
      .format("YYYY-MM-DD HH:mm:ss");

    let readmeContent = await readFile("README.md");
    const replacements = [
      [/^更新时间.*/, `更新时间: ${beijingTime} （北京时间）`],
      [/^黑名单规则数量.*/, `黑名单规则数量: ${numRules}`],
      [/^白名单规则数量.*/, `白名单规则数量: ${numAllow}`],
    ];
    readmeContent = readmeContent
      .split("\n")
      .map((line) => {
        for (const [regex, replacement] of replacements) {
          if (regex.test(line)) return replacement;
        }
        return line;
      })
      .join("\n");

    await writeFile("README.md", readmeContent);
    console.log("更新md文件成功");
  } catch (error) {
    // ★ 保留完整堆栈
    throw new Error(`更新md文件失败:${error?.message || error || "未知错误"}`);
  }
};

module.exports = { cleanReadme };
