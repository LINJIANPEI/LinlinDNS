const fs = require("node:fs");
const readline = require("node:readline");
const moment = require("moment-timezone");
const { readFile, writeFile } = require("./common_func");

const countLines = (filePath) =>
  new Promise((resolve, reject) => {
    let n = 0;
    const rl = readline.createInterface({
      input: fs.createReadStream(filePath, { encoding: "utf8" }),
      crlfDelay: Infinity,
    });
    rl.on("line", () => n++);
    rl.on("close", () => resolve(n));
    rl.on("error", reject);
  });

const extractCount = async (filename) => {
  console.log(`开始统计${filename}行数`);
  try {
    const total = await countLines(filename);
    const match = total - 7; // 减去 title 的 7 行头部
    console.log(`统计${filename}行数成功`);
    return match > 0 ? match : "0";
  } catch (error) {
    throw `统计${filename}行数失败:${error}`;
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
    throw new Error(`更新md文件失败:${error.message}`);
  }
};

module.exports = { cleanReadme };
