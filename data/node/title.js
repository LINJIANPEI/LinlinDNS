const fs = require("node:fs");
const readline = require("node:readline");
const { finished } = require("node:stream/promises");
const path = require("path");
const moment = require("moment-timezone");
const { readDir } = require("./common_func");

const getFilenameWithoutExtension = (filepath) => {
  const name = path.basename(filepath);
  return path.parse(name).name;
};

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

const title = async () => {
  console.log("开始写入头部信息");
  try {
    const beijingTime = moment()
      .tz("Asia/Shanghai")
      .format("YYYY-MM-DD HH:mm:ss");

    const files = await readDir("./");
    const fileList = files.filter((f) => f.endsWith(".txt"));

    for (const file of fileList) {
      const filePath = `./${file}`;
      const result = getFilenameWithoutExtension(file);
      const tmpPath = `${filePath}.tmp`;

      // 1. 流式统计行数
      const lineCount = await countLines(filePath);

      // 2. 写临时文件：头部 + 原内容
      const out = fs.createWriteStream(tmpPath, { encoding: "utf8" });
      out.write(
        `[个人合并 2.0]\n` +
          `! Title: 林林${result}\n` +
          `! Homepage: https://github.com/LINJIANPEI/DnsRules/\n` +
          `! Expires: 1 Hours\n` +
          `! Version: ${beijingTime}（北京时间）\n` +
          `! Description: 适用于AdGuard的去广告规则，合并优质上游规则并去重整理排列\n` +
          `! Total count: ${lineCount}\n`,
      );

      // 3. 流式追加原内容
      const rl = readline.createInterface({
        input: fs.createReadStream(filePath, { encoding: "utf8" }),
        crlfDelay: Infinity,
      });
      for await (const line of rl) {
        if (!out.write(line + "\n")) {
          await new Promise((r) => out.once("drain", r));
        }
      }
      out.end();
      await finished(out);

      // 4. 替换原文件
      await fs.promises.rename(tmpPath, filePath);
    }
    console.log("写入头部信息成功");
  } catch (error) {
    throw new Error(`写入头部信息失败:${error.message}`);
  }
};

module.exports = { title };
