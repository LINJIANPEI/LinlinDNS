const fs = require("node:fs");
const readline = require("node:readline");
const path = require("node:path");
const moment = require("moment-timezone");
const { readFile, writeFile } = require("./common_func");

const countLines = (filePath) =>
  new Promise((resolve, reject) => {
    let n = 0;
    let settled = false;
    const stream = fs.createReadStream(filePath, { encoding: "utf8" });
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
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

/**
 * 统计行数：
 * - 原文件存在 → 直接统计
 * - 原文件不存在 → 查找 rules.part*.txt / allow.part*.txt 求和
 *   （兜底：即使 cleanReadme 被移到分片之后，也能拿到正确数字）
 */
const extractCount = async (filename) => {
  console.log(`开始统计${filename}行数`);

  // 1. 原文件存在
  if (fs.existsSync(filename)) {
    const total = await countLines(filename);
    const match = total - 7;
    console.log(`统计${filename}行数成功：${match}（原文件）`);
    return match > 0 ? String(match) : "0";
  }

  // 2. 原文件不存在 → 查分片
  const dir = path.dirname(filename) || ".";
  const base = path.basename(filename, ".txt");
  const partRe = new RegExp(
    `^${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.part\\d+\\.txt$`,
  );

  let parts = [];
  try {
    parts = fs
      .readdirSync(dir)
      .filter((f) => partRe.test(f))
      .map((f) => path.join(dir, f))
      .sort();
  } catch {}

  if (parts.length === 0) {
    console.warn(`⚠️ ${filename} 及其分片都不存在，返回 0`);
    return "0";
  }

  console.log(
    `检测到 ${parts.length} 个分片：${parts.map((p) => path.basename(p)).join(", ")}`,
  );

  let total = 0;
  for (const p of parts) {
    const n = await countLines(p);
    total += n - 7; // 每片都有 title() 写入的 7 行头部
  }
  console.log(
    `统计${filename}行数成功：${total}（${parts.length} 个分片合计）`,
  );
  return total > 0 ? String(total) : "0";
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
    throw new Error(`更新md文件失败:${error?.message || error || "未知错误"}`);
  }
};

module.exports = { cleanReadme };
