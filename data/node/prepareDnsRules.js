const path = require("node:path");
const { readLines, LineWriter } = require("./stream_utils");
const { parseRule } = require("./rule_parser");

const prepareDnsRules = async (inputFile, outDir) => {
  console.log("开始准备 DNS 兼容规则");

  const blackFile = path.join(outDir, "black.txt");
  const whiteFile = path.join(outDir, "white.txt");

  const blackWriter = new LineWriter(blackFile);
  const whiteWriter = new LineWriter(whiteFile);

  const seenBlack = new Map();
  const seenWhite = new Map();

  let total = 0;
  let dropped = 0;
  let rewriteCount = 0;

  await readLines(inputFile, async (line) => {
    const t = line.trim();
    if (!t) return;
    total++;

    const result = parseRule(t);
    if (!result) {
      dropped++;
      return;
    }

    if (result.ip) rewriteCount++;

    const map = result.isWhite ? seenWhite : seenBlack;
    if (!map.has(result.domain)) {
      map.set(result.domain, t);
    }
  });

  for (const original of seenBlack.values()) {
    await blackWriter.write(original);
  }
  for (const original of seenWhite.values()) {
    await whiteWriter.write(original);
  }

  await blackWriter.close();
  await whiteWriter.close();

  console.log(
    `DNS 兼容过滤完成：输入 ${total} 条 | 黑 ${seenBlack.size} | 白 ${seenWhite.size}（含重写 ${rewriteCount}）| 丢弃 ${dropped}`,
  );

  return {
    blackFile,
    whiteFile,
    blackCount: seenBlack.size,
    whiteCount: seenWhite.size,
    rewriteCount,
    dropped,
  };
};

module.exports = { prepareDnsRules };
