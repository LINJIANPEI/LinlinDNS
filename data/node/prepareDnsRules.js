const path = require("node:path");
const { readLines, LineWriter } = require("./stream_utils");
const { parseRule } = require("./rule_parser");

/**
 * ★ 判断一条 dnsrewrite 规则是否是「拦截语义」。
 * - 黑洞 IP：0.0.0.0 / 127.x.x.x / ::1 / 0:0:0:0:0:0:0:1
 * - 单参数状态码：NOERROR / NXDOMAIN / REFUSED / SERVFAIL
 * 多参数（含 ;）属于定向重写，不算拦截。
 */
const isBlockRewrite = (ip) => {
  if (!ip) return false;
  if (ip.includes(";")) return false;
  const first = ip.split(",")[0].trim().toLowerCase();
  if (
    first === "0.0.0.0" ||
    first.startsWith("127.") ||
    first === "::1" ||
    first === "0:0:0:0:0:0:0:1"
  ) {
    return true;
  }
  return /^(noerror|nxdomain|refused|servfail)$/i.test(first);
};

/**
 * ★ 冲突时决定是否替换已有规则。
 * 优先级：重定向 > 拦截 > 普通规则
 */
const shouldReplace = (existingParsed, newParsed) => {
  if (!existingParsed.ip && !newParsed.ip) {
    return newParsed.important && !existingParsed.important;
  }

  if (existingParsed.ip && !newParsed.ip) return false;
  if (!existingParsed.ip && newParsed.ip) return true;

  const existingIsBlock = isBlockRewrite(existingParsed.ip);
  const newIsBlock = isBlockRewrite(newParsed.ip);

  // 重定向优先：已有拦截 → 新重定向 → 替换
  if (existingIsBlock && !newIsBlock) return true;
  // 重定向优先：已有重定向 → 新拦截 → 不替换
  if (!existingIsBlock && newIsBlock) return false;

  if (newParsed.important && !existingParsed.important) return true;
  return false;
};

const prepareDnsRules = async (inputFile, outDir, archiveDir) => {
  console.log("开始准备 DNS 兼容规则");

  const blackFile = path.join(outDir, "black.txt");
  const whiteFile = path.join(outDir, "white.txt");

  const blackWriter = new LineWriter(blackFile);
  const whiteWriter = new LineWriter(whiteFile);

  const droppedWriter = archiveDir
    ? new LineWriter(path.join(archiveDir, "DNS兼容-解析失败.txt"))
    : null;
  const conflictWriter = archiveDir
    ? new LineWriter(path.join(archiveDir, "DNS兼容-同域冲突.txt"))
    : null;

  const seenBlack = new Map();
  const seenWhite = new Map();

  let total = 0;
  let dropped = 0;
  let rewriteCount = 0;
  let conflictCount = 0;

  await readLines(inputFile, async (line) => {
    const t = line.trim();
    if (!t) return;
    total++;

    const result = parseRule(t);
    if (!result) {
      if (droppedWriter) await droppedWriter.write(line);
      dropped++;
      return;
    }

    if (result.ip) rewriteCount++;

    const map = result.isWhite ? seenWhite : seenBlack;
    const existing = map.get(result.domain);

    if (existing === undefined) {
      map.set(result.domain, t);
    } else {
      const existingParsed = parseRule(existing);
      if (!existingParsed) {
        map.set(result.domain, t);
        return;
      }
      if (shouldReplace(existingParsed, result)) {
        if (conflictWriter) {
          await conflictWriter.write(`[替换] ${existing}  →  ${t}`);
          conflictCount++;
        }
        map.set(result.domain, t);
      } else {
        if (conflictWriter) {
          await conflictWriter.write(`[保留] ${existing}  ✕  ${t}`);
          conflictCount++;
        }
      }
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
  if (droppedWriter) await droppedWriter.close();
  if (conflictWriter) await conflictWriter.close();

  console.log(
    `DNS 兼容过滤完成：输入 ${total} 条 | 黑 ${seenBlack.size} | 白 ${seenWhite.size}（含重写 ${rewriteCount}）| 丢弃 ${dropped} | 同域冲突 ${conflictCount}`,
  );

  return {
    blackFile,
    whiteFile,
    blackCount: seenBlack.size,
    whiteCount: seenWhite.size,
    rewriteCount,
    dropped,
    conflictCount,
  };
};

module.exports = { prepareDnsRules };
