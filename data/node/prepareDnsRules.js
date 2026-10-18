const path = require("node:path");
const fs = require("node:fs");
const { readLines, LineWriter } = require("./stream_utils");
const { parseRule } = require("./rule_parser");

/**
 * 判断 dnsrewrite 是否拦截语义。
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
 * 冲突时决定是否替换已有规则。
 * 优先级：重定向 > 拦截 > 普通规则
 */
const shouldReplace = (existingParsed, newParsed) => {
  if (!existingParsed.ip && !newParsed.ip) {
    return newParsed.important && !existingParsed.important;
  }
  if (existingParsed.ip && !newParsed.ip) return false;
  if (!existingParsed.ip && newParsed.ip) return true;

  const eB = isBlockRewrite(existingParsed.ip);
  const nB = isBlockRewrite(newParsed.ip);

  // 重定向优先
  if (eB && !nB) return true;
  if (!eB && nB) return false;

  if (newParsed.important && !existingParsed.important) return true;
  return false;
};

/**
 * options.priorityFile：该文件里的规则优先级最高，不会被替换
 */
const prepareDnsRules = async (inputFile, outDir, archiveDir, options = {}) => {
  const { priorityFile = null } = options;

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

  // ★ 读入强制规则原文（用于优先保护）
  const prioritySet = new Set();
  if (priorityFile && fs.existsSync(priorityFile)) {
    await readLines(priorityFile, (line) => {
      const t = line.trim();
      if (t) prioritySet.add(t);
    });
    console.log(`强制优先规则：${prioritySet.size} 条`);
  }

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

      // ★ 强制规则优先：existing 是强制规则 → 不替换
      if (prioritySet.has(existing)) {
        if (conflictWriter) {
          await conflictWriter.write(`[强制保留] ${existing}  ✕  ${t}`);
          conflictCount++;
        }
        return;
      }
      // ★ 强制规则优先：new 是强制规则 → 替换
      if (prioritySet.has(t)) {
        if (conflictWriter) {
          await conflictWriter.write(`[强制替换] ${existing}  →  ${t}`);
          conflictCount++;
        }
        map.set(result.domain, t);
        return;
      }

      // 普通规则走 shouldReplace
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
    `DNS 兼容过滤完成：输入 ${total} 条 | 黑 ${seenBlack.size} | 白 ${seenWhite.size}（含重写 ${rewriteCount}）| 丢弃 ${dropped} | 同域冲突 ${conflictCount} | 强制优先 ${prioritySet.size}`,
  );

  return {
    blackFile,
    whiteFile,
    blackCount: seenBlack.size,
    whiteCount: seenWhite.size,
    rewriteCount,
    dropped,
    conflictCount,
    priorityCount: prioritySet.size,
  };
};

module.exports = { prepareDnsRules };
