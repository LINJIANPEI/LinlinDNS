const path = require("node:path");
const { readDir } = require("./common_func");
const { readLines, LineWriter } = require("./stream_utils");

// HTML 特征
const HTML_RE = /<\s*(html|head|body|div|a\s|script|style|!DOCTYPE|meta|link)/i;

// ★ AdGuard Home DNS 层支持的修饰符（其余一律整条丢弃）
const DNS_SUPPORTED_MODIFIERS = new Set([
  "important",
  "badfilter",
  "match-case",
  "denyallow",
  "dnsrewrite",
  "dnstype",
  "client",
]);

// 提取 $ 后的修饰符名（去掉 $、去掉 =值、去掉 ~ 前缀）
const getModifiers = (line) => {
  const idx = line.indexOf("$");
  if (idx === -1) return [];
  return line
    .slice(idx + 1)
    .split(",")
    .map((m) => m.trim().split("=")[0].replace(/^~/, "").toLowerCase())
    .filter(Boolean);
};

// 含任意 DNS 不支持的修饰符 → 整条丢弃
const hasUnsupportedModifier = (line) => {
  const mods = getModifiers(line);
  return mods.some((m) => !DNS_SUPPORTED_MODIFIERS.has(m));
};

// 静态资源后缀（不是域名）
const STATIC_FILE_RE =
  /\.(js|ts|css|html?|json|xml|txt|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|map|mp4|mp3|webm|m3u8)(\^|\$|$)/i;

/**
 * 是否符合 AdGuard Home DNS 规则。
 * 只放行：域名规则 / hosts 规则 / 纯域名 / DNS 支持的修饰符。
 */
const isValidRuleLine = (t) => {
  if (!t) return false;
  if (t.length < 3) return false;
  if (t.length > 1024) return false;

  // 注释 / 标题 / 元素隐藏规则 —— 全丢
  if (t.startsWith("!")) return false;
  if (t.startsWith("[")) return false;
  if (t.startsWith("#")) return false;

  // HTML 垃圾
  if (HTML_RE.test(t)) return false;

  // 必含 . 或 /
  if (!t.includes(".") && !t.includes("/")) return false;

  // ★ URL 路径规则一律丢
  if (/^\/(?!\/)/.test(t)) return false;

  // ★ 含 DNS 不支持的修饰符 → 整条丢
  if (hasUnsupportedModifier(t)) return false;

  // 静态资源后缀
  if (STATIC_FILE_RE.test(t)) return false;

  return true;
};

/**
 * 合并所有 rules*.txt / allow*.txt 到一个文件。
 * - 过滤注释 / 无效行 / URL 规则 / 不支持的修饰符
 * - 用 Set 去重，保留首次出现顺序
 */
const mergeAll = async (directory, outputFile) => {
  console.log("开始合并所有规则（含去重）");
  try {
    const fileList = await readDir(directory);
    const allFiles = fileList
      .filter(
        (f) =>
          (f.startsWith("rules") || f.startsWith("allow")) &&
          f.endsWith(".txt"),
      )
      .filter((f) => !/\.part\d+\./.test(f))
      .sort();

    const writer = new LineWriter(outputFile);

    if (allFiles.length === 0) {
      console.log("没有找到规则文件");
      await writer.close();
      return { fileCount: 0, lineCount: 0, skipped: 0, duplicated: 0 };
    }

    const seen = new Set();
    let skipped = 0;
    let duplicated = 0;
    let written = 0;

    for (const file of allFiles) {
      let fileWritten = 0;
      await readLines(path.join(directory, file), async (line) => {
        const t = line.trim();

        // 1. 过滤
        if (!isValidRuleLine(t)) {
          skipped++;
          return;
        }

        // 2. 去重
        if (seen.has(t)) {
          duplicated++;
          return;
        }
        seen.add(t);

        // 3. 写入
        await writer.write(t);
        written++;
        fileWritten++;
      });
      console.log(`  ${file}: 写入 ${fileWritten} 行`);
    }

    await writer.close();
    seen.clear();

    console.log(
      `合并完成：${allFiles.length} 个文件，` +
        `写入 ${written} 行，跳过 ${skipped} 行，去重 ${duplicated} 行`,
    );
    return {
      fileCount: allFiles.length,
      lineCount: written,
      skipped,
      duplicated,
    };
  } catch (error) {
    throw new Error(`合并失败: ${error.message}`);
  }
};

module.exports = { mergeAll };