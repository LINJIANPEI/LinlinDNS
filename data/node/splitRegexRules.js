const path = require("node:path");
const { readLines, LineWriter } = require("./stream_utils");

const REGEX_LINE_RE = /^(@@)?\/.+\/[^/]*$/;
const isRegexRuleLine = (s) => REGEX_LINE_RE.test(s);

/**
 * 从单一文件按【内容】分离正则/普通 + 黑/白。
 *
 * 判断顺序：
 *   @@ 前缀 → 白名单
 *   否则 → 黑名单
 *   /regex/ 格式 → 正则
 */
const splitRegexRules = async (inputFile, outDir) => {
  const files = {
    regexBlackFile: path.join(outDir, "black_regex.txt"),
    restBlackFile: path.join(outDir, "black_rest.txt"),
    regexWhiteFile: path.join(outDir, "white_regex.txt"),
    restWhiteFile: path.join(outDir, "white_rest.txt"),
  };

  const rb = new LineWriter(files.regexBlackFile);
  const rkb = new LineWriter(files.restBlackFile);
  const rw = new LineWriter(files.regexWhiteFile);
  const rkw = new LineWriter(files.restWhiteFile);

  await readLines(inputFile, async (line) => {
    const t = line.trim();
    if (!t) return;

    const isWhite = t.startsWith("@@");
    const isRegex = isRegexRuleLine(t);

    if (isWhite && isRegex) await rw.write(t);
    else if (isWhite) await rkw.write(t);
    else if (isRegex) await rb.write(t);
    else await rkb.write(t);
  });

  await Promise.all([rb.close(), rkb.close(), rw.close(), rkw.close()]);

  const counts = {
    regexBlacklist: rb.count,
    restBlacklist: rkb.count,
    regexWhitelist: rw.count,
    restWhitelist: rkw.count,
  };

  console.log(
    `拆分完成（按内容）：正则黑 ${counts.regexBlacklist}，普通黑 ${counts.restBlacklist}，` +
      `正则白 ${counts.regexWhitelist}，普通白 ${counts.restWhitelist}`,
  );

  return { ...files, counts };
};

module.exports = { splitRegexRules };
