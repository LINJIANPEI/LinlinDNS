const path = require("node:path");
const { readLines, LineWriter } = require("./stream_utils");

const REGEX_LINE_RE = /^(@@)?\/.+\/[^/]*$/;
const isRegexRuleLine = (s) => REGEX_LINE_RE.test(s);

/**
 * 从黑/白名单文件中分离正则规则，输出 4 个文件。
 * @returns {Promise<{regexBlackFile, restBlackFile, regexWhiteFile, restWhiteFile, counts}>}
 */
const splitRegexRules = async (blackFile, whiteFile, outDir) => {
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

  await readLines(blackFile, async (line) => {
    const t = line.trim();
    if (!t) return;
    if (isRegexRuleLine(t)) await rb.write(t);
    else await rkb.write(line);
  });

  await readLines(whiteFile, async (line) => {
    const t = line.trim();
    if (!t) return;
    if (isRegexRuleLine(t)) await rw.write(t);
    else await rkw.write(line);
  });

  await Promise.all([rb.close(), rkb.close(), rw.close(), rkw.close()]);

  const counts = {
    regexBlacklist: rb.count,
    restBlacklist: rkb.count,
    regexWhitelist: rw.count,
    restWhitelist: rkw.count,
  };

  console.log(
    `正则抽离完成：正则黑 ${counts.regexBlacklist}，普通黑 ${counts.restBlacklist}，` +
      `正则白 ${counts.regexWhitelist}，普通白 ${counts.restWhitelist}`,
  );

  return { ...files, counts };
};

module.exports = { splitRegexRules };
