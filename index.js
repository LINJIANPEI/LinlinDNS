const {
  createDir,
  copyFiles,
  deleteDir,
  deleteFiles,
  writeFile,
  writeFileArray,
} = require("./data/node/common_func"); // common_func.js 模块

// 读取规则源
const { readListFile } = require("./data/node/readListFile"); // readListFile.js 模块

//规则下载
const { downloadRules } = require("./data/node/downloadRules"); // downloadRules.js 模块

// 合并规则
// 黑名单
const { mergeBlacklists } = require("./data/node/mergeBlacklists"); // mergeBlacklists.js 模块
// 白名单
const { mergeWhitelist } = require("./data/node/mergeWhitelist"); // mergeWhitelist.js 模块

// 正则抽离
const { splitRegexRules } = require("./data/node/splitRegexRules"); // splitRegexRules.js 模块

// 去除死域名
const { removeDeadRules } = require("./data/node/removeDeadRules"); // removeDeadRules.js 模块

// 精确去重和域名标准化去重，并处理黑白名单冲突
const { buildAdGuardHomeLists } = require("./data/node/buildAdGuardHomeLists"); // buildAdGuardHomeLists.js 模块

// 处理title
const { title } = require("./data/node/title"); // title.js 模块
// 处理md文件
const { cleanReadme } = require("./data/node/cleanReadme"); // cleanReadme.js 模块

// 旧地址
const oldDirectory = "./tmp";
// 新地址
const newDirectory = "./";

// 丢弃的规则
const removeDir = "./data/remove";

async function main() {
  try {
    await createDir(oldDirectory);

    const rules = await readListFile("./data/configs/rules.txt", "黑名单");
    const allow = await readListFile("./data/configs/allow.txt", "白名单");

    await downloadRules(rules, allow, oldDirectory);

    await copyFiles(
      ["./data/rules/adblock.txt", `${oldDirectory}/rules01.txt`],
      ["./data/rules/whitelist.txt", `${oldDirectory}/allow01.txt`],
    );

    // ---------- 1. 合并 ----------
    let blacklists1 = await mergeBlacklists(oldDirectory);
    let whitelists1 = await mergeWhitelist(oldDirectory);

    // ---------- 2. 正则抽离 ----------
    const { regexBlacklist, regexWhitelist, restBlacklist, restWhitelist } =
      splitRegexRules(blacklists1, whitelists1);

    // ★ 立刻释放原始数组
    blacklists1 = null;
    whitelists1 = null;
    if (global.gc) global.gc();

    // ---------- 3. 合并 rest（concat 而非 spread）----------
    const restAll = restBlacklist.concat(restWhitelist);

    // ---------- 4. 剔除死域名 ----------
    // ★ 关闭缓存，省下 305 万条 map + 序列化开销
    //   如果你确实想要缓存，用 cacheFile: "./dns-cache.json"
    const { cleaned, nocleaned, passthrough } = await removeDeadRules(restAll, {
      cacheFile: "./dns-cache.json",
    });

    // ---------- 5. 构建最终列表 ----------
    const { blacklist, whitelist, noblacklist, nowhitelist, skipped } =
      buildAdGuardHomeLists(cleaned);

    await deleteFiles(`${newDirectory}/allow.txt`, `${newDirectory}/rules.txt`);

    // ★ 用 writeFileArray，不要 join 大字符串
    await writeFileArray(
      `${newDirectory}/rules.txt`,
      blacklist.concat(regexBlacklist),
    );
    await writeFileArray(
      `${newDirectory}/allow.txt`,
      whitelist.concat(regexWhitelist),
    );

    await deleteDir(removeDir);
    await createDir(removeDir);

    await writeFileArray(`${removeDir}/noblacklist.txt`, noblacklist);
    await writeFileArray(`${removeDir}/nowhitelist.txt`, nowhitelist);
    await writeFileArray(`${removeDir}/skipped.txt`, skipped);
    await writeFileArray(`${removeDir}/dead.txt`, nocleaned);
    await writeFileArray(`${removeDir}/passthrough.txt`, passthrough);

    await title();
    await cleanReadme();
    console.log("更新完成");
  } catch (error) {
    console.log(`更新失败:${error}`);
  } finally {
    await deleteDir(oldDirectory);
  }
}

main();
