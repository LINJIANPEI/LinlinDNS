const {
  createDir,
  copyFiles,
  deleteDir,
  deleteFiles,
  writeFile,
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
    // 创建临时文件夹
    await createDir(oldDirectory);
    await createDir(removeDir);

    //黑名单规则
    const rules = await readListFile("./data/configs/rules.txt", "黑名单");
    //白名单规则
    const allow = await readListFile("./data/configs/allow.txt", "白名单");

    //规则下载
    await downloadRules(rules, allow, oldDirectory);

    // 复制文件
    await copyFiles(
      ["./data/rules/adblock.txt", `${oldDirectory}/rules01.txt`],
      ["./data/rules/whitelist.txt", `${oldDirectory}/allow01.txt`],
    );

    // 合并规则
    const blacklists1 = await mergeBlacklists(oldDirectory);
    const whitelists1 = await mergeWhitelist(oldDirectory);

    const { regexBlacklist, regexWhitelist, restBlacklist, restWhitelist } =
      splitRegexRules(blacklists1, whitelists1);

    const { cleaned, nocleaned, passthrough } = await removeDeadRules([
      ...restBlacklist,
      ...restWhitelist,
    ]);

    // 精确去重和域名标准化去重，并处理黑白名单冲突
    const { blacklist, whitelist, noblacklist, nowhitelist, skipped } =
      buildAdGuardHomeLists(cleaned);

    // 删除文件
    await deleteFiles(
      `${newDirectory}/allow.txt`,
      `${newDirectory}/rules.txt`,
      `${removeDir}/dead.txt`,
      `${removeDir}/noblacklist.txt`,
      `${removeDir}/nowhitelist.txt`,
      `${removeDir}/skipped.txt`,
      `${removeDir}/passthrough.txt`,
    );

    //有效规则
    await writeFile(
      `${newDirectory}/rules.txt`,
      [...blacklist, ...regexBlacklist].join("\n"),
    );
    await writeFile(
      `${newDirectory}/allow.txt`,
      [...whitelist, ...regexWhitelist].join("\n"),
    );

    //去重以及丢弃规则
    await writeFile(`${removeDir}/noblacklist.txt`, noblacklist.join("\n"));
    await writeFile(`${removeDir}/nowhitelist.txt`, nowhitelist.join("\n"));
    await writeFile(`${removeDir}/skipped.txt`, skipped.join("\n"));
    // 死域名清单
    await writeFile(`${removeDir}/dead.txt`, nocleaned.join("\n"));
    //丢弃的规则
    await writeFile(`${removeDir}/passthrough.txt`, passthrough.join("\n"));

    // 处理title
    await title();
    // 处理md文件
    await cleanReadme();
    console.log("更新完成");
  } catch (error) {
    console.log(`更新失败:${error}`);
  } finally {
    // 删除临时文件夹
    await deleteDir(oldDirectory);
  }
}
main();
