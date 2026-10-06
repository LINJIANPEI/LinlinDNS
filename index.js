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

// 处理title
const { title } = require("./data/node/title"); // title.js 模块
// 处理md文件
const { cleanReadme } = require("./data/node/cleanReadme"); // cleanReadme.js 模块

// 旧地址
const oldDirectory = "./tmp";
// 新地址
const newDirectory = "./";

async function main() {
  try {
    // 创建临时文件夹
    await createDir(oldDirectory);

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

    // 合并规则并去重
    const blacklists1 = await mergeBlacklists(oldDirectory);

    const whitelists1 = await mergeWhitelist(oldDirectory);

    // 删除文件
    await deleteFiles(`${newDirectory}/allow.txt`, `${newDirectory}/rules.txt`);

    //有效规则

    await writeFile(`${newDirectory}/rules.txt`, [...blacklists1].join("\n"));

    await writeFile(`${newDirectory}/allow.txt`, [...whitelists1].join("\n"));

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
