const path = require("node:path");
const { createDir, copyFiles, deleteDir } = require("./data/node/common_func");

const { readListFile } = require("./data/node/readListFile");
const { downloadRules } = require("./data/node/downloadRules");
const { mergeAll } = require("./data/node/mergeAll");
const { prepareDnsRules } = require("./data/node/prepareDnsRules");
const { removeDeadRules } = require("./data/node/removeDeadRules");
const { buildAdGuardHomeLists } = require("./data/node/buildAdGuardHomeLists");
const { title } = require("./data/node/title");
const { cleanReadme } = require("./data/node/cleanReadme");
const { splitLargeFilesInDir } = require("./data/node/splitLargeFile");

const tmpDir = "./tmp";
const outDir = "./";
const removeDir = "./data/remove";

const p = (f) => path.join(tmpDir, f);

// ============================================================
// ★ 缓存模式（改这里切换）
// ------------------------------------------------------------
//   A 不读不写：cacheRead: false, cacheWrite: false
//   B 只读不写：cacheRead: true,  cacheWrite: false
//   C 要读要写：cacheRead: true,  cacheWrite: true   ← 默认
//   D 只写不读：cacheRead: false, cacheWrite: true
// ============================================================
const CACHE_MODE = {
  read: true,
  write: true,
};

// ★ 归档文件名（中文，按流水线编号）
const ARCHIVE = {
  mergeInvalid: "01-合并-无效行.txt",
  mergeParseFail: "02-合并-无法解析.txt",
  mergeFormatFail: "03-合并-格式化失败.txt",
  mergeDuplicate: "04-合并-重复规则.txt",
  dnsParseFail: "05-DNS-无法解析.txt",
  dead: "06-死域名.txt",
  passthrough: "07-非域名行.txt",
  noBlacklist: "08-黑名单被覆盖.txt",
  noWhitelist: "09-白名单被收敛.txt",
  skipped: "10-构建-无法解析.txt",
  redundant: "11-构建-同域冗余.txt",
  buildDuplicate: "12-构建-重复规则.txt",
};

async function main() {
  try {
    await createDir(tmpDir);

    // ★ 提前创建归档目录，供 mergeAll / prepareDnsRules 写入
    await deleteDir(removeDir);
    await createDir(removeDir);

    const rules = await readListFile("./data/configs/rules.txt", "黑名单");
    const allow = await readListFile("./data/configs/allow.txt", "白名单");

    await downloadRules(rules, allow, tmpDir);

    await copyFiles(
      ["./data/rules/adblock.txt", p("rules01.txt")],
      ["./data/rules/whitelist.txt", p("allow01.txt")],
    );

    // ★ 传入归档目录
    await mergeAll(tmpDir, p("all.txt"), removeDir);

    // ★ 传入归档目录
    const dns = await prepareDnsRules(p("all.txt"), tmpDir, removeDir);

    await removeDeadRules([dns.blackFile, dns.whiteFile], {
      cleanedFile: p("cleaned.txt"),
      nocleanedFile: p("nocleaned.txt"),
      passthroughFile: p("passthrough.txt"),
      deadDomainsFile: p("dead-domains.txt"),
      cacheFile: "./dns-cache.json",
      cacheRead: CACHE_MODE.read, // ★ 缓存读开关
      cacheWrite: CACHE_MODE.write, // ★ 缓存写开关
      concurrency: 500,
    });

    // ★ removeDir 已在 main 开头创建，无需重复删除/创建

    await buildAdGuardHomeLists({
      cleanedFile: p("cleaned.txt"),
      // ★ 产物保持英文（订阅链接指向它们）
      outRulesFile: path.join(outDir, "rules.txt"),
      outAllowFile: path.join(outDir, "allow.txt"),
      // ★ 归档用中文
      outNoBlacklistFile: path.join(removeDir, ARCHIVE.noBlacklist),
      outNoWhitelistFile: path.join(removeDir, ARCHIVE.noWhitelist),
      outSkippedFile: path.join(removeDir, ARCHIVE.skipped),
      outRedundantFile: path.join(removeDir, ARCHIVE.redundant),
      outDuplicateFile: path.join(removeDir, ARCHIVE.buildDuplicate), // ★ 新增
    });

    await copyFiles(
      [p("nocleaned.txt"), path.join(removeDir, ARCHIVE.dead)],
      [p("passthrough.txt"), path.join(removeDir, ARCHIVE.passthrough)],
    );

    await title();

    await splitLargeFilesInDir(outDir, {
      pattern: /^(rules|allow)\.txt$/,
    });
    await splitLargeFilesInDir(removeDir);

    await cleanReadme();

    console.log("更新完成");
    process.exitCode = 0;
  } catch (error) {
    console.error(`更新失败:${error.stack || error}`);
    process.exitCode = 1;
  } finally {
    await deleteDir(tmpDir);
  }
}

main();
