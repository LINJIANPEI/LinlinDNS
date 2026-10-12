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

// ★ 归档文件名（中文）
const ARCHIVE = {
  dead: "死域名.txt",
  passthrough: "非域名行.txt",
  noBlacklist: "被覆盖的黑名单.txt",
  noWhitelist: "被收敛的白名单.txt",
  skipped: "无法解析.txt",
  redundant: "冗余规则.txt",
  // ★ 新增归档
  mergeInvalid: "合并-无效行.txt",
  mergeParseFail: "合并-解析失败.txt",
  mergeFormatFail: "合并-格式化失败.txt",
  mergeDuplicate: "合并-重复行.txt",
  dnsParseFail: "DNS兼容-解析失败.txt",
  buildDuplicate: "构建-重复行.txt",
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
