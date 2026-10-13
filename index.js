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
// ★ 缓存模式（从环境变量读取）
// ------------------------------------------------------------
//   CI:  由 workflow 的 env.CACHE_READ / env.CACHE_WRITE 注入
//   本地: 不设环境变量时默认 read=true, write=true
//
//   A 不读不写：CACHE_READ=false CACHE_WRITE=false node index.js
//   B 只读不写：CACHE_READ=true  CACHE_WRITE=false node index.js
//   C 要读要写：CACHE_READ=true  CACHE_WRITE=true  node index.js  ← 默认
//   D 只写不读：CACHE_READ=false CACHE_WRITE=true  node index.js
// ============================================================
const CACHE_MODE = {
  read: process.env.CACHE_READ !== "false",
  write: process.env.CACHE_WRITE !== "false",
};

// ★ 归档文件名（中文，按流水线编号）
const ARCHIVE = {
  // ===== 阶段 1：合并上游规则（mergeAll）=====
  mergeInvalid: "① 合并-无效行.txt",
  mergeParseFail: "② 合并-无法解析.txt",
  mergeFormatFail: "③ 合并-格式化失败.txt",
  mergeDuplicate: "④ 合并-重复规则.txt",

  // ===== 阶段 2：DNS 兼容过滤（prepareDnsRules）=====
  dnsParseFail: "⑤ DNS-无法解析.txt",

  // ===== 阶段 3：剔除死域名（removeDeadRules）=====
  dead: "⑥ 死域名.txt",
  passthrough: "⑦ 非域名行.txt",

  // ===== 阶段 4：构建 AdGuard 列表（buildAdGuardHomeLists）=====
  noBlacklist: "⑧ 黑名单被覆盖.txt",
  noWhitelist: "⑨ 白名单被收敛.txt",
  skipped: "⑩ 构建-无法解析.txt",
  redundant: "⑪ 构建-同域冗余.txt",
  buildDuplicate: "⑫ 构建-重复规则.txt",
};

async function main() {
  try {
    console.log(`缓存模式：read=${CACHE_MODE.read} write=${CACHE_MODE.write}`);

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
      outDuplicateFile: path.join(removeDir, ARCHIVE.buildDuplicate),
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
