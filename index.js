const path = require("node:path");
const fs = require("node:fs");
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

const CACHE_MODE = {
  read: process.env.CACHE_READ !== "false",
  write: process.env.CACHE_WRITE !== "false",
};

const ARCHIVE = {
  mergeInvalid: "① 合并-无效行.txt",
  mergeParseFail: "② 合并-无法解析.txt",
  mergeFormatFail: "③ 合并-格式化失败.txt",
  mergeDuplicate: "④ 合并-重复规则.txt",

  dnsParseFail: "⑤ DNS-无法解析.txt",

  dead: "⑥ 死域名.txt",
  passthrough: "⑦ 非域名行.txt",

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

    await deleteDir(removeDir);
    await createDir(removeDir);

    const rules = await readListFile("./data/configs/rules.txt", "黑名单");
    const allow = await readListFile("./data/configs/allow.txt", "白名单");

    await downloadRules(rules, allow, tmpDir);

    await copyFiles(
      ["./data/rules/adblock.txt", p("rules01.txt")],
      ["./data/rules/whitelist.txt", p("allow01.txt")],
    );

    await mergeAll(tmpDir, p("all.txt"), removeDir);

    const dns = await prepareDnsRules(p("all.txt"), tmpDir, removeDir);

    await removeDeadRules([dns.blackFile, dns.whiteFile], {
      cleanedFile: p("cleaned.txt"),
      nocleanedFile: p("nocleaned.txt"),
      passthroughFile: p("passthrough.txt"),
      deadDomainsFile: p("dead-domains.txt"),
      cacheFile: "./dns-cache.json",
      cacheRead: CACHE_MODE.read,
      cacheWrite: CACHE_MODE.write,
      concurrency: 1500,
    });

    await buildAdGuardHomeLists({
      cleanedFile: p("cleaned.txt"),
      outRulesFile: path.join(outDir, "rules.txt"),
      outAllowFile: path.join(outDir, "allow.txt"),
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

    // ★ 排查：确认关键文件存在
    console.log("=== 当前目录文件检查 ===");
    for (const f of ["rules.txt", "allow.txt", "README.md"]) {
      if (fs.existsSync(f)) {
        const s = fs.statSync(f);
        console.log(`  ✓ ${f} (${(s.size / 1024).toFixed(1)} KB)`);
      } else {
        console.error(`  ✗ ${f} 不存在！`);
      }
    }

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
