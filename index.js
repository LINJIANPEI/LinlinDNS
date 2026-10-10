const path = require("node:path");
const { createDir, copyFiles, deleteDir } = require("./data/node/common_func");

const { readListFile } = require("./data/node/readListFile");
const { downloadRules } = require("./data/node/downloadRules");
const { mergeAll } = require("./data/node/mergeAll");
const { dedupeFile } = require("./data/node/dedupe");
const { prepareDnsRules } = require("./data/node/prepareDnsRules"); // ★ 替代 splitRegexRules
const { removeDeadRules } = require("./data/node/removeDeadRules");
const { buildAdGuardHomeLists } = require("./data/node/buildAdGuardHomeLists");
const { title } = require("./data/node/title");
const { cleanReadme } = require("./data/node/cleanReadme");
const { splitLargeFilesInDir } = require("./data/node/splitLargeFile");

const tmpDir = "./tmp";
const outDir = "./";
const removeDir = "./data/remove";

const p = (f) => path.join(tmpDir, f);

async function main() {
  try {
    await createDir(tmpDir);

    const rules = await readListFile("./data/configs/rules.txt", "黑名单");
    const allow = await readListFile("./data/configs/allow.txt", "白名单");

    await downloadRules(rules, allow, tmpDir);

    await copyFiles(
      ["./data/rules/adblock.txt", p("rules01.txt")],
      ["./data/rules/whitelist.txt", p("allow01.txt")],
    );

    await mergeAll(tmpDir, p("all.txt"));
    await dedupeFile(p("all.txt"));

    const dns = await prepareDnsRules(p("all.txt"), tmpDir);

    await removeDeadRules([dns.blackFile, dns.whiteFile], {
      cleanedFile: p("cleaned.txt"),
      nocleanedFile: p("nocleaned.txt"),
      passthroughFile: p("passthrough.txt"),
      deadDomainsFile: p("dead-domains.txt"),
      cacheFile: "./dns-cache.json",
      concurrency: 500,
    });

    await deleteDir(removeDir);
    await createDir(removeDir);

    await buildAdGuardHomeLists({
      cleanedFile: p("cleaned.txt"),
      outRulesFile: path.join(outDir, "rules.txt"),
      outAllowFile: path.join(outDir, "allow.txt"),
      outNoBlacklistFile: path.join(removeDir, "noblacklist.txt"),
      outNoWhitelistFile: path.join(removeDir, "nowhitelist.txt"),
      outSkippedFile: path.join(removeDir, "skipped.txt"),
    });

    await copyFiles(
      [p("nocleaned.txt"), path.join(removeDir, "dead.txt")],
      [p("passthrough.txt"), path.join(removeDir, "passthrough.txt")],
    );

    await title();

    await splitLargeFilesInDir(outDir, {
      pattern: /^(rules|allow)\.txt$/,
    });
    await splitLargeFilesInDir(removeDir);

    await cleanReadme();

    console.log("更新完成");
    process.exitCode = 0; // ★ 显式成功
  } catch (error) {
    console.error(`更新失败:${error.stack || error}`); // ★ 打完整堆栈
    process.exitCode = 1; // ★ 关键：标记失败
  } finally {
    await deleteDir(tmpDir);
  }
}

main();
