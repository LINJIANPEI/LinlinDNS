const path = require("node:path");
const { createDir, copyFiles, deleteDir } = require("./data/node/common_func");

const { readListFile } = require("./data/node/readListFile");
const { downloadRules } = require("./data/node/downloadRules");
const { mergeBlacklists } = require("./data/node/mergeBlacklists");
const { mergeWhitelist } = require("./data/node/mergeWhitelist");
const { dedupeFile } = require("./data/node/dedupe"); // ★ 新增
const { splitRegexRules } = require("./data/node/splitRegexRules");
const { removeDeadRules } = require("./data/node/removeDeadRules");
const { buildAdGuardHomeLists } = require("./data/node/buildAdGuardHomeLists");
const { title } = require("./data/node/title");
const { cleanReadme } = require("./data/node/cleanReadme");

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

    // 1. 合并 → 文件
    await mergeBlacklists(tmpDir, p("black_all.txt"));
    await mergeWhitelist(tmpDir, p("white_all.txt"));

    // ★ 2. 去重（sort -u，原地替换）
    await dedupeFile(p("black_all.txt"));
    await dedupeFile(p("white_all.txt"));

    // 3. 正则抽离 → 4 个文件
    const split = await splitRegexRules(
      p("black_all.txt"),
      p("white_all.txt"),
      tmpDir,
    );

    // 4. 剔除死域名（输入 = rest 黑 + rest 白 两个文件）
    await removeDeadRules([split.restBlackFile, split.restWhiteFile], {
      cleanedFile: p("cleaned.txt"),
      nocleanedFile: p("nocleaned.txt"),
      passthroughFile: p("passthrough.txt"),
      deadDomainsFile: p("dead-domains.txt"),
      cacheFile: "./dns-cache.json",
      concurrency: 500,
    });

    // 5. 构建最终列表（直接写 rules.txt / allow.txt）
    await deleteDir(removeDir);
    await createDir(removeDir);

    await buildAdGuardHomeLists({
      cleanedFile: p("cleaned.txt"),
      regexBlackFile: split.regexBlackFile,
      regexWhiteFile: split.regexWhiteFile,
      outRulesFile: path.join(outDir, "rules.txt"),
      outAllowFile: path.join(outDir, "allow.txt"),
      outNoBlacklistFile: path.join(removeDir, "noblacklist.txt"),
      outNoWhitelistFile: path.join(removeDir, "nowhitelist.txt"),
      outSkippedFile: path.join(removeDir, "skipped.txt"),
    });

    // 6. 把 nocleaned / passthrough 复制到 remove 目录
    await copyFiles(
      [p("nocleaned.txt"), path.join(removeDir, "dead.txt")],
      [p("passthrough.txt"), path.join(removeDir, "passthrough.txt")],
    );

    await title();
    await cleanReadme();
    console.log("更新完成");
  } catch (error) {
    console.log(`更新失败:${error}`);
  } finally {
    await deleteDir(tmpDir);
  }
}

main();
