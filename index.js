// 创建临时文件夹
const { createDir } = require("./data/node/createDir"); // createDir.js 模块
// 删除临时文件夹
const { deleteDir } = require("./data/node/deleteDir"); // deleteDir.js 模块
// 复制文件
const { copyFiles } = require("./data/node/copyFiles"); // copyFiles.js 模块
// 删除文件
const { deleteFiles } = require("./data/node/deleteFiles"); // deleteFiles.js 模块
//规则下载
const { downloadRules } = require("./data/node/downloadRules"); // downloadRules.js 模块

// 合并规则
// 黑名单
const { mergeBlacklists } = require("./data/node/mergeBlacklists"); // mergeBlacklists.js 模块
// 白名单
const { mergeWhitelist } = require("./data/node/mergeWhitelist"); // mergeWhitelist.js 模块

// 规则转换
const { transformations } = require("./data/node/transformations"); // transformations.js 模块
// 过滤DNS
const { filterDns } = require("./data/node/filterDns"); // filterDns.js 模块
// 处理所有规则
const { handleAllRules } = require("./data/node/handleAllRules"); // handleAllRules.js 模块
// 处理title
const { title } = require("./data/node/title"); // title.js 模块
// 处理md文件
const { cleanReadme } = require("./data/node/cleanReadme"); // cleanReadme.js 模块

//黑名单规则
const rules = [
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt", //5460
  "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt", //大萌主
  "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt", //DD
  "https://raw.gitmirror.com/Cats-Team/dns-filter/main/abp.txt", //AdRules DNS Filter
  "https://raw.hellogithub.com/hosts", //GitHub加速
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt", //测试hosts
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt", //白名单
  "https://raw.githubusercontent.com/loveqqzj/AdGuard/master/Mobile.txt", //loveqqzj
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Blacklist.txt", //mphin
  "https://gitee.com/zjqz/ad-guard-home-dns/raw/master/black-list", //周木木
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/black.txt", //liwenjie119
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/T%E7%99%BD%E5%90%8D%E5%8D%95.txt", //T白
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt", //秋风规则
  "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts", //FCM Hosts

  "https://www.coolapk.com/link?url=https%3A%2F%2Fraw.gitmirror.com%2FTTDNS%2FCat%2Fmain%2FTT%25E6%258B%2592%25E7%25BB%259D%25E5%2588%2597%25E8%25A1%25A8%25E6%25B8%2585%25E5%258D%2595%2520(%25E6%259B%25B4%25E6%2596%25B0%25E4%25B8%25AD).txt", //TTDNS
  "https://mirror.ghproxy.com/raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt", //HyperADRules
  "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/all.txt", //AdGuardHomeRules
  "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/manhua-max.txt", //AdGuardHomeRules
  "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/skyrules.txt", //AdGuardHomeRules
  "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/minority-mv.txt", //乘风视频
  "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt", //乘风视频
  "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt", //乘风视频
  "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/blacklist.txt", //Zisbusy
  "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/easylist.txt", //Zisbusy
  "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/filter.txt", //Zisbusy
  "https://raw.githubusercontent.com/sccheng460/adguard/main/blacklist.txt", //sccheng460
  "https://easylist-downloads.adblockplus.org/easylist.txt", //EasyList-去除国际网页
];
//白名单规则
const allow = [
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt", //白名单
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
  "https://file-git.trli.club/file-hosts/allow/Domains", //冷漠
  "https://hub.gitmirror.com/https://raw.githubusercontent.com/user001235/112/main/white.txt", //浅笑
  "https://gitee.com/zjqz/ad-guard-home-dns/raw/master/white-list", //周木木
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt", //liwenjie119
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/T%E7%99%BD%E5%90%8D%E5%8D%95.txt", //T白名单

  "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/whitelist.txt", //Zisbusy
  "https://raw.githubusercontent.com/sccheng460/adguard/main/whitelist.txt", //sccheng460
  "https://mirror.ghproxy.com/raw.githubusercontent.com/8680/GOODBYEADS/master/allow.txt", //8680
  "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/ok.txt", //AdGuardHomeRules
];
// 旧地址
const oldDirectory = "./tmp";
// 新地址
const newDirectory = "./";

async function main() {
  try {
    // 创建临时文件夹
    await createDir(oldDirectory);
    //规则下载
    await downloadRules(rules, allow, oldDirectory);
    // 删除文件
    await deleteFiles(
      "./allow.txt",
      "./dns.txt",
      "./DnsConfiguration.txt",
      "./rules.txt"
    );
    // 复制文件
    await copyFiles("./data/rules/adblock.txt", `${oldDirectory}/rules01.txt`);
    await copyFiles(
      "./data/rules/whitelist.txt",
      `${oldDirectory}/allow01.txt`
    );
    // 合并规则
    await mergeBlacklists(oldDirectory);
    await mergeWhitelist(oldDirectory);

    // 规则转换
    await transformations(
      `${oldDirectory}/tmp-rules.txt`,
      `${oldDirectory}/tmp-allow.txt`
    );

    // 复制文件
    await copyFiles(
      `${oldDirectory}/tmp-allow.txt`,
      `${newDirectory}/allow.txt`
    );
    await copyFiles(
      `${oldDirectory}/tmp-rules.txt`,
      `${newDirectory}/rules.txt`
    );
    // 过滤DNS
    await filterDns(newDirectory);

    // 处理所有规则
    await handleAllRules("./allow.txt", "./dns.txt", "./rules.txt");

    // 处理title
    await title();
    // 处理md文件
    await cleanReadme();
    // 删除临时文件夹
    await deleteDir(oldDirectory);
    console.log("更新完成");
  } catch (error) {
    throw `更新失败:${error}`;
  }
}
main();
