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
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt", //5460
  "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt", //大萌主
  "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt", //DD
  "https://raw.gitmirror.com/Cats-Team/dns-filter/main/abp.txt", //AdRules DNS Filter
  "https://www.i-dont-care-about-cookies.eu/abp/", //I don't care about cookies
  "https://raw.hellogithub.com/hosts", //GitHub加速
  "https://raw.githubusercontent.com/loveqqzj/AdGuard/master/Mobile.txt", //loveqqzj
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Blacklist.txt", //mphin
  "https://gitee.com/zjqz/ad-guard-home-dns/raw/master/black-list", //周木木
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/black.txt", //liwenjie119
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt", //秋风规则
  "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts", //FCM Hosts
  "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt", //8680
  "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt", //8680
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
  "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt", //海哥
  "https://anti-ad.net/easylist.txt", //anti-AD
  "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt", //Anti-AD抗ad
  "https://raw.githubusercontent.com/cjx82630/cjxlist/refs/heads/master/cjx-ublock.txt", //CJX'suBlocklist
  "https://easylist-downloads.adblockplus.org/easyprivacy.txt", //EasyListPrivacy
  "https://easylist-downloads.adblockplus.org/easylistchina.txt", //EasylistChina
  "https://raw.githubusercontent.com/cjx82630/cjxlist/refs/heads/master/cjx-annoyance.txt", //CJX'sAnnoyanceList
  "https://cdn.jsdelivr.net/gh/zsakvo/AdGuard-Custom-Rule@master/rule/zhihu-strict.txt", //移除知乎部分广告
  "https://raw.githubusercontent.com/zsakvo/AdGuard-Custom-Rule/master/rule/zhihu.txt", // Basic
  "http://sub.adtchrome.com/adt-chinalist-easylist.txt", //ChinaList+EasyList(淇)
  "https://raw.githubusercontent.com/Goooler/1024_hosts/master/hosts", //Goooler
  "https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts", //ad-wars
  "https://raw.githubusercontent.com/jdlingyu/ad-wars/master/sha_ad_hosts", //ad-wars
  "https://adaway.org/hosts.txt", //AdAwayAdaway
  "http://winhelp2002.mvps.org/hosts.txt", //MVPSHOST
  "https://hblock.molinero.dev/hosts ", //Hblock
  "https://raw.githubusercontent.com/yous/YousList/master/hosts.txt"//YousList
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", //StevenBlack
  "https://raw.githubusercontent.com/googlehosts/hosts/master/hosts-files/hosts", //Google hosts
  "https://cdn.jsdelivr.net/gh/neoFelhz/neohosts@gh-pages/full/hosts.txt", //NekoDevTeam&neoHostsTeam
  "https://cdn.jsdelivr.net/gh/neoFelhz/neohosts@gh-pages/basic/hosts.txt ", //Basic
  "https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts.txt", //VeleSila/yhosts
  "https://raw.githubusercontent.com/timlu85/AdGuard-Home_Youtube-Adfilter/master/Youtube-Adfilter-Web.txt", //Youtube-Adfilter-Web
  "https://raw.githubusercontent.com/91ajames/ublock-filters-ulist-youtube/main/blocklist.txt", //ublock-filters-ulist-youtube
  "https://halflife.coding.net/p/list/d/list/git/raw/master/ad.txt", //本规则合并自乘风视频广告过滤规则、EasylistChina、EasylistLite、CJX'sAnnoyance
  "https://cdn.jsdelivr.net/gh/anudeepND/blacklist@master/adservers.txt", //anudeepND/blacklist
  "https://raw.githubusercontent.com/neodevpro/neodevhost/master/adblocker", //NEODEVHOST
  "https://cdn.jsdelivr.net/gh/liwenjie119/adg-rules@master/black.txt", //LWJ'sblacklist
  "https://raw.githubusercontent.com/mphin/adguardhome_rules/main/Blacklist.txt", //mphin
];
//白名单规则
const allow = [
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt", //5460
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/T%E7%99%BD%E5%90%8D%E5%8D%95.txt", //T白 5460
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
  "https://file-git.trli.club/file-hosts/allow/Domains", //冷漠
  "https://hub.gitmirror.com/https://raw.githubusercontent.com/user001235/112/main/white.txt", //浅笑
  "https://gitee.com/zjqz/ad-guard-home-dns/raw/master/white-list", //周木木
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt", //liwenjie119
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/T%E7%99%BD%E5%90%8D%E5%8D%95.txt", //T白名单

  "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/whitelist.txt", //Zisbusy
  "https://raw.githubusercontent.com/sccheng460/adguard/main/whitelist.txt", //sccheng460
  "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt", //8680
  "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/ok.txt", //AdGuardHomeRules
  "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/skyrules.txt", //AdGuardHomeRules
  "https://cdn.jsdelivr.net/gh/hl2guide/Filterlist-for-AdGuard@master/filter_whitelist.txt", //hl2guideFilterlist-for-AdGuard
  "https://cdn.jsdelivr.net/gh/hg1978/AdGuard-Home-Whitelist@master/whitelist.txt", //hg1978/AdGuard-Home-Whitelist
  "https://cdn.jsdelivr.net/gh/mmotti/adguard-home-filters@master/whitelist.txt", //mmotti/adguard-home-filters
  "https://raw.githubusercontent.com/mawenjian/china-cdn-domain-whitelist/master/china-top-website-whitelist.txt", //china-cdn-domain-whitelist
  "https://raw.githubusercontent.com/mawenjian/china-cdn-domain-whitelist/master/china-cdn-domain-whitelist.txt", //china-cdn-domain-whitelist
  "https://raw.githubusercontent.com/pluwen/china-domain-allowlist/master/allow-list.sorl", //china-domain-allowlist
  "https://raw.githubusercontent.com/entr0pia/SwitchyOmega-Whitelist/master/white-list.sorl", //SwitchyOmega-Whitelist
  "https://cdn.jsdelivr.net/gh/liwenjie119/adg-rules@master/white.txt", //LWJ'swhitelist
  "https://cdn.jsdelivr.net/gh/LucienShui/chinalist@gh-pages/chinalist.txt", //LucienShui/chinalist
  "https://raw.githubusercontent.com/etotakeo/AdGuardDNSPassList/master/DNS-Pass-List", //etotakeo/AdGuardDNSPassList
  "https://cdn.jsdelivr.net/gh/JamesDamp/AdGuard-Home---Personal-Whitelist@master/AdGuardHome-Whitelist.txt", //JamesDamp/Personal-Whitelist
  "https://raw.githubusercontent.com/Aveelo/Aveelo-adguard-home-Adlist-Whitelist/master/WhitelistAdGuardHome", //Aveelo-adguard-home-Adlist-Whitelist
  "https://raw.githubusercontent.com/mphin/adguardhome_rules/main/Allowlist.txt", //mphin
  "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt", //5460
  "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt", //AdguardFilter
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
    console.log("更新完成");
  } catch (error) {
    console.log(`更新失败:${error}`);
  } finally {
    // 删除临时文件夹
    await deleteDir(oldDirectory);
  }
}
main();
