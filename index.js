const {
  createDir,
  copyFiles,
  deleteDir,
  deleteFiles,
  writeFile,
  getFileNamesWithSuffixAsync,
  writeFileWithSizeCheck,
} = require("./data/node/common_func"); // common_func.js 模块

//规则下载
const { downloadRules } = require("./data/node/downloadRules"); // downloadRules.js 模块

// 合并规则
// 黑名单
const { mergeBlacklists } = require("./data/node/mergeBlacklists"); // mergeBlacklists.js 模块
// 白名单
const { mergeWhitelist } = require("./data/node/mergeWhitelist"); // mergeWhitelist.js 模块

const { optimizeProcessing } = require("./data/node/optimizeProcessing"); // optimizeProcessing.js 模块

const { AdGuardConverters } = require("./data/node/AdGuardConverters"); // AdGuardConverters.js 模块

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
  "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", //AdGuard DNS filter
  "https://raw.githubusercontent.com/yous/YousList/master/hosts.txt", //YousList
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
  "https://raw.githubusercontent.com/mphin/adguardhome_rules/main/Blacklist.txt", //mphin
  "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt", //217heidai/adblockfilters
  "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt", //217heidai/adblockfilters
  "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt", //217heidai/adblockfilters
  "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilterslite.txt", //217heidai/adblockfilters
  "https://cdn.jsdelivr.net/gh/LucienShui/chinalist@gh-pages/chinalist.txt", //LucienShui/chinalist
  "https://raw.githubusercontent.com/qq5460168/666/master/rules.txt", //酷安反馈
  "https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt", //HyperADRules
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt", //AWAvenue
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt", //AWAvenue Ads Rule
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
  "https://raw.githubusercontent.com/mawenjian/china-cdn-domain-whitelist/master/china-cdn-domain-whitelist.txt", //china-cdn-domain-whitelist
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

const assets = "./data/assets";

async function main() {
  try {
    // 创建临时文件夹
    await createDir(oldDirectory);
    //规则下载
    await downloadRules(rules, allow, oldDirectory);

    // 复制文件
    await copyFiles(
      ["./data/rules/adblock.txt", `${oldDirectory}/rules01.txt`],
      ["./data/rules/whitelist.txt", `${oldDirectory}/allow01.txt`]
    );

    // 合并规则并去重
    const blacklists1 = await mergeBlacklists(oldDirectory);

    const whitelists1 = await mergeWhitelist(oldDirectory);

    // 使用示例
    const optimizedResult = await optimizeProcessing(blacklists1, whitelists1);

    // 删除文件
    await deleteFiles(
      `${newDirectory}/allow.txt`,
      `${newDirectory}/dns.txt`,
      `${newDirectory}/dnsallow.txt`,
      `${newDirectory}/DnsConfiguration.txt`,
      `${newDirectory}/rules.txt`
    );

    await deleteFiles(
      ...(await getFileNamesWithSuffixAsync(`${assets}`, `${assets}/`))
    );

    //有效规则
    await writeFile(
      `${newDirectory}/dns.txt`,
      optimizedResult.effective.blacklist.join("\n")
    );

    await writeFile(
      `${newDirectory}/dnsallow.txt`,
      optimizedResult.effective.whitelist.join("\n")
    );

    await writeFile(
      `${newDirectory}/rules.txt`,
      AdGuardConverters(optimizedResult.excluded.blacklist.invalid).join("\n")
    );

    await writeFile(
      `${newDirectory}/allow.txt`,
      AdGuardConverters(optimizedResult.excluded.whitelist.invalid).join("\n")
    );

    // 冲突规则
    await writeFileWithSizeCheck(
      `${assets}/conflictsBlacklist.txt`,
      optimizedResult.excluded.blacklist.conflicts
        .map((obj) => JSON.stringify(obj))
        .join("\n"),
      50
    );
    await writeFileWithSizeCheck(
      `${assets}/conflictsWhitelist.txt`,
      optimizedResult.excluded.whitelist.conflicts
        .map((obj) => JSON.stringify(obj))
        .join("\n"),
      50
    );

    // 重复规则
    await writeFileWithSizeCheck(
      `${assets}/duplicatesBlacklist.txt`,
      optimizedResult.excluded.blacklist.duplicates
        .map((obj) => JSON.stringify(obj))
        .join("\n"),
      50
    );

    await writeFileWithSizeCheck(
      `${assets}/duplicatesWhitelist.txt`,
      optimizedResult.excluded.whitelist.duplicates
        .map((obj) => JSON.stringify(obj))
        .join("\n"),
      50
    );

    // 无效规则
    await writeFileWithSizeCheck(
      `${assets}/invalidBlacklist.txt`,
      optimizedResult.excluded.blacklist.invalid.join("\n"),
      50
    );

    await writeFileWithSizeCheck(
      `${assets}/invalidWhitelist.txt`,
      optimizedResult.excluded.whitelist.invalid.join("\n"),
      50
    );

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
