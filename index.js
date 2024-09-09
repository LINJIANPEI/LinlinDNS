const fs = require('fs');
const axios = require('axios');
const iconv = require('iconv-lite');
const path = require('path');
const { promisify } = require('util');
const { filterDns } = require('./data/node/filter-dns'); // 引用 filter-dns.js 模块
const { rule } = require('./data/node/rule'); // rule.js 模块
const { title } = require('./data/node/title'); // title.js 模块
const { cleanReadme } = require('./data/node/clean-readme'); // clean-readme.js 模块
const fss = fs.promises
const _ = require('lodash');

//黑名单规则
const rules = [
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/black.txt",//5460
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",//大萌主
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",//DD
    "https://raw.gitmirror.com/Cats-Team/dns-filter/main/abp.txt",//AdRules DNS Filter
    "https://raw.hellogithub.com/hosts",//GitHub加速
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt",//测试hosts
    "https://raw.githubusercontent.com/loveqqzj/AdGuard/master/Mobile.txt",//loveqqzj
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Blacklist.txt",//mphin
    "https://gitee.com/zjqz/ad-guard-home-dns/raw/master/black-list",//周木木
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/black.txt",//liwenjie119
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/T%E7%99%BD%E5%90%8D%E5%8D%95.txt",//T白
    "https://www.coolapk.com/link?url=https%3A%2F%2Fraw.gitmirror.com%2FTTDNS%2FCat%2Fmain%2FTT%25E6%258B%2592%25E7%25BB%259D%25E5%2588%2597%25E8%25A1%25A8%25E6%25B8%2585%25E5%258D%2595%2520(%25E6%259B%25B4%25E6%2596%25B0%25E4%25B8%25AD).txt",//TTDNS
    "https://mirror.ghproxy.com/raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt",//HyperADRules
    "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/all.txt",//AdGuardHomeRules
    "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/manhua-max.txt",//AdGuardHomeRules
    "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/skyrules.txt",//AdGuardHomeRules
    "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",//FCM Hosts
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/minority-mv.txt",//乘风视频
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",//乘风视频
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt",//乘风视频
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",//秋风规则
    "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/blacklist.txt",//Zisbusy
    "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/easylist.txt",//Zisbusy
    "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/filter.txt",//Zisbusy
    "https://raw.githubusercontent.com/sccheng460/adguard/main/blacklist.txt",//sccheng460
]
//白名单规则
const allow = [
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",//白名单
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",//
    "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
    "https://file-git.trli.club/file-hosts/allow/Domains",//冷漠
    "https://hub.gitmirror.com/https://raw.githubusercontent.com/user001235/112/main/white.txt",//浅笑
    "https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/ok.txt",//AdGuardHomeRules
    "https://mirror.ghproxy.com/raw.githubusercontent.com/8680/GOODBYEADS/master/allow.txt",//8680
    "https://gitee.com/zjqz/ad-guard-home-dns/raw/master/white-list",//周木木
    "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",//liwenjie119
    "https://raw.githubusercontent.com/qq5460168/dangchu/main/T%E7%99%BD%E5%90%8D%E5%8D%95.txt",//T白名单
    "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/whitelist.txt",//Zisbusy
    "https://raw.githubusercontent.com/sccheng460/adguard/main/whitelist.txt",//sccheng460
]

// 创建临时文件夹
const createDir = async (directory) => {
    console.log('开始创建临时文件夹');
    const mkdir = promisify(fs.mkdir);
    try {
        await mkdir(directory, { recursive: true });
        console.log('创建临时文件夹成功');
    } catch (error) {
        console.error('创建临时文件夹失败');
    }
}
// 删除临时文件夹
const deleteDir = async (directory) => {
    console.log('开始删除临时文件夹');
    const mkdir = promisify(fs.rm);
    try {
        await mkdir(directory, { recursive: true, force: true });
        console.log('删除临时文件夹成功');
    } catch (error) {
        console.error('删除临时文件夹失败');
    }
}
// 复制文件
const CopyFiles = async (oldDirectory, newDirectory) => {
    console.log('开始复制文件');
    try {
        const copyFile = promisify(fs.copyFile);
        await copyFile(oldDirectory, newDirectory);
        console.log('复制文件成功');
    } catch (error) {
        console.error('复制文件失败');
    }
}

//规则下载
const downloadRules = async (rules, allow, directory) => {
    const downloadFile = async (url, directory) => {
        const writeFile = promisify(fs.writeFile);
        try {
            const response = await axios.get(url, { responseType: 'arraybuffer', timeout: 60000 });
            const decoded = iconv.decode(response.data, 'utf-8');
            await writeFile(directory, decoded);
        } catch (error) {
            console.error(`下载规则文件失败: ${url}`);
        }
    }
    console.log('开始下载规则');
    try {
        const downloadPromises = rules.map((url, index) => downloadFile(url, `${directory}/rules${index}.txt`));
        const allowPromises = allow.map((url, index) => downloadFile(url, `${directory}/allow${index}.txt`));
        await Promise.all([...downloadPromises, ...allowPromises]);
        console.log('规则下载完成');
    } catch (error) {
        console.error('规则下载失败');
    }
}

// 添加空格
const addEmptyLinesToFiles = async (directory) => {
    console.log('开始添加空格');
    try {
        let files = await fss.readdir(directory);
        await Promise.all(files.map(async (file) => {
            const filePath = path.join(directory, file);
            if ((await fss.stat(filePath)).isFile()) {
                await fss.appendFile(filePath, '\n');
            }
        }));
        console.log('添加空格成功');
    } catch (error) {
        console.error('添加空格失败');
    }
}


// 规则转换
const transformations = async (oldDirectory, newDirectory) => {
    console.log('开始规则转换');

    try {

        const files = await fss.readdir(oldDirectory);
        const allData = await Promise.all(files.map(file => fss.readFile(`${oldDirectory}/${file}`, 'utf-8')));
        let allDatas = allData
            .join('\n')
            .split('\n')
            .filter(line => line.trim() !== '')
            .filter((line) => {
                const regex = /^\/[a-z]([a-z]|\.)*\.$/;
                return regex.test(line)
            })
            .join('\n')
        await fss.writeFile(`${oldDirectory}/4.txt`, allDatas);

        console.log('规则转换成功');
    } catch (error) {
        console.log('规则转换失败');
    }

};


// 开始合并规则
const processFiles = async (oldDirectory, newDirectory) => {
    console.log('开始合并规则');

    try {

        const files = await fss.readdir(oldDirectory)
        const ruleFiles = files.filter(file => file.startsWith('rules') && file.endsWith('.txt'));
        const allruleData = await Promise.all(ruleFiles.map(file => fss.readFile(`${oldDirectory}/${file}`, 'utf-8')));

        let allruleDatas = allruleData
            .join('\n')
            .split('\n')
            .filter(line => {
                const regex = /^((\!)|(\[)).*/;
                return !regex.test(line)
            })
            .filter(line => line.trim() !== '')
        allruleDatas = [...new Set(allruleDatas)].join('\n')

        await fss.writeFile(`${oldDirectory}/tmp-rules.txt`, allruleDatas, 'utf8')

        const filess = await fss.readdir(oldDirectory)
        const allallowData = await Promise.all(filess.map(file => fss.readFile(`${oldDirectory}/${file}`, 'utf-8')));
        let allallowDatas = allallowData
            .join('\n')
            .split('\n')
            .filter(line => line.startsWith('@'))
            .filter(line => line.trim() !== '')
        allallowDatas = [...new Set(allallowDatas)].join('\n')
        await fss.writeFile(`${oldDirectory}/tmp-allow.txt`, allallowDatas, 'utf8')

        await CopyFiles(`${oldDirectory}/tmp-rules.txt`, `${newDirectory}/rules.txt`);
        await CopyFiles(`${oldDirectory}/tmp-allow.txt`, `${newDirectory}/allow.txt`);

        console.log('合并规则完成');
    } catch (error) {
        console.error('合并规则失败');
    }
}
(async function main() {
    const newDirectorys = './tmp'
    await createDir(newDirectorys)
    await CopyFiles('./data/rules/adblock.txt', `${newDirectorys}/rules01.txt`);
    await CopyFiles('./data/rules/whitelist.txt', `${newDirectorys}/allow01.txt`);
    await downloadRules(rules, allow, newDirectorys)
    await addEmptyLinesToFiles(newDirectorys);
    await transformations(newDirectorys, newDirectorys);
    await processFiles(newDirectorys, './')
    await filterDns()
    await rule()
    await cleanReadme()
    await title()
    deleteDir(newDirectorys)
    console.log('更新完成');
})();





