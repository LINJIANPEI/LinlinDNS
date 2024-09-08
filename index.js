const fs = require('fs');
const axios = require('axios');
const iconv = require('iconv-lite');
const path = require('path');
const os = require('os');
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
const createDir = async (directory, filesName) => {
    const mkdir = promisify(fs.mkdir);
    try {
        // Get the OS temporary directory
        const tempDir = path.join(directory, filesName);

        // Create the temporary directory
        await mkdir(tempDir, { recursive: true });
        console.log('创建临时文件夹');

    } catch (error) {
        console.error('错误:', error);
    }
}

// 复制文件
const CopyFiles = async (oldDirectory, newDirectory) => {
    try {
        const copyFile = promisify(fs.copyFile);
        await copyFile(oldDirectory, newDirectory);

    } catch (error) {
        console.error('错误:', error);
    }
}

// 切换工作目类
const tempDir = (directory) => {
    process.chdir(directory);
    console.log('当前工作目录:', process.cwd());
}


//规则下载
const downloadFile = async (url, outputPath) => {
    const writeFile = promisify(fs.writeFile);
    try {
        const response = await axios.get(url, { responseType: 'arraybuffer', timeout: 60000 });
        const decoded = iconv.decode(response.data, 'utf-8');
        await writeFile(outputPath, decoded);
        console.error(`下载规则文件成功: ${url}`);
    } catch (error) {
        console.error(`下载规则文件失败: ${url}`);
    }
}
const downloadRules = async (rules, allow, directory) => {
    try {
        const downloadPromises = rules.map((url, index) => downloadFile(url, path.join(directory, `rules${index}.txt`)));
        const allowPromises = allow.map((url, index) => downloadFile(url, path.join(directory, `allow${index}.txt`)));
        await Promise.all([...downloadPromises, ...allowPromises]);
        console.log('规则下载完成');
    } catch (error) {
        console.error('错误:', error);
    }
}

// 添加空格
const addEmptyLinesToFiles = async (directory) => {
    try {
        let files = await fss.readdir(directory, async (err, filess) => {
            if (err) throw err;
        });
        await Promise.all(files.map(async (file) => {
            const filePath = path.join(directory, file);
            if ((await fss.stat(filePath)).isFile()) {
                await fss.appendFile(filePath, '\n');
            }
        }));
        console.log('Empty lines added to all files');
    } catch (error) {
        console.error('Error adding empty lines:', error.message);
    }
}

// 处理规则中
const processRules = async (oldDirectory, newDirectory) => {
    try {
        const baseSrcFilePath = path.join(newDirectory, 'base-src-hosts.txt');

        const files = await fss.readdir(oldDirectory, async (err, filess) => {
            if (err) throw err;
        });
        const fileContents = await Promise.all(files.map(file => fss.readFile(path.join(oldDirectory, file), 'utf-8')));
        const allData = fileContents.join('\n');

        const processedData = allData
            .split('\n')
            .filter(line => line.trim() !== '' && !/^#/.test(line))
            .filter(line => !/^[0-9f\.:]+\s+(ip6\-)|(localhost|local|loopback)$/.test(line))
            .filter(line => !/local.*\.local.*$/.test(line))
            .map(line => line.replace(/127\.0\.0\.1/g, '0.0.0.0'))
            .map(line => line.replace(/::/g, '0.0.0.0'))
            .filter(line => /0.0.0.0/.test(line))
            .filter(line => !/\.0\.0\.0\.0/.test(line))
            .sort()
            .filter((item, pos, self) => self.indexOf(item) === pos)  // Remove duplicates
            .join('\n');

        await fss.writeFile(baseSrcFilePath, processedData);

        console.log('Rules processed and saved to base-src-hosts.txt');
    } catch (error) {
        console.error('Error processing rules:', error.message);
    }
}
const processFile = async (inputFilePath, outputFilePath, transformationsList) => {
    try {
        // Read the file content
        let data = await fss.readFile(inputFilePath, 'utf-8');

        // Apply transformations
        for (const transform of transformationsList) {
            data = transform(data);
        }

        // Write the processed data to the output file
        await fss.writeFile(outputFilePath, data);
        console.log(`Processed data saved to ${outputFilePath}`);
    } catch (error) {
        console.error('Error processing file:', error.message);
    }
};

const transformations = async (directory) => {
    // Define transformations for each step
    const transformationsBaseSrc = [
        data => data.split('\n').filter(line => !/#|\$|@|!|\/|\\|\*/.test(line)).join('\n'),
        data => data.split('\n').filter(line => !/^((#.*)|(\s*))$/.test(line)).join('\n'),
        data => data.split('\n').filter(line => !/^[0-9f\.:]+\s+(ip6\-)|(localhost|loopback)$/.test(line)).join('\n'),
        data => data.replace(/127\.0\.0\.1\s*/g, '').replace(/0\.0\.0\.0\s*/g, ''),
        data => data.split('\n').map(line => `||${line}^`).filter(line => line.trim() !== '').join('\n'),
        data => data.split('\n').filter(line => !/^#/.test(line)).join('\n'),
        data => [...new Set(data.split('\n'))].join('\n'), // Unique lines
        data => data.split('\n').filter(line => /^\|\|\S+\^$/.test(line)).join('\n') // Filter valid ABP rules
    ];

    // Process base-src-hosts.txt
    await processFile(
        path.join(directory, 'base-src-hosts.txt'),
        path.join(directory, 'processed-base-src-hosts.txt'),
        transformationsBaseSrc
    );

    // Transformations for allow domains
    const transformationsAllowDomains = [
        data => data.split('\n').filter(line => line.trim() !== '' && !/^#/.test(line)).map(line => `@@||${line}^`).join('\n'),
        data => [...new Set(data.split('\n'))].join('\n')
    ];

    // Process allow.txt
    await processFile(
        path.join(directory, 'allow.txt'),
        path.join(directory, 'processed-allow.txt'),
        transformationsAllowDomains
    );

    // Transformations for other domains
    const transformationsOtherDomains = [
        data => data.split('\n').filter(line => line.trim() !== '' && !/^#/.test(line)).map(line => `0.0.0.0 ${line}`).join('\n'),
        data => [...new Set(data.split('\n'))].join('\n')
    ];

    // Process other-domains.txt
    await processFile(
        path.join(directory, 'other-domains.txt'),
        path.join(directory, 'processed-other-domains.txt'),
        transformationsOtherDomains
    );

    // Example for processing all text files
    const transformationsAllTxt = [
        data => data.split('\n').filter(line => line.trim() !== '' && !/^#/.test(line)).sort().join('\n'),
        data => data.split('\n').filter(line => /^\/[a-z]([a-z]|\.)*\.$/.test(line)).sort().join('\n')
    ];

    // Process *.txt files
    const txtFiles = await fss.readdir(directory, async (err, filess) => {
        if (err) throw err;
    }).then(files => files.filter(file => file.endsWith('.txt')));
    for (const file of txtFiles) {
        await processFile(
            path.join(directory, file),
            path.join(directory, `processed-${file}`),
            transformationsAllTxt
        );
    }
};

// 开始合并
const processFiles = async (oldDirectory, newDirectory) => {
    try {
        // Read all .txt files in the temp directory
        const files = await fss.readdir(oldDirectory, async (err, filess) => {
            if (err) throw err;
        })
        const txtFiles = files.filter(file => file.endsWith('.txt'));

        // Initialize arrays to hold data
        let allRules = [];
        let allAllow = [];

        // Read all files and collect data
        for (const file of txtFiles) {
            const filePath = path.join(oldDirectory, file);
            const content = await fss.readFile(filePath, 'utf8');
            const lines = content.split('\n').filter(line => line.trim());

            // Process rules
            allRules = allRules.concat(lines.filter(line => !line.startsWith('@')));
            allAllow = allAllow.concat(lines.filter(line => line.startsWith('@')));
        }

        // Process AdGuard rules
        let tmpRules = _.uniq(allRules.filter(line => !/^([!|\[|\]]).*/.test(line)));
        tmpRules = _.uniq(tmpRules.sort((a, b) => a.localeCompare(b)));
        await fss.writeFile(path.join(oldDirectory, 'tmp-rules.txt'), tmpRules.join('\n'));

        // Process allow list
        const ll = _.uniq(allAllow
            .filter(line => /^(@@||).*\^$/.test(line))
            .filter(line => !/(\d{1,3}\.){3}\d{1,3}/.test(line))
            .sort((a, b) => a.localeCompare(b)));
        await fss.writeFile(path.join(oldDirectory, 'll.txt'), ll.join('\n'));

        // Process allow list with '@'
        const tmpAllow = _.uniq(allAllow.filter(line => line.startsWith('@')).sort((a, b) => a.localeCompare(b)));
        await fss.writeFile(path.join(oldDirectory, 'tmp-allow.txt'), tmpAllow.join('\n'));
        // Copy files to final destination
        await fss.writeFile(path.join(newDirectory, 'rules.txt'), tmpRules.join('\n'));
        await fss.writeFile(path.join(newDirectory, 'allow.txt'), tmpAllow.join('\n'));

        console.log('规则处理完成');
    } catch (error) {
        console.error('错误:', error);
    }
}
(async function main() {
    const oldDirectory = './tmp/rulesList';
    const newDirectory = './tmp'
    await createDir('./', "tmp")
    await createDir('./tmp/', "rulesList")
    await CopyFiles('./data/rules/adblock.txt', './tmp/rules01.txt');
    await CopyFiles('./data/rules/whitelist.txt', './tmp/allow01.txt');
    await downloadRules(rules, allow, oldDirectory)
    await addEmptyLinesToFiles(oldDirectory);
    await processRules(oldDirectory, newDirectory);
    await transformations(newDirectory);
    await processFiles(newDirectory, './')
    await filterDns()
    await rule()
    await cleanReadme()
    await title()
    console.log('更新完成');
})();





