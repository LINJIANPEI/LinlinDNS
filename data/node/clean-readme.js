const fs = require('fs');
const fss = fs.promises
const moment = require('moment');

//更新md文件
const cleanReadme = async () => {
    console.log('开始更新md文件');

    const extractCount = async (filename) => {
        const content = await fss.readFile(filename, 'utf8');
        const match = content.split('\n').length - 7
        return match ? match : '0';
    }
    try {

        const numRules = await extractCount('rules.txt');
        const numDns = await extractCount('dns.txt');
        const numAllow = await extractCount('allow.txt');
        const numDnsConfiguration = await extractCount('DnsConfiguration.txt');
        const time = moment().format('YYYY-MM-DD HH:mm:ss');
        let readmeContent = await fss.readFile('README.md', 'utf8');
        readmeContentData = readmeContent
            .split('\n')
            .map((line) => {
                return line
                    .replace(/^更新时间.*/, `更新时间: ${time} （北京时间）`)
                    .replace(/^拦截规则数量.*/, `拦截规则数量: ${numRules}`)
                    .replace(/^DNS拦截规则数量.*/, `DNS拦截规则数量: ${numDns}`)
                    .replace(/^白名单规则数量.*/, `白名单规则数量: ${numAllow}`)
                    .replace(/^DNS配置数量.*/, `DNS配置数量: ${numDnsConfiguration}`);
            })
            .join('\n')

        await fss.writeFile('README.md', readmeContentData);
        console.log('更新md文件成功');
    } catch (error) {
        console.error('更新md文件失败');
    }

}
module.exports = {
    cleanReadme
};
