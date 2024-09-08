const fs = require('fs');
const fss = fs.promises
const moment = require('moment');

const extractCount = async (filename) => {
    const content = await fss.readFile(filename, 'utf8');
    const match = content.match(/^! Total count: (\d+)/);
    return match ? match[1] : '0';
}

const cleanReadme = async () => {
    // Get counts from files
    const numRules = await extractCount('rules.txt');
    const numDns = await extractCount('dns.txt');
    const numAllow = await extractCount('allow.txt');
    const numDnsConfiguration = await extractCount('DnsConfiguration.txt');


    // Get the current time in UTC-8
    const time = moment().format('YYYY-MM-DD HH:mm:ss');

    // Read README.md
    let readmeContent = await fss.readFile('README.md', 'utf-8');

    // Update README.md
    readmeContent = readmeContent
        .replace(/^更新时间.*/gm, `更新时间: ${time} （北京时间）`)
        .replace(/^拦截规则数量.*/gm, `拦截规则数量: ${numRules}`)
        .replace(/^DNS拦截规则数量.*/gm, `DNS拦截规则数量: ${numDns}`)
        .replace(/^白名单规则数量.*/gm, `白名单规则数量: ${numAllow}`)
        .replace(/^DNS配置数量.*/gm, `DNS配置数量: ${numDnsConfiguration}`);

    // Write the updated content back to README.md
    await fss.writeFile('README.md', readmeContent);

    console.log('README.md has been updated.');
}
module.exports = {
    cleanReadme
};
