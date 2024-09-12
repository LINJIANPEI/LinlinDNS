const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const readFile = promisify(fs.readFile)
const writeFile = promisify(fs.writeFile)
//过滤DNS
const filterDns = async (directory) => {
    console.log('开始过滤DNS');

    try {
        // 读取文件
        const data = await readFile(`${directory}/rules.txt`, 'utf8');
        // 处理数据
        const lines = data.split('\n');
        const filteredLines = lines
            .filter(line => line.trim().length >= 2 && line.trim().startsWith('||') && line.trim().endsWith('^'))
            .join('\n') + '\n'
        // 写入文件
        await writeFile(`${directory}/dns.txt`, filteredLines, 'utf8');

        console.log('过滤DNS成功');
    } catch (error) {
        throw `过滤DNS失败:${error}`
    }
}
module.exports = {
    filterDns
};