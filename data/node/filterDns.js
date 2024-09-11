const fs = require('fs');
const path = require('path');
const fss = fs.promises
//过滤DNS
const filterDns = async () => {
    console.log('开始过滤DNS');

    try {
        // 读取文件
        const data = await fss.readFile(path.resolve('./', 'rules.txt'), 'utf8');
        // 处理数据
        const lines = data.split('\n');
        const filteredLines = lines.filter(line => line.trim().length >= 2 && line.trim().startsWith('||') && line.trim().endsWith('^'));
        // 写入文件
        await fss.writeFile(path.resolve('./', 'dns.txt'), filteredLines.join('\n') + '\n', 'utf8');

        console.log('过滤DNS成功');
    } catch (error) {
        throw `过滤DNS失败:${error}`
    }
}
module.exports = {
    filterDns
};