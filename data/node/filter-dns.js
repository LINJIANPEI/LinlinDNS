const fs = require('fs');
const path = require('path');
const fss = fs.promises

const filterDns = async () => {
    try {
        // 读取文件
        const data = await fss.readFile(path.resolve('./', 'rules.txt'), 'utf8');
        // 处理数据
        const lines = data.split('\n');
        const filteredLines = lines.filter(line => {
            const trimmedLine = line.trim();
            return trimmedLine.length >= 2 && trimmedLine.startsWith('||') && trimmedLine.endsWith('^');
        });
        // 写入文件
        await fss.writeFile(path.resolve('./', 'dns.txt'), filteredLines.join('\n') + '\n', 'utf8');
    } catch (error) {
        console.error('Error filterDns:', error.message);
    }
}
module.exports = {
    filterDns
};