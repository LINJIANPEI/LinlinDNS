const fs = require('fs');
const fss = fs.promises

const rule = async () => {

    try {
        console.log("规则去重中");
        // 读取当前目录下的所有文件
        const files = await fss.readdir('./').then(files => files.filter(file => file.endsWith('.txt')))
        files.forEach(async (file) => {
            // 读取文件内容
            const data = await fss.readFile(file, 'utf8')
            // 将文件内容按行分割，‌去重，‌排序
            const lines = [...new Set(data.split('\n'))].sort();

            // 将处理后的内容写回新文件，‌然后替换原文件
            // await fss.writeFile('test' + file, lines.join('\n'), 'utf8')
            // 删除原文件
            fss.unlink(file)
            fss.writeFile(file, lines.join('\n'), 'utf8')

            // await fss.rename('test' + file, file);
        });
        console.log("规则去重完成");
    } catch (error) {
        console.error('Error rule:', error.message);
    }
}
module.exports = {
    rule
};