const path = require('path');
const fs = require('fs');
const fss = fs.promises
// 规则去重
const rule = async () => {
    console.log("开始规则去重");
    try {
        // 读取当前目录下的所有文件
        const files = await fss.readdir('./').then(files => files.filter(file => file.endsWith('.txt')))
        for (let index = 0; index < files.length; index++) {
            const file = files[index]
            // 读取文件内容
            const data = await fss.readFile(file, 'utf8')
            // 将文件内容按行分割，‌去重，‌排序
            const lines = [...new Set(data.split('\n'))]

            const linesdata = lines
                .sort()
                .filter(line => line.trim() !== "")
                .map(line => line.trim())
                .filter(line => !/(((^#)([^#]|$))|^#{4,}).*$/.test(line))
                .join('\n')
            await fss.writeFile(file, linesdata, 'utf8')
        }

        console.log("规则去重成功");
    } catch (error) {
        console.error('规则去重失败');
    }
}
module.exports = {
    rule
};