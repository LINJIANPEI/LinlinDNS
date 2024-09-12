const fs = require('fs');
const { promisify } = require('util');
const path = require('path');
const readDir = promisify(fs.readdir)
const readFile = promisify(fs.readFile)
const writeFile = promisify(fs.writeFile)

// 规则转换
const transformations = async (directory) => {
    console.log('开始规则转换');

    try {
        directory = path.join(__dirname, directory)
        // 读取列表文件名
        const files = await readDir(directory);
        // 读取所有文件内容
        const allData = await Promise.all(files.map(file => readFile(`${directory}/${file}`, 'utf8')));
        // 处理文件规则
        let allDatas = allData
            .join('\n')
            .split('\n')
            .filter(line => line.trim() !== '')
            .filter((line) => /^\/[a-z]([a-z]|\.)*\.$/.test(line))
            .join('\n')
        // 写入文件
        await writeFile(`${directory}/4.txt`, allDatas);

        console.log('规则转换成功');
    } catch (error) {
        throw `规则转换失败:${error}`
    }

};
module.exports = {
    transformations
};