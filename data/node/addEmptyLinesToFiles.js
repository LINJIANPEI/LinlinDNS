const fs = require('fs');
const { promisify } = require('util');
const readDir = promisify(fs.readdir)
const stat = promisify(fs.stat)
const appendFile = promisify(fs.appendFile)

// 添加空格
const addEmptyLinesToFiles = async (directory) => {
    console.log('开始添加空格');
    try {
        // 读取列表文件名
        const files = await readDir(directory);
        // 读取所有文件内容并添加空格
        await Promise.all(files.map(async (file) => {
            // 判断是不是文件
            if ((await stat(`${directory}/${file}`)).isFile()) {
                // 追加内容
                await appendFile(`${directory}/${file}`, '\n');
            }
        }));
        console.log('添加空格成功');
    } catch (error) {
        throw `添加空格失败:${error}`
    }
}

module.exports = {
    addEmptyLinesToFiles
};