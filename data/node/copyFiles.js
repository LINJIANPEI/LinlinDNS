const fs = require('fs');
const { promisify } = require('util');
const copyFile = promisify(fs.copyFile);

// 复制文件
const copyFiles = async (oldDirectory, newDirectory) => {
    console.log('开始复制文件');
    try {
        await copyFile(oldDirectory, newDirectory);
        console.log('复制文件成功');
    } catch (error) {
        throw `复制文件失败:${error}`
    }
}

module.exports = {
    copyFiles
};