const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const copyFile = promisify(fs.copyFile);

async function fileExistsAsync(filePath) {
    try {
        await fs.access(filePath, fs.constants.F_OK);
        return true;
    } catch (error) {
        return false;
    }
}

// 复制文件
const copyFiles = async (oldDirectory, newDirectory) => {
    console.log('开始复制文件');
    try {
        oldDirectory = path.join(__dirname, oldDirectory)
        newDirectory = path.join(__dirname, newDirectory)
        if (await fileExistsAsync(oldDirectory)) {
            await copyFile(oldDirectory, newDirectory);
            console.log('复制文件成功');
        }
    } catch (error) {
        throw `复制文件失败:${error}`
    }
}

module.exports = {
    copyFiles
};