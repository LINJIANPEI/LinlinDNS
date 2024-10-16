const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const mkdir = promisify(fs.mkdir);

// 创建临时文件夹
const createDir = async (directory) => {
    console.log('开始创建临时文件夹');
    try {
        directory = path.join(__dirname, directory)
        await mkdir(directory, { recursive: true });
        console.log('创建临时文件夹成功');
    } catch (error) {
        throw `创建临时文件夹失败:${error}`
    }
}


module.exports = {
    createDir
};