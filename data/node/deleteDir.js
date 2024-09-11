const fs = require('fs');
const { promisify } = require('util');
const mkdir = promisify(fs.rm);

// 删除临时文件夹
const deleteDir = async (directory) => {
    console.log('开始删除临时文件夹');
    try {
        await mkdir(directory, { recursive: true, force: true });
        console.log('删除临时文件夹成功');
    } catch (error) {
        throw `删除临时文件夹失败:${error}`
    }
}

module.exports = {
    deleteDir
};