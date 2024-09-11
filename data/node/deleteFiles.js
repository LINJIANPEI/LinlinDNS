const fs = require('fs');
const { promisify } = require('util');
const deleteFile = promisify(fs.unlink);

// 删除文件
const deleteFiles = async (directory) => {
    console.log('开始删除文件');
    try {
        await deleteFile(directory);
        console.log('删除文件成功');
    } catch (error) {
        throw `删除文件失败:${error}`
    }
}

module.exports = {
    deleteFiles
};