const fs = require("fs");
const { promisify } = require("util");
const path = require("path");
const deleteFile = promisify(fs.unlink);

const getFilenameWithoutExtension = (filepath) => {
  const filenameWithExtension = path.basename(filepath);
  return path.parse(filenameWithExtension).name;
};

async function fileExistsAsync(filePath) {
  try {
    await fs.access(filePath, fs.constants.F_OK);
    return true;
  } catch (error) {
    return false;
  }
}

// 删除文件
const deleteFiles = async (...directory) => {
  console.log("开始删除文件");
  try {
    for (let i = 0; i < directory.length; i++) {
      if (await fileExistsAsync(directory[i])) {
        await deleteFile();
        const name = await getFilenameWithoutExtension(directory[i]);
        console.log(`删除文件${name}成功`);
      }
    }
  } catch (error) {
    throw `删除文件失败:${error}`;
  }
};

module.exports = {
  deleteFiles,
};
