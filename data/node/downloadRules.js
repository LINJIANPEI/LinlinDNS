const fs = require("fs");
const axios = require("axios");
const iconv = require("iconv-lite");
const { promisify } = require("util");
const writeFile = promisify(fs.writeFile);

const downloadFile = async (url, directory) => {
  try {
    const response = await axios.get(url, {
      responseType: "arraybuffer",
      timeout: 60000,
    });
    const decoded = iconv.decode(response.data, "utf8");
    await writeFile(directory, decoded);
    console.log(`下载规则文件成功: ${url}`);
  } catch (error) {
    console.log(`下载规则文件失败:${url}${error}`);
    // throw `下载规则文件失败:${url}${error}`;
  }
};

//规则下载
const downloadRules = async (rules, allow, directory) => {
  console.log("开始下载规则");
  try {
    const downloadPromises = rules.map((url, index) =>
      downloadFile(url, `${directory}/rules${index}.txt`)
    );
    const allowPromises = allow.map((url, index) =>
      downloadFile(url, `${directory}/allow${index}.txt`)
    );
    await Promise.all([...downloadPromises, ...allowPromises]);
    console.log("规则下载完成");
  } catch (error) {
    console.log(`规则下载失败:${error}`);
    // throw `规则下载失败:${error}`;
  }
};

module.exports = {
  downloadRules,
};
