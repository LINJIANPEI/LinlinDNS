const axios = require("axios");
const iconv = require("iconv-lite");
const { writeFile } = require("./common_func");

/**
 * 下载文件。
 * @param {string} url - 下载链接。
 * @param {string} directory - 下载保存的文件路径。
 *
 */
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
    console.error(`下载文件失败: ${url} - ${error.message}`);
  }
};

/**
 * 规则下载。
 * @param {Array} rules - 下载链接。
 * @param {Array} allow - 下载链接。
 * @param {string} directory - 下载保存的文件路径。
 *
 */
const downloadRules = async (rules, allow, directory) => {
  console.log("开始下载规则");
  const downloadTasks = [
    ...rules.map((url, index) =>
      downloadFile(url, `${directory}/rules${index + 1}.txt`)
    ),
    ...allow.map((url, index) =>
      downloadFile(url, `${directory}/allow${index + 1}.txt`)
    ),
  ];
  try {
    await Promise.all(downloadTasks);
    console.log("规则下载完成");
  } catch (error) {
    console.error(`规则下载过程中发生错误: ${error.message}`);
  }
};

module.exports = {
  downloadRules,
};
