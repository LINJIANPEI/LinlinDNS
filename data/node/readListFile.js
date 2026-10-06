const { readFile } = require("./common_func");

/**
 * 读取纯文本列表文件
 * - 忽略空行
 * - 忽略以 # 开头的注释行
 * - 支持行尾注释（URL # 备注），可选
 * @param {string} filePath 文件路径
 * @returns {string[]} 有效条目数组
 */
const readListFile = async (filePath, title) => {
  console.log(`开始读取${title}规则源`);
  try {
    const con = readFile(filePath)
      .split(/\r?\n/)
      .map((line) => line.split("#")[0].trim()) // 支持行尾注释
      .filter((line) => line && !line.startsWith("#"));
    console.log(`读取${title}规则源完成，共${con.length}个规则源`);
    return con;
  } catch (error) {
    throw new Error(`读取${title}规则源失败: ${error.message}`);
  }
};

module.exports = {
  readListFile,
};
