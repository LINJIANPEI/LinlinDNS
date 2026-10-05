const path = require("path");
const moment = require("moment-timezone");
const { readFile, writeFile, readDir } = require("./common_func");

const getFilenameWithoutExtension = (filepath) => {
  const filenameWithExtension = path.basename(filepath);
  return path.parse(filenameWithExtension).name;
};

// 写入头部信息
const title = async () => {
  console.log("开始写入头部信息");
  try {
    // 获取当前时间并转换为北京时间
    const beijingTime = moment()
      .tz("Asia/Shanghai")
      .format("YYYY-MM-DD HH:mm:ss");

    const files = await readDir("./");
    const fileList = files.filter((file) => file.endsWith(".txt"));
    for (let i = 0; i < fileList.length; i++) {
      const content = await readFile(`${fileList[i]}`);
      const result = getFilenameWithoutExtension(fileList[i]);
      const lineCount = content.split("\n").length;

      const newContent = `[个人合并 2.0]
! Title: 林林${result}
! Homepage: https://github.com/LINJIANPEI/DnsRules/
! Expires: 1 Hours
! Version: ${beijingTime}（北京时间）
! Description: 适用于AdGuard的去广告规则，合并优质上游规则并去重整理排列
! Total count: ${lineCount}
${content}`;

      await writeFile(fileList[i], newContent);
    }
    console.log("写入头部信息成功");
  } catch (error) {
    throw new Error(`写入头部信息失败:${error.message}`);
  }
};
module.exports = {
  title,
};
