const fs = require("fs");
const { promisify } = require("util");
const path = require("path");
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);

// 规则转换
const transformations = async (...fileList) => {
  console.log("开始规则转换");
  try {
    for (let i = 0; i < fileList.length; i++) {
      let content = await readFile(`${fileList[i]}`, "utf8");
      const contentArray = content.split("\n");
      contentArrays = contentArray
        .filter((line) => line.trim() !== "")
        .filter((line) => /^\/[a-z]([a-z]|\.)*\.$/.test(line));
      const contentString = contentArray.join("\n");
      await writeFile(`${fileList[i]}`, contentString);
    }
    console.log("规则转换成功");
  } catch (error) {
    throw `规则转换失败:${error}`;
  }
};
module.exports = {
  transformations,
};
