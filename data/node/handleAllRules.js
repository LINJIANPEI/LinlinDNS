const fs = require("fs");
const { promisify } = require("util");
const writeFile = promisify(fs.writeFile);
const readFile = promisify(fs.readFile);
const handleAllRules = async (...fileList) => {
  for (let i = 0; i < fileList.length; i++) {
    const fileLists = path.join(__dirname, fileList[i]);
    const content = await readFile(`${fileLists}`, "utf8");
    const contentArray = content.split("\n");
    contentArray.filter((line) => !/^!|^#[^#,^@,^%,^\$]|^\[.*\]$/.test(line));
    contentArray = [...new Set(contentArray)];
    const contentString = contentArray.join("\n");
    await writeFile(`${fileLists}`, contentString, "utf8");
  }
};
module.exports = {
  handleAllRules,
};
