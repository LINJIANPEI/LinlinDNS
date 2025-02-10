const moment = require("moment-timezone");
const { readFile, writeFile } = require("./common_func");

const extractCount = async (filename) => {
  console.log(`开始统计${filename}行数`);
  try {
    const content = await readFile(filename);
    const match = content.split("\n").length - 7;
    console.log(`统计${filename}行数成功`);
    return match ? match : "0";
  } catch (error) {
    throw `统计${filename}行数失败:${error}`;
  }
};

//更新md文件
const cleanReadme = async () => {
  console.log("开始更新md文件");

  try {
    // const numRules = await extractCount("rules.txt");
    const numDns = await extractCount("dns.txt");
    // const numAllow = await extractCount("allow.txt");
    const numdnsAllow = await extractCount("dnsallow.txt");
    const numDnsConfiguration = await extractCount("DnsConfiguration.txt");
    // 获取当前时间并转换为北京时间
    const beijingTime = moment()
      .tz("Asia/Shanghai")
      .format("YYYY-MM-DD HH:mm:ss");
    let readmeContent = await readFile("README.md");
    const replacements = [
      [/^更新时间.*/, `更新时间: ${beijingTime} （北京时间）`],
      // [/^拦截规则数量.*/, `拦截规则数量: ${numRules}`],
      [/^DNS拦截规则数量.*/, `DNS拦截规则数量: ${numDns}`],
      [/^DNS白名单规则数量.*/, `DNS白名单规则数量: ${numdnsAllow}`],
      // [/^白名单规则数量.*/, `白名单规则数量: ${numAllow}`],
      [/^DNS配置数量.*/, `DNS配置数量: ${numDnsConfiguration}`],
    ];
    readmeContentData = readmeContent
      .split("\n")
      .map((line) => {
        for (const [regex, replacement] of replacements) {
          if (regex.test(line)) return replacement; // 匹配成功直接返回
        }
        return line; // 未匹配则保持原样
      })
      .join("\n");

    await writeFile("README.md", readmeContentData);
    console.log("更新md文件成功");
  } catch (error) {
    throw new Error(`更新md文件失败:${error.message}`);
  }
};
module.exports = {
  cleanReadme,
};
