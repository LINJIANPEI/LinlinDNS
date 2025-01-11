// 处理所有规则的函数
const handleAllRules = async (...fileList) => {
  console.log("开始处理所有规则");
  let confilter = [];
  for (const [index, filePath] of fileList.entries()) {
    try {
      let tmpAllow = [];
      let tmpRules = [];
      let processedContentArray = [];

      processedContentArray = filePath.filter((line) => {
        if (/^\|\|.*/.test(line) || /^\/.*\/$/.test(line)) {
          tmpAllow.push(line);
        } else if (/^@@.*/.test(line)) {
          tmpRules.push(line);
        } else {
          return line;
        }
      });

      confilter.push([tmpRules, tmpAllow, processedContentArray]);

      console.log(`文件 ${index} 处理成功`);
    } catch (fileError) {
      // 捕获并打印单个文件的错误
      console.error(`处理文件 ${index} 时出错: ${fileError.message}`);
      throw new Error(`处理文件 ${index} 时出错`);
    }
  }
  console.log("所有文件的规则处理完成");
  return confilter;
};

module.exports = { handleAllRules };
