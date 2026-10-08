const { readFile, readDir } = require("./common_func");

// 合并规则
const mergeWhitelist = async (directory) => {
  console.log("开始合并白名单规则");
  try {
    // 读取列表文件名
    const fileList = await readDir(directory);
    // 过滤出以"allow"开头且以".txt"结尾的文件
    const allowFiles = fileList
      .filter((file) => file.startsWith("allow") && file.endsWith(".txt"))
      .sort(); // 排序，保证每次顺序一致

    // 如果没有找到符合条件的文件，提前返回空数组
    if (allowFiles.length === 0) {
      console.log("没有找到符合条件的白名单文件");
      return [];
    }

    const allFileDatas = [];

    // 逐个文件读取、切分、push，避免一次性 join 出超大字符串
    for (const file of allowFiles) {
      const content = await readFile(`${directory}/${file}`);
      if (!content) continue;

      const lines = content.split("\n");
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed) allFileDatas.push(trimmed);
      }
    }

    console.log(
      `合并白名单规则完成，共处理了${allowFiles.length}个文件，合并规则${allFileDatas.length}条`,
    );

    return allFileDatas;
  } catch (error) {
    throw new Error(`合并白名单规则失败: ${error.message}`);
  }
};

module.exports = {
  mergeWhitelist,
};
