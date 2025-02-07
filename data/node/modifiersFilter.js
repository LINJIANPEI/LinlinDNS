// 过滤修饰符
const modifiersFilter = async (con) => {
  console.log("开始过滤修饰符");

  try {
    const cons = con.map((line) => {
      return line
        .trim()
        .replace(/^@@\|\||^\|\||^\||^@@|\$important\$|\s#[^#]*$|\^$/, "");
    });

    console.log(`过滤修饰符成功`);
    return cons;
  } catch (fileError) {
    // 捕获并打印单个文件的错误
    console.error(`过滤修饰符时出错: ${fileError.message}`);
    throw new Error(`过滤修饰符时出错`);
  }
};

module.exports = { modifiersFilter };
