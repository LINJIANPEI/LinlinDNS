// 过滤正则规则
const regexFilter = async (con) => {
  console.log("开始过滤正则规则");

  try {
    let conFalse = [];
    const conTrue = con
      .filter((line) => {
        if (
          !/[,#&=,:]/.test(line) &&
          !/^[*,@,\-,_,\.,&,\?]/.test(line) &&
          !/\$[^s]/.test(line) &&
          !/\^([^s])/.test(line)
        ) {
          return line;
        } else {
          conFalse.push(line);
          return null;
        }
      })
      .filter(Boolean); // 移除 null 值;

    console.log(
      `过滤正则规则成功,过滤规则${conTrue.length}条,不匹配${conFalse.length}条`
    );
    return [conTrue, conFalse];
  } catch (fileError) {
    // 捕获并打印单个文件的错误
    console.error(`过滤正则规则时出错: ${fileError.message}`);
    throw new Error(`过滤正则规则时出错`);
  }
};

module.exports = { regexFilter };
