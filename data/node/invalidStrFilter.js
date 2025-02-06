// 过滤无效字符
const invalidStrFilter = async (con) => {
  console.log("开始过滤无效字符");

  try {
    let conFalse = [];
    const conTrue = con
      .filter((line) => {
        if (
          !/^!|^#[^#,^@,^%,^\$]|\[\.*\]$/.test(line) &&
          !/(((^#)([^#]|$))|^#{4,}).*$/.test(line) &&
          !/^[\u4e00-\u9fa5]+$/.test(line) &&
          !/^!|^＃|^！|^#[^#,^@,^%,^\$]|^\[.*\]$/.test(line) &&
          (!/^##.*[\u4e00-\u9fa5].*$/.test(line) || /^##.*\[.*\].*$/.test(line))
        ) {
          return line;
        } else {
          conFalse.push(line);
          return null;
        }
      })
      .filter(Boolean); // 移除 null 值;

    console.log(
      `过滤无效字符成功,过滤规则${conTrue.length}条,不匹配${conFalse.length}条`
    );
    return [conTrue, conFalse];
  } catch (fileError) {
    // 捕获并打印单个文件的错误
    console.error(`过滤无效字符时出错: ${fileError.message}`);
    throw new Error(`过滤无效字符时出错`);
  }
};

module.exports = { invalidStrFilter };
