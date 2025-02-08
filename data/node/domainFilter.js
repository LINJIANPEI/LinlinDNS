// 过滤域名规则
const domainFilter = async (con, str) => {
  console.log("开始过滤域名规则");
  try {
    let conFalse = [];
    const conTrue = con
      .map((line) => {
        // const regex = /^([\w,\d,-,\*]+\.)+[\w,\d,-,\*]+(\^$)?$/;
        const regex =
          /^(?:\*\.|[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,6}$|^\*?[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(\.[a-zA-Z]{2,6})?$|^[\w.-]+\.[a-zA-Z]{2,6}$|^\*[\w.-]+\.[a-zA-Z]{2,6}$|^[a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,6}$|^\*?[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(\.[a-zA-Z]{2,6})?$|^(?!.*--)(\*|\w*-*\w*)(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,6}$|^(?!.*--)(\*|\w*(?:-\w*)*\w*)(\.[a-zA-Z0-9-]+)+\.[a-zA-Z]{2,6}$|^[a-zA-Z0-9-]+\.[a-zA-Z]{2,6}$/;

        if (regex.test(line)) {
          return `${str}${line}`;
        } else {
          conFalse.push(line);
          return null;
        }
      })
      .filter(Boolean); // 移除 null 值;

    console.log(
      `过滤域名规则成功,过滤规则${conTrue.length}条不匹配${conFalse.length}条`
    );
    return [conTrue, conFalse];
  } catch (fileError) {
    // 捕获并打印单个文件的错误
    console.error(`过滤域名规则时出错: ${fileError.message}`);
    throw new Error(`过滤域名规则时出错`);
  }
};

module.exports = { domainFilter };
