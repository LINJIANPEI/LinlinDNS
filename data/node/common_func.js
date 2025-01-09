const filters = (arr) => {
  const arrs = [...new Set(arr)]
    .map((line) => line.trim()) // 修剪每行的空白
    .filter((line) => line !== "") // 过滤掉空行
    .sort();
  return arrs;
};

module.exports = { filters };
