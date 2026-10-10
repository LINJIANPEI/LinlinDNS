const axios = require("axios");
const iconv = require("iconv-lite");
const { writeFile } = require("./common_func");

const HEADERS = {
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  Accept: "*/*",
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * 下载单个文件，失败自动重试。
 * 返回 true 表示成功，false 表示失败。
 */
const downloadFile = async (url, filePath, retries = 2) => {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      console.log(
        `[开始] ${url} -> ${filePath}${attempt > 0 ? `（重试 ${attempt}）` : ""}`,
      );

      const response = await axios.get(url, {
        responseType: "arraybuffer",
        timeout: 60000,
        headers: HEADERS,
        maxRedirects: 5,
      });

      const buffer = Buffer.from(response.data);
      const decoded = iconv.decode(buffer, "utf8");

      // ★ 内容校验：太小或像 HTML，判定为失败
      if (decoded.length < 100) {
        throw new Error(`内容过短（${decoded.length} 字节）`);
      }
      if (/^\s*<(!DOCTYPE|html)/i.test(decoded)) {
        throw new Error("返回的是 HTML 页面，不是规则文件");
      }

      await writeFile(filePath, decoded);

      console.log(`[成功] ${url}（${decoded.length} 字节）`);
      return true;
    } catch (error) {
      console.error(`[失败] ${url} - ${error.message}`);

      if (attempt < retries) {
        await sleep(1000 * (attempt + 1));
      }
    }
  }

  return false;
};

/**
 * 限制并发执行任务。
 */
const runWithConcurrency = async (tasks, limit) => {
  const results = [];
  const executing = [];

  for (const task of tasks) {
    const p = task();
    results.push(p);

    const e = p.then(
      () => executing.splice(executing.indexOf(e), 1),
      () => executing.splice(executing.indexOf(e), 1),
    );

    executing.push(e);

    if (executing.length >= limit) {
      await Promise.race(executing);
    }
  }

  return Promise.all(results);
};

/**
 * 规则下载。
 * - 全部失败 → 抛错
 * - 部分失败 → 警告，继续
 */
const downloadRules = async (rules, allow, directory) => {
  console.log(
    `开始下载规则：黑名单 ${rules.length} 个，白名单 ${allow.length} 个`,
  );

  const tasks = [
    ...rules.map(
      (url, index) => () =>
        downloadFile(url, `${directory}/rules${index + 1}.txt`),
    ),
    ...allow.map(
      (url, index) => () =>
        downloadFile(url, `${directory}/allow${index + 1}.txt`),
    ),
  ];

  const results = await runWithConcurrency(tasks, 5);

  const total = results.length;
  const failed = results.filter((ok) => !ok).length;
  const success = total - failed;

  // 全部失败 → 报错（避免生成空规则）
  if (success === 0) {
    throw new Error(`所有规则源下载失败（${total} 个）`);
  }

  // 部分失败 → 警告，继续
  if (failed > 0) {
    console.warn(
      `⚠️ 有 ${failed}/${total} 个规则源下载失败，继续使用成功的 ${success} 个`,
    );
  } else {
    console.log(`规则下载完成：${success}/${total}`);
  }
};

module.exports = {
  downloadRules,
};
