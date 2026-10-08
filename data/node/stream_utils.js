const fs = require("node:fs");
const readline = require("node:readline");
const { finished } = require("node:stream/promises");

/**
 * 流式按行读取文件。
 * @param {string} filePath
 * @param {(line: string) => Promise<void>|void} onLine
 */
const readLines = async (filePath, onLine) => {
  const rl = readline.createInterface({
    input: fs.createReadStream(filePath, { encoding: "utf8" }),
    crlfDelay: Infinity,
  });
  for await (const line of rl) {
    await onLine(line);
  }
};

/**
 * 流式按行写入文件，自动处理背压。
 */
class LineWriter {
  constructor(filePath) {
    this.stream = fs.createWriteStream(filePath, { encoding: "utf8" });
    this.count = 0;
    this.closed = false;
  }
  async write(line) {
    this.count++;
    if (!this.stream.write(line + "\n")) {
      await new Promise((r) => this.stream.once("drain", r));
    }
  }
  async close() {
    if (this.closed) return;
    this.closed = true;
    this.stream.end();
    await finished(this.stream);
  }
}

module.exports = { readLines, LineWriter };
