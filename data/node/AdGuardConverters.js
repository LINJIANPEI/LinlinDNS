class AdGuardConverter {
  constructor() {
    this.ipv4Regex =
      /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?){3}$/;
    this.domainRegex = /^(?!-)[A-Za-z0-9-.]{1,63}(?<!-)$/;
    this.domainPatternRegex = /^(\*\.)?([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+$/;
  }

  // 主转换方法
  convert(rules) {
    return rules
      .reduce((acc, line) => {
        const processed = this.processLine(line);
        if (processed) acc.push(processed);
        return acc;
      }, [])
      .filter(Boolean);
  }

  // 私有方法：行处理逻辑
  processLine(line) {
    const trimmed = line.trim();
    if (!trimmed || this.isComment(trimmed)) return null;

    return (
      this.handleHostsFormat(trimmed) ||
      this.handleSpecialCases(trimmed) ||
      this.validateAdGuardRule(trimmed)
    );
  }

  // 处理 hosts 格式
  handleHostsFormat(line) {
    const parts = line.split(/\s+/);
    if (parts.length < 2 || !this.isValidIP(parts[0])) return null;

    const validDomains = parts
      .slice(1)
      .filter((d) => d && !d.startsWith("#"))
      .filter((d) => this.isValidDomain(d));

    return validDomains.length > 0 ? validDomains.map((d) => `||${d}^`) : null;
  }

  // 处理特殊格式（ABlock/dnsrewrite）
  handleSpecialCases(line) {
    // 处理 ABlock 的 DNS 重写格式
    if (line.startsWith("||") && line.includes("$dnsrewrite")) {
      const cleanDomain = line.split("^")[0].slice(2);
      return this.isValidDomain(cleanDomain) ? `||${cleanDomain}^` : null;
    }

    // 处理包含通配符的规则
    if (line.includes("*")) {
      return this.validateWildcardRule(line);
    }
    return null;
  }

  // 验证 AdGuard 规则有效性
  validateAdGuardRule(rule) {
    if (rule.startsWith("@@")) return rule; // 异常规则
    if (rule.includes("##")) return this.validateElementRule(rule);
    if (rule.startsWith("/") && rule.endsWith("/")) return rule; // 正则规则
    if (this.isBasicRule(rule)) return rule;
    return null;
  }

  // 辅助验证方法
  isComment(line) {
    return /^[#!！]/.test(line);
  }

  isValidIP(ip) {
    return this.ipv4Regex.test(ip);
  }

  isValidDomain(domain) {
    return this.domainRegex.test(domain);
  }

  validateElementRule(rule) {
    const [domains, selector] = rule.split("##");
    return domains
      .split(",")
      .every((d) => this.domainPatternRegex.test(d.trim())) && selector
      ? rule
      : null;
  }

  isBasicRule(rule) {
    return (
      /^\|{0,2}[\w.*-]+(\^)?(\$.*)?$/.test(rule) || /\$[a-z,~]+$/.test(rule)
    );
  }

  validateWildcardRule(rule) {
    const domainPart = rule.replace(/^\|+/g, "").split(/[\^$]/)[0];
    return this.domainPatternRegex.test(domainPart) ? rule : null;
  }
}

const AdGuardConverters = async (input) => {
  // 使用示例
  const converter = new AdGuardConverter();
  return converter.convert(input);
};

// 输出：
// [
//   "||example.com^",
//   "||doubleclick.net^",
//   "||ads.google.com^",
//   "||adservice.com^",
//   "example.com##.ad-banner",
//   "@@||good-site.com^",
//   "/ads[0-9]+\.com/"
// ]
// 使用示例，保持原有入参和出参格式

module.exports = { AdGuardConverters };
