const removeDeadRules = async (
  rules,
  {
    concurrency = DEFAULT_CONCURRENCY,
    nameservers = DEFAULT_NAMESERVERS,
    port = DEFAULT_PORT,
    whiteSet = new Set(),
    cache,
    cacheFile = DEFAULT_CACHE_FILE,
    keepWhiteRules = true,
    autoSaveCache = true,
    onProgress,
    progressStep = DEFAULT_PROGRESS_STEP,
  } = {},
) => {
  console.log("开始剔除死域名规则");
  try {
    if (!Array.isArray(rules)) {
      throw new TypeError("rules 必须是字符串数组");
    }

    const cacheStore = cache || createFileCache(cacheFile);

    // 1. 解析规则
    const domainMap = new Map();
    const passthrough = [];

    for (const line of rules) {
      const parsed = parseRule(line);
      if (!parsed) {
        passthrough.push(line);
        continue;
      }
      const entry = domainMap.get(parsed.domain) || {
        isWhite: parsed.isWhite,
        originals: [],
      };
      entry.originals.push(parsed.original);
      if (parsed.isWhite) entry.isWhite = true;
      domainMap.set(parsed.domain, entry);
    }

    const domains = [...domainMap.keys()];
    const total = domains.length;
    console.log(`规则解析完成，共${rules.length}条规则，提取${total}个域名`);

    // 2. 并发检测（带进度）
    const limit = pLimit(concurrency);
    const results = new Map();
    const now = Math.floor(Date.now() / 1000);
    let cacheHits = 0;
    let completed = 0;
    const startTime = Date.now();

    const report = (force = false) => {
      if (!force && completed % progressStep !== 0) return;
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      const percent = ((completed / total) * 100).toFixed(1);
      const speed = completed / Math.max(elapsed, 0.001);
      const remain = speed > 0 ? ((total - completed) / speed).toFixed(0) : "?";
      console.log(
        `进度: ${completed}/${total} (${percent}%) | 缓存命中: ${cacheHits} | 已用: ${elapsed}s | 预计剩余: ${remain}s`,
      );
      if (typeof onProgress === "function") {
        onProgress({
          completed,
          total,
          cacheHits,
          elapsed: Number(elapsed),
          remain: Number(remain) || 0,
          percent: Number(percent),
        });
      }
    };

    await Promise.all(
      domains.map((domain) =>
        limit(async () => {
          const cached = cacheStore.get(domain);
          if (cached && now - cached.timeStamp <= CACHE_TTL) {
            results.set(domain, cached.ipList);
            cacheHits++;
          } else {
            const ipList = await checkDomain(domain, { nameservers, port });
            cacheStore.set(domain, { ipList, timeStamp: now });
            results.set(domain, ipList);
          }
          completed++;
          report();
        }),
      ),
    );
    report(true);

    // 3. 分类
    const deadSet = new Set();
    const aliveSet = new Set();
    for (const domain of domains) {
      const ipList = results.get(domain);
      if (ipList.length > 0) aliveSet.add(domain);
      else deadSet.add(domain);
    }

    // 4. 剔除规则（用循环 push，避免展开运算符爆栈）
    const cleaned = [];
    const nocleaned = [];

    for (const [domain, entry] of domainMap) {
      const isDead = deadSet.has(domain);
      const isWhite = entry.isWhite || whiteSet.has(domain);

      if (isWhite && keepWhiteRules) {
        for (const r of entry.originals) cleaned.push(r);
        continue;
      }
      if (!isDead) {
        for (const r of entry.originals) cleaned.push(r);
        continue;
      }

      const labels = domain.split(".");
      let parentAlive = false;
      for (let i = 1; i < labels.length; i++) {
        if (aliveSet.has(labels.slice(i).join("."))) {
          parentAlive = true;
          break;
        }
      }
      if (parentAlive) {
        for (const r of entry.originals) cleaned.push(r);
      } else {
        for (const r of entry.originals) nocleaned.push(r);
      }
    }

    for (const r of passthrough) cleaned.push(r);

    // 5. 统计信息
    const deadDomains = [...deadSet].sort();
    const aliveDomains = [...aliveSet].sort();

    const stats = {
      totalRules: rules.length,
      totalDomains: total,
      aliveDomains: aliveDomains.length,
      deadDomains: deadDomains.length,
      aliveRules: cleaned.length,
      deadRules: nocleaned.length,
      passthrough: passthrough.length,
      cacheHits,
      cacheSize: cacheStore.size ? cacheStore.size() : 0,
    };

    if (autoSaveCache && typeof cacheStore.save === "function") {
      cacheStore.save();
    }

    console.log(
      `剔除死域名规则完成，存活${cleaned.length}条，剔除${nocleaned.length}条，死域名${deadDomains.length}个，缓存命中${cacheHits}次`,
    );

    return {
      cleaned, // 排除死域名后的规则
      nocleaned, // 被剔除的死域名规则
      deadDomains, // 死域名列表
      aliveDomains, // 存活域名列表
      stats, // 统计信息
    };
  } catch (error) {
    throw new Error(`剔除死域名规则失败: ${error.message}`);
  }
};
