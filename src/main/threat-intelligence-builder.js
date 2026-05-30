const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");
const { bucketFeature, normalizeUrlForMatch } = require("./feature-engine");

const downloads = path.join(os.homedir(), "Downloads");
const defaultDataDir = path.join(__dirname, "..", "data");
const defaultConfigPath = path.join(__dirname, "..", "..", "config", "threat-feeds.json");

async function buildLocalIntelligence(options = {}) {
  const dataDir = options.outputDir || defaultDataDir;
  const indexDir = path.join(dataDir, "intelligence-index");
  const metadataPath = path.join(dataDir, "local-threat-intelligence.json");
  const config = loadFeedConfig(options.configPath || defaultConfigPath);
  const phishingDbRoot = path.join(downloads, "Phishing.Database-master", "Phishing.Database-master");
  const legitPhishCsv = path.join(downloads, "LegitPhish Dataset", "LegitPhish Dataset", "url_features_extracted1.csv");
  const phiusiilCsv = path.join(downloads, "phiusiil+phishing+url+dataset", "PhiUSIIL_Phishing_URL_Dataset.csv");

  fs.mkdirSync(indexDir, { recursive: true });
  const failures = [];
  const indexes = {
    activeDomains: new Map(),
    activeIps: new Map(),
    activeUrlHashes: new Map(),
    historicalDomains: new Map(),
    historicalIps: new Map(),
    historicalUrlHashes: new Map()
  };

  if (config.sources.downloads !== false) {
    await addValueFiles(indexes.activeDomains, [path.join(phishingDbRoot, "phishing-domains-ACTIVE.txt")], "domain", "Phishing.Database active domains", failures);
    await addValueFiles(indexes.activeIps, [path.join(phishingDbRoot, "phishing-IPs-ACTIVE.txt")], "ip", "Phishing.Database active IPs", failures);
    await addUrlHashFiles(indexes.activeUrlHashes, [path.join(phishingDbRoot, "phishing-links-ACTIVE.txt")], "Phishing.Database active links", failures);
    await addValueFiles(indexes.historicalDomains, [path.join(phishingDbRoot, "phishing-domains-INACTIVE")], "domain", "Phishing.Database inactive domains", failures);
    await addValueFiles(indexes.historicalIps, [path.join(phishingDbRoot, "phishing-IPs-INACTIVE.txt"), path.join(phishingDbRoot, "phishing-IPs-INACTIVE")], "ip", "Phishing.Database inactive IPs", failures);
    await addUrlHashFiles(indexes.historicalUrlHashes, [path.join(phishingDbRoot, "phishing-links-INACTIVE")], "Phishing.Database inactive links", failures);
  }

  if (config.sources.phishtank !== false) {
    await addPhishTank(indexes.activeUrlHashes, config, failures);
  }
  if (config.sources.openphish !== false) {
    await addRemoteUrlList(indexes.activeUrlHashes, "https://openphish.com/feed.txt", "OpenPhish community feed", config, failures);
  }
  if (config.sources.urlhaus && config.urlhausAuthKey) {
    await addRemoteUrlList(indexes.activeUrlHashes, `https://urlhaus-api.abuse.ch/v2/files/exports/${encodeURIComponent(config.urlhausAuthKey)}/recent.csv`, "URLhaus recent feed", config, failures);
  }

  const indexFiles = {};
  const counts = {};
  const sources = {};
  for (const [name, map] of Object.entries(indexes)) {
    const fileName = `${name}.sha256.bin`;
    writeHashIndex(path.join(indexDir, fileName), map);
    indexFiles[name] = path.join("intelligence-index", fileName).replace(/\\/g, "/");
    counts[name] = map.size;
    sources[name] = summarizeSources(map);
  }

  const models = [
    await trainCsvModel({
      name: "LegitPhish Dataset",
      source: legitPhishCsv,
      sourceLabel: "Downloads/LegitPhish Dataset/url_features_extracted1.csv",
      labelColumn: "ClassLabel",
      phishingLabel: "0",
      ignoredColumns: new Set(["URL", "ClassLabel"])
    }),
    await trainCsvModel({
      name: "PhiUSIIL URL Dataset",
      source: phiusiilCsv,
      sourceLabel: "Downloads/phiusiil+phishing+url+dataset/PhiUSIIL_Phishing_URL_Dataset.csv",
      labelColumn: "label",
      phishingLabel: "0",
      ignoredColumns: new Set(["FILENAME", "URL", "Domain", "TLD", "Title", "label"])
    })
  ].filter(Boolean);

  const metadata = {
    schemaVersion: 2,
    databaseVersion: `local-${new Date().toISOString().slice(0, 10)}`,
    generatedAt: new Date().toISOString(),
    config: {
      sources: config.sources,
      phishtankConfigured: Boolean(config.phishtankAppKey),
      urlhausConfigured: Boolean(config.urlhausAuthKey),
      googleSafeBrowsingConfigured: Boolean(config.googleSafeBrowsingApiKey)
    },
    sourcePaths: {
      phishingDatabase: "Downloads/Phishing.Database-master/Phishing.Database-master",
      legitPhishCsv: "Downloads/LegitPhish Dataset/url_features_extracted1.csv",
      phiusiilCsv: "Downloads/phiusiil+phishing+url+dataset/PhiUSIIL_Phishing_URL_Dataset.csv"
    },
    indexFiles,
    counts,
    sources,
    refreshFailures: failures,
    models
  };

  fs.writeFileSync(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`, "utf8");
  const result = {
    metadataPath,
    indexDir,
    counts,
    models: models.map((model) => ({ name: model.name, rows: model.rows, features: model.features.length })),
    failures
  };
  if (options.log) console.log(JSON.stringify(result, null, 2));
  return result;
}

function loadFeedConfig(configPath) {
  const fallback = {
    sources: { downloads: true, phishtank: false, openphish: true, urlhaus: false, googleSafeBrowsing: false },
    phishtankAppKey: "",
    urlhausAuthKey: "",
    googleSafeBrowsingApiKey: "",
    refresh: { timeoutMs: 20000, userAgent: "PhishingURLDetector/2.0 local-threat-refresh" }
  };
  try {
    return { ...fallback, ...JSON.parse(fs.readFileSync(configPath, "utf8")) };
  } catch {
    return fallback;
  }
}

async function addPhishTank(target, config, failures) {
  const keyPath = config.phishtankAppKey ? `${encodeURIComponent(config.phishtankAppKey)}/` : "";
  await addRemoteUrlList(target, `https://data.phishtank.com/data/${keyPath}online-valid.csv`, "PhishTank verified online feed", config, failures);
}

async function addRemoteUrlList(target, url, source, config, failures) {
  try {
    const response = await fetchWithTimeout(url, config.refresh?.timeoutMs || 20000, config.refresh?.userAgent);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const text = await response.text();
    let count = 0;
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("phish_id,")) continue;
      const urlValue = source.startsWith("PhishTank") ? parseCsvLine(trimmed)[1] : parseCsvLine(trimmed).find((value) => /^https?:\/\//i.test(value)) || trimmed;
      const normalized = normalizeUrlForMatch(urlValue);
      if (normalized && normalized.includes(".")) {
        addHash(target, normalized, source);
        count += 1;
      }
    }
    if (!count) failures.push({ source, message: "Feed returned no usable URLs" });
  } catch (error) {
    failures.push({ source, message: error.message });
  }
}

async function fetchWithTimeout(url, timeoutMs, userAgent) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      signal: controller.signal,
      headers: { "user-agent": userAgent || "PhishingURLDetector/2.0" }
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function addValueFiles(target, inputs, kind, source, failures) {
  for (const file of await expandFiles(inputs)) {
    try {
      await readLines(file, (line) => {
        const value = normalizeListValue(line, kind);
        if (value) addHash(target, value, source);
      });
    } catch (error) {
      failures.push({ source, file: path.basename(file), message: error.message });
    }
  }
}

async function addUrlHashFiles(target, inputs, source, failures) {
  for (const file of await expandFiles(inputs)) {
    try {
      await readLines(file, (line) => {
        const normalized = normalizeUrlForMatch(line);
        if (normalized && normalized.includes(".")) addHash(target, normalized, source);
      });
    } catch (error) {
      failures.push({ source, file: path.basename(file), message: error.message });
    }
  }
}

function addHash(target, value, source) {
  const hash = sha256Hex(value);
  const existing = target.get(hash);
  if (existing) existing.add(source);
  else target.set(hash, new Set([source]));
}

function writeHashIndex(filePath, map) {
  const hashes = [...map.keys()].sort();
  const buffer = Buffer.allocUnsafe(hashes.length * 32);
  hashes.forEach((hash, index) => Buffer.from(hash, "hex").copy(buffer, index * 32));
  fs.writeFileSync(filePath, buffer);
}

function summarizeSources(map) {
  const counts = {};
  for (const sourceSet of map.values()) {
    for (const source of sourceSet) counts[source] = (counts[source] || 0) + 1;
  }
  return counts;
}

async function trainCsvModel({ name, source, sourceLabel, labelColumn, phishingLabel, ignoredColumns }) {
  if (!fs.existsSync(source)) return null;
  const stream = fs.createReadStream(source);
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  let headers = null;
  let labelIndex = -1;
  let rows = 0;
  let phishingRows = 0;
  let legitimateRows = 0;
  const features = new Map();

  for await (const line of rl) {
    if (!headers) {
      headers = parseCsvLine(line);
      labelIndex = headers.indexOf(labelColumn);
      continue;
    }
    if (!line.trim()) continue;
    const row = parseCsvLine(line);
    const label = row[labelIndex];
    if (label !== phishingLabel && label !== "1") continue;
    rows += 1;
    const isPhishing = label === phishingLabel;
    if (isPhishing) phishingRows += 1;
    else legitimateRows += 1;

    for (let index = 0; index < headers.length; index += 1) {
      const feature = headers[index];
      if (index === labelIndex || ignoredColumns.has(feature)) continue;
      const value = row[index];
      if (value === undefined || value === "") continue;
      const number = Number(value);
      if (!Number.isFinite(number)) continue;
      const bucket = bucketFeature(feature, number);
      if (!features.has(feature)) {
        features.set(feature, { name: feature, buckets: new Map(), phishingSeen: 0, legitimateSeen: 0 });
      }
      const item = features.get(feature);
      if (isPhishing) item.phishingSeen += 1;
      else item.legitimateSeen += 1;
      if (!item.buckets.has(bucket)) item.buckets.set(bucket, { bucket, phishing: 0, legitimate: 0 });
      const bucketStats = item.buckets.get(bucket);
      if (isPhishing) bucketStats.phishing += 1;
      else bucketStats.legitimate += 1;
    }
  }

  const baseline = rows ? phishingRows / rows : 0;
  return {
    name,
    source: sourceLabel || path.basename(source),
    rows,
    phishingRows,
    legitimateRows,
    phishingLabel,
    legitimateLabel: "1",
    baselinePhishingRate: round(baseline),
    features: [...features.values()]
      .map((feature) => ({
        name: feature.name,
        phishingSeen: feature.phishingSeen,
        legitimateSeen: feature.legitimateSeen,
        buckets: [...feature.buckets.values()]
          .map((bucket) => {
            const support = bucket.phishing + bucket.legitimate;
            const phishingRate = support ? bucket.phishing / support : 0;
            const lift = baseline ? phishingRate / baseline : 0;
            return {
              bucket: bucket.bucket,
              support,
              phishingRate: round(phishingRate),
              lift: round(lift),
              weight: round(Math.max(0, Math.min(10, (phishingRate - baseline) * 16)))
            };
          })
          .filter((bucket) => bucket.support >= 20)
      }))
      .filter((feature) => feature.buckets.some((bucket) => bucket.weight > 0))
  };
}

async function expandFiles(inputs) {
  const found = [];
  for (const input of inputs) {
    if (!fs.existsSync(input)) continue;
    const stat = fs.statSync(input);
    if (stat.isFile()) {
      found.push(input);
    } else if (stat.isDirectory()) {
      for (const item of fs.readdirSync(input, { withFileTypes: true })) {
        const child = path.join(input, item.name);
        if (item.isDirectory()) found.push(...(await expandFiles([child])));
        if (item.isFile() && item.name.toLowerCase().endsWith(".txt")) found.push(child);
      }
    }
  }
  return found;
}

async function readLines(file, onLine) {
  const rl = readline.createInterface({ input: fs.createReadStream(file), crlfDelay: Infinity });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("!") || trimmed.startsWith("[")) continue;
    onLine(trimmed);
  }
}

function normalizeListValue(line, kind) {
  let value = line.trim().toLowerCase();
  if (value.includes("##")) value = value.split("##")[0];
  value = value.replace(/^\|\|/, "").replace(/\^$/, "").replace(/^0\.0\.0\.0\s+/, "").trim();
  if (kind === "ip") return isIp(value) ? value : "";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    try {
      value = new URL(value).hostname.toLowerCase();
    } catch {
      return "";
    }
  }
  value = value.replace(/^\*\./, "").replace(/^\./, "");
  return value.includes(".") && !value.includes("/") && !value.includes(" ") ? value : "";
}

function parseCsvLine(line) {
  const values = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === '"') {
      if (quoted && line[index + 1] === '"') {
        current += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
    } else if (char === "," && !quoted) {
      values.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  values.push(current);
  return values;
}

function isIp(value) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(":");
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function round(value) {
  return Number(value.toFixed(4));
}

module.exports = { buildLocalIntelligence };
