const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const { bucketFeature, extractUrlFeatures, normalizeUrlForMatch } = require("./feature-engine");
const PHISHING_FEATURE_PROFILE = require("../data/phishing-feature-profile.json");

const DEFAULT_DATA_DIR = path.join(__dirname, "..", "data");
const HASH_BYTES = 32;
const TRUSTED_PRIMARY_DOMAINS = new Set(["google.com", "microsoft.com", "apple.com", "paypal.com", "amazon.com"]);

let dataDirs = [DEFAULT_DATA_DIR];
let artifact = null;
let indexes = null;
let loadedDataDir = null;

function configureLocalIntelligence(options = {}) {
  const dirs = options.dataDirs || [options.dataDir].filter(Boolean);
  dataDirs = unique([...dirs, DEFAULT_DATA_DIR]);
  reloadLocalIntelligence();
}

function reloadLocalIntelligence() {
  artifact = null;
  indexes = null;
  loadedDataDir = null;
}

function getLocalIntelligenceStatus() {
  loadArtifact();
  return {
    available: Boolean(artifact),
    loadedDataDir,
    databaseVersion: artifact.databaseVersion,
    generatedAt: artifact.generatedAt,
    schemaVersion: artifact.schemaVersion || 1,
    counts: artifact.counts || {},
    sources: artifact.sources || {},
    config: artifact.config || {},
    refreshFailures: artifact.refreshFailures || [],
    indexBytes: Object.fromEntries(Object.entries(indexes || {}).map(([name, buffer]) => [name, buffer.length]))
  };
}

function evaluateLocalIntelligence(report, parsed) {
  loadArtifact();
  const started = performance.now();
  const features = extractUrlFeatures(report.normalizedUrl, report);
  const blocklistResult = matchBlocklists(report, parsed);
  const modelResult = scoreModels(features);
  const legacyProfile = scoreLegacyProfile(report, parsed);
  const trustedPrimary = blocklistResult.blocklistMatch.status === "none" && isTrustedPrimaryDomain(parsed.hostname);
  const trainedModelScore = trustedPrimary ? Math.min(20, Math.max(modelResult.score, legacyProfile.score)) : Math.max(modelResult.score, legacyProfile.score);
  const modelScores = [...modelResult.modelScores, legacyProfile.modelScore].filter(Boolean);
  const matchedFeatures = [...modelResult.matchedFeatures, ...legacyProfile.matchedFeatures]
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 12);
  const confidence = blocklistResult.blocklistMatch.status === "active"
    ? "High"
    : trainedModelScore >= 65 || blocklistResult.blocklistMatch.status === "historical"
      ? "Medium"
      : trainedModelScore >= 35
        ? "Low"
        : "None";
  const evidencePriority = blocklistResult.blocklistMatch.status === "active"
    ? "active-feed"
    : blocklistResult.blocklistMatch.status === "historical"
      ? "historical-feed"
      : trainedModelScore >= 35
        ? "trained-model"
        : "supporting-signals";

  const localIntelligence = {
    blocklistMatch: blocklistResult.blocklistMatch,
    feedMatches: blocklistResult.feedMatches,
    matchedDataset: blocklistResult.blocklistMatch.dataset || (matchedFeatures[0]?.dataset ?? "None"),
    trainedModelScore,
    modelScores,
    matchedFeatures,
    confidence,
    databaseVersion: artifact.databaseVersion,
    generatedAt: artifact.generatedAt,
    counts: artifact.counts || {},
    sources: artifact.sources || {},
    evidencePriority,
    trustOverride: trustedPrimary ? "trusted-primary-domain" : null,
    refreshFailures: artifact.refreshFailures || [],
    inferenceMs: Number((performance.now() - started).toFixed(2))
  };

  return {
    localIntelligence,
    findings: buildFindings(localIntelligence)
  };
}

function matchBlocklists(report, parsed) {
  const host = parsed.hostname.toLowerCase();
  const candidates = domainCandidates(host);
  const normalizedUrls = unique([report.normalizedUrl, report.finalUrl].filter(Boolean).map(normalizeUrlForMatch));
  const ips = unique([host, ...(report.ipAddresses || [])].filter((value) => net.isIP(value)));
  const feedMatches = [];

  for (const value of normalizedUrls) {
    if (hasHash("activeUrlHashes", value)) feedMatches.push(feedMatch("active", "url", "Exact URL hash", "activeUrlHashes"));
  }
  for (const value of candidates) {
    if (hasHash("activeDomains", value)) feedMatches.push(feedMatch("active", "domain", value, "activeDomains"));
  }
  for (const value of ips) {
    if (hasHash("activeIps", value)) feedMatches.push(feedMatch("active", "ip", value, "activeIps"));
  }
  for (const value of normalizedUrls) {
    if (hasHash("historicalUrlHashes", value)) feedMatches.push(feedMatch("historical", "url", "Exact URL hash", "historicalUrlHashes"));
  }
  for (const value of candidates) {
    if (hasHash("historicalDomains", value)) feedMatches.push(feedMatch("historical", "domain", value, "historicalDomains"));
  }
  for (const value of ips) {
    if (hasHash("historicalIps", value)) feedMatches.push(feedMatch("historical", "ip", value, "historicalIps"));
  }

  return {
    blocklistMatch: feedMatches[0] || { status: "none", type: "none", value: "No local blocklist match", dataset: null, sources: [] },
    feedMatches
  };
}

function feedMatch(status, type, value, indexName) {
  const sources = sourceNames(indexName);
  return {
    status,
    type,
    value,
    index: indexName,
    dataset: sources.length ? sources[0] : indexLabel(indexName),
    sources
  };
}

function scoreModels(features) {
  const matchedFeatures = [];
  const modelScores = [];
  for (const model of artifact.models || []) {
    const modelFeatures = [];
    for (const feature of model.features || []) {
      if (!(feature.name in features)) continue;
      const bucketName = bucketFeature(feature.name, features[feature.name]);
      const bucket = (feature.buckets || []).find((item) => item.bucket === bucketName);
      if (!bucket || bucket.weight <= 0) continue;
      modelFeatures.push({
        dataset: model.name,
        feature: feature.name,
        bucket: bucket.bucket,
        phishingRate: bucket.phishingRate,
        lift: bucket.lift,
        support: bucket.support,
        weight: bucket.weight
      });
    }
    const score = modelScore(modelFeatures);
    modelScores.push({
      dataset: model.name,
      score,
      baselinePhishingRate: model.baselinePhishingRate,
      rows: model.rows,
      matchedFeatureCount: modelFeatures.length,
      topFeatures: modelFeatures.sort((a, b) => b.weight - a.weight).slice(0, 5)
    });
    matchedFeatures.push(...modelFeatures);
  }
  return {
    score: Math.max(0, ...modelScores.map((item) => item.score)),
    modelScores,
    matchedFeatures
  };
}

function modelScore(features) {
  const weight = features.sort((a, b) => b.weight - a.weight).slice(0, 10).reduce((sum, item) => sum + item.weight, 0);
  return Math.min(100, Math.round(weight * 3.2));
}

function scoreLegacyProfile(report, parsed) {
  const matchedFeatures = inferLegacyFeatureMatches(report, parsed)
    .map((feature) => {
      const profile = PHISHING_FEATURE_PROFILE.features?.[feature];
      return profile
        ? {
            dataset: "UCI Phishing URL Feature Profile",
            feature,
            bucket: "risk-present",
            phishingRate: profile.phishingRateWhenRisky,
            lift: profile.lift,
            support: profile.support,
            weight: profile.pointWeight
          }
        : null;
    })
    .filter(Boolean);
  const weight = matchedFeatures.filter((item) => item.weight >= 0.5).reduce((sum, item) => sum + item.weight, 0);
  return {
    score: Math.min(100, Math.round(weight * 5)),
    modelScore: {
      dataset: "UCI Phishing URL Feature Profile",
      score: Math.min(100, Math.round(weight * 5)),
      baselinePhishingRate: PHISHING_FEATURE_PROFILE.baselinePhishingRate,
      rows: PHISHING_FEATURE_PROFILE.totalRows,
      matchedFeatureCount: matchedFeatures.length,
      topFeatures: matchedFeatures.sort((a, b) => b.weight - a.weight).slice(0, 5)
    },
    matchedFeatures
  };
}

function buildFindings(localIntelligence) {
  const findings = [];
  if (localIntelligence.blocklistMatch.status === "active") {
    findings.push({
      severity: "High",
      title: "Active phishing database hit",
      detail: `${localIntelligence.blocklistMatch.dataset} matched this ${localIntelligence.blocklistMatch.type}: ${localIntelligence.blocklistMatch.value}.`,
      points: 70
    });
  } else if (localIntelligence.blocklistMatch.status === "historical") {
    findings.push({
      severity: "Medium",
      title: "Historical phishing database hit",
      detail: `${localIntelligence.blocklistMatch.dataset} previously tracked this ${localIntelligence.blocklistMatch.type}: ${localIntelligence.blocklistMatch.value}.`,
      points: 24
    });
  }

  const strongFeatures = localIntelligence.matchedFeatures.filter((item) => item.weight >= 1);
  if (localIntelligence.trainedModelScore >= 65 && strongFeatures.length >= 3) {
    findings.push({
      severity: "High",
      title: "Trained dataset risk pattern",
      detail: `Local trained datasets produced a ${localIntelligence.trainedModelScore}/100 model score. Top indicators: ${strongFeatures.slice(0, 6).map((item) => item.feature).join(", ")}.`,
      points: 22
    });
  } else if (localIntelligence.trainedModelScore >= 35 && strongFeatures.length >= 2) {
    findings.push({
      severity: "Medium",
      title: "Trained dataset risk pattern",
      detail: `Local trained datasets produced a ${localIntelligence.trainedModelScore}/100 model score. Top indicators: ${strongFeatures.slice(0, 5).map((item) => item.feature).join(", ")}.`,
      points: 12
    });
  }
  return findings;
}

function inferLegacyFeatureMatches(report, parsed) {
  const host = parsed.hostname.toLowerCase();
  const labels = host.split(".");
  const registrable = labels.length >= 2 ? labels.slice(-2).join(".") : host;
  const pathAfterScheme = report.normalizedUrl.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const matched = [];
  const add = (condition, feature) => {
    if (condition) matched.push(feature);
  };

  add(Boolean(net.isIP(host)), "UsingIP");
  add(report.normalizedUrl.length >= 75, "LongURL");
  add(report.normalizedUrl.includes("@"), "Symbol@");
  add(pathAfterScheme.includes("//"), "Redirecting//");
  add(registrable.includes("-"), "PrefixSuffix-");
  add(labels.length >= 4, "SubDomains");
  add(parsed.protocol !== "https:", "HTTPS");
  add(parsed.port && !["80", "443"].includes(parsed.port), "NonStdPort");
  add(host.includes("https"), "HTTPSDomainURL");
  add((report.pageSignals.externalLinkRatio || 0) >= 0.61 || (report.pageSignals.externalFormActions || 0) > 0, "RequestURL");
  add((report.pageSignals.externalLinkRatio || 0) >= 0.67, "AnchorURL");
  add((report.pageSignals.externalScripts || 0) >= 8, "LinksInScriptTags");
  add((report.pageSignals.externalFormActions || 0) > 0 || ((report.pageSignals.emptyFormActions || 0) > 0 && (report.pageSignals.passwordInputs || 0) > 0), "ServerFormHandler");
  add((report.pageSignals.mailLinks || 0) > 0, "InfoEmail");
  add(Boolean(report.finalUrl && new URL(report.finalUrl).hostname.toLowerCase() !== host), "WebsiteForwarding");
  add((report.pageSignals.rightClickBlocks || 0) > 0, "DisableRightClick");
  add((report.pageSignals.popupCalls || 0) > 0, "UsingPopupWindow");
  add((report.pageSignals.iframes || 0) > 0, "IframeRedirection");
  add(report.whois?.domainAgeDays !== null && report.whois?.domainAgeDays !== undefined && report.whois.domainAgeDays < 180, "AgeofDomain");
  add(report.whois?.registered === false || report.errors.some((error) => error.toLowerCase().includes("dns lookup failed")), "DNSRecording");

  return unique(matched);
}

function loadArtifact() {
  if (artifact && indexes) return;
  const location = findMetadata();
  if (!location) {
    artifact = {
      schemaVersion: 2,
      databaseVersion: "missing",
      generatedAt: null,
      counts: {},
      sources: {},
      indexFiles: {},
      models: [],
      refreshFailures: [{ source: "Local data", message: "Threat intelligence metadata was not found" }]
    };
    indexes = {};
    loadedDataDir = null;
    return;
  }
  artifact = JSON.parse(fs.readFileSync(location.metadataPath, "utf8"));
  loadedDataDir = location.dataDir;
  indexes = {};
  for (const [name, relativeFile] of Object.entries(artifact.indexFiles || {})) {
    const filePath = path.join(location.dataDir, relativeFile);
    indexes[name] = fs.existsSync(filePath) ? fs.readFileSync(filePath) : Buffer.alloc(0);
  }
}

function findMetadata() {
  for (const dataDir of dataDirs) {
    const metadataPath = path.join(dataDir, "local-threat-intelligence.json");
    if (fs.existsSync(metadataPath)) return { dataDir, metadataPath };
  }
  return null;
}

function hasHash(indexName, value) {
  const buffer = indexes[indexName];
  if (!buffer?.length || buffer.length % HASH_BYTES !== 0) return false;
  return binarySearch(buffer, sha256Buffer(value));
}

function binarySearch(buffer, needle) {
  let low = 0;
  let high = buffer.length / HASH_BYTES - 1;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const offset = mid * HASH_BYTES;
    const compared = Buffer.compare(buffer.subarray(offset, offset + HASH_BYTES), needle);
    if (compared === 0) return true;
    if (compared < 0) low = mid + 1;
    else high = mid - 1;
  }
  return false;
}

function sourceNames(indexName) {
  return Object.keys(artifact.sources?.[indexName] || {});
}

function indexLabel(indexName) {
  return ({
    activeDomains: "Active phishing domain feeds",
    activeIps: "Active phishing IP feeds",
    activeUrlHashes: "Active phishing URL feeds",
    historicalDomains: "Historical phishing domain feeds",
    historicalIps: "Historical phishing IP feeds",
    historicalUrlHashes: "Historical phishing URL feeds"
  })[indexName] || "Local threat feed";
}

function domainCandidates(host) {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  const candidates = [];
  for (let index = 0; index <= Math.max(0, labels.length - 2); index += 1) {
    candidates.push(labels.slice(index).join("."));
  }
  return unique(candidates);
}

function isTrustedPrimaryDomain(host) {
  const normalized = String(host || "").toLowerCase().replace(/\.$/, "");
  return TRUSTED_PRIMARY_DOMAINS.has(normalized);
}

function sha256Buffer(value) {
  return crypto.createHash("sha256").update(String(value)).digest();
}

function unique(items) {
  return [...new Set(items.filter(Boolean).map((item) => String(item).trim()).filter(Boolean))];
}

module.exports = {
  configureLocalIntelligence,
  evaluateLocalIntelligence,
  getLocalIntelligenceStatus,
  reloadLocalIntelligence
};
