const { scanUrl } = require("./scanner");
const { getLocalIntelligenceStatus } = require("./local-intelligence");

const DEFAULT_SAMPLES = [
  { url: "https://google.com", label: "legitimate" },
  { url: "https://microsoft.com", label: "legitimate" },
  { url: "https://apple.com", label: "legitimate" },
  { url: "https://paypal.com", label: "legitimate" },
  { url: "https://amazon.com", label: "legitimate" },
  { url: "https://00000000000000000000000000000000000000000.xyz", label: "phishing" },
  { url: "http://100.25.1.9", label: "phishing" },
  { url: "ftp://188.128.111.33/iptv/tv1324/view.html", label: "phishing" },
  { url: "http://paypal-login-verify-account.example.xyz/signin?session=abc", label: "phishing" }
];

async function evaluateThreatModel(samples = DEFAULT_SAMPLES) {
  const started = performance.now();
  const results = [];
  for (const sample of samples) {
    const itemStarted = performance.now();
    const report = await scanUrl(sample.url, { fetchSite: false, network: false, timeoutMs: 2000 });
    const predictedPositive = report.verdict !== "Safe";
    results.push({
      url: sample.url,
      label: sample.label,
      verdict: report.verdict,
      riskScore: report.riskScore,
      predictedPositive,
      inferenceMs: report.performance?.inferenceMs || Number((performance.now() - itemStarted).toFixed(2)),
      localIntelligence: report.localIntelligence
    });
  }
  const metrics = calculateMetrics(results);
  return {
    generatedAt: new Date().toISOString(),
    database: getLocalIntelligenceStatus(),
    metrics: {
      ...metrics,
      averageInferenceMs: average(results.map((item) => item.inferenceMs)),
      elapsedMs: Number((performance.now() - started).toFixed(2)),
      rocAucApproximation: Number(((metrics.recall + (1 - metrics.falsePositiveRate)) / 2).toFixed(3))
    },
    samples: results
  };
}

function calculateMetrics(results) {
  const tp = results.filter((item) => item.label === "phishing" && item.predictedPositive).length;
  const tn = results.filter((item) => item.label === "legitimate" && !item.predictedPositive).length;
  const fp = results.filter((item) => item.label === "legitimate" && item.predictedPositive).length;
  const fn = results.filter((item) => item.label === "phishing" && !item.predictedPositive).length;
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const falsePositiveRate = fp + tn ? fp / (fp + tn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return {
    truePositive: tp,
    trueNegative: tn,
    falsePositive: fp,
    falseNegative: fn,
    precision: roundMetric(precision),
    recall: roundMetric(recall),
    f1: roundMetric(f1),
    falsePositiveRate: roundMetric(falsePositiveRate)
  };
}

function average(values) {
  const filtered = values.filter((value) => Number.isFinite(value));
  if (!filtered.length) return 0;
  return Number((filtered.reduce((sum, value) => sum + value, 0) / filtered.length).toFixed(2));
}

function roundMetric(value) {
  return Number(value.toFixed(3));
}

module.exports = { DEFAULT_SAMPLES, evaluateThreatModel };
