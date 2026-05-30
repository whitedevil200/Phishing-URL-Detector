const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { exportReport, scanUrl } = require("../src/main/scanner");
const localThreatIntel = require("../src/data/local-threat-intelligence.json");
const { getLocalIntelligenceStatus } = require("../src/main/local-intelligence");

async function testScannerSignals() {
  const suspicious = await scanUrl("http://paypal-login-verify-account.example.xyz/signin?session=abc", {
    fetchSite: false,
    timeoutMs: 3000
  });
  assert.equal(suspicious.verdict, "Dangerous");
  assert.ok(suspicious.riskScore >= 65);
  assert.ok(suspicious.findings.some((finding) => finding.title === "Possible brand impersonation"));
  assert.ok(suspicious.findings.some((finding) => finding.title === "No HTTPS"));

  const invalid = await scanUrl("not a url", { fetchSite: false, timeoutMs: 1000 });
  assert.ok(["Suspicious", "Dangerous"].includes(invalid.verdict));
  assert.ok(invalid.findings.length > 0);
}

async function testReportExport() {
  const report = await scanUrl("http://paypal-login-verify-account.example.xyz/signin?session=abc", {
    fetchSite: false,
    timeoutMs: 3000
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "phishing-url-detector-"));
  const htmlPath = path.join(dir, "report.html");
  const jsonPath = path.join(dir, "report.json");
  exportReport(report, htmlPath, "html");
  exportReport(report, jsonPath, "json");
  assert.ok(fs.readFileSync(htmlPath, "utf8").includes("Phishing URL Report"));
  const parsed = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
  assert.equal(parsed.verdict, report.verdict);
}

async function testWhoisParsing() {
  const google = await scanUrl("https://google.com", { fetchSite: false, timeoutMs: 12000 });
  assert.equal(google.whois.registered, true);
  assert.match(google.whois.registrar, /MarkMonitor|Google|provided/i);
  assert.notEqual(google.whois.created, "Not provided");
  assert.ok(google.whois.nameservers.length > 0);

  const subdomain = await scanUrl("https://accounts.google.com", { fetchSite: false, timeoutMs: 12000 });
  assert.equal(subdomain.whois.domain, "google.com");
  assert.equal(subdomain.whois.registered, true);
}

async function testLocalThreatIntelligence() {
  assert.ok(localThreatIntel.counts.activeDomains > 0);
  assert.ok(localThreatIntel.counts.activeIps > 0);
  assert.ok(localThreatIntel.counts.activeUrlHashes > 0);
  assert.ok(!localThreatIntel.blocklists);
  assert.equal(localThreatIntel.schemaVersion, 2);
  assert.ok(localThreatIntel.models.some((model) => model.name === "LegitPhish Dataset" && model.phishingLabel === "0"));
  assert.ok(localThreatIntel.models.some((model) => model.name === "PhiUSIIL URL Dataset" && model.phishingLabel === "0"));
  const status = getLocalIntelligenceStatus();
  for (const relativeFile of Object.values(localThreatIntel.indexFiles)) {
    const fullPath = path.join(__dirname, "..", "src", "data", relativeFile);
    assert.ok(fs.existsSync(fullPath));
    assert.ok(fs.statSync(fullPath).size > 0);
  }
  assert.ok(status.indexBytes.activeDomains > 0);

  const activeDomain = await scanUrl("https://00000000000000000000000000000000000000000.xyz", {
    fetchSite: false,
    timeoutMs: 3000
  });
  assert.equal(activeDomain.verdict, "Dangerous");
  assert.equal(activeDomain.localIntelligence.blocklistMatch.status, "active");
  assert.equal(activeDomain.localIntelligence.blocklistMatch.type, "domain");

  const activeIp = await scanUrl("http://100.25.1.9", { fetchSite: false, timeoutMs: 3000 });
  assert.equal(activeIp.localIntelligence.blocklistMatch.status, "active");
  assert.equal(activeIp.localIntelligence.blocklistMatch.type, "ip");

  const activeUrl = await scanUrl("ftp://188.128.111.33/iptv/tv1324/view.html", {
    fetchSite: false,
    timeoutMs: 3000
  });
  assert.equal(activeUrl.localIntelligence.blocklistMatch.status, "active");
  assert.equal(activeUrl.localIntelligence.blocklistMatch.type, "url");

  const google = await scanUrl("https://google.com", { fetchSite: false, timeoutMs: 12000 });
  assert.notEqual(google.verdict, "Dangerous");
  assert.equal(google.localIntelligence.blocklistMatch.status, "none");
  assert.ok(Array.isArray(google.localIntelligence.feedMatches));
  assert.ok(Array.isArray(google.localIntelligence.modelScores));
  assert.ok(google.localIntelligence.evidencePriority);
  assert.ok(google.performance.inferenceMs >= 0);

  for (const clean of ["https://microsoft.com", "https://apple.com", "https://paypal.com", "https://amazon.com"]) {
    const report = await scanUrl(clean, { fetchSite: false, timeoutMs: 12000 });
    assert.notEqual(report.verdict, "Dangerous");
    assert.equal(report.localIntelligence.blocklistMatch.status, "none");
  }
}

(async () => {
  await testScannerSignals();
  await testReportExport();
  await testWhoisParsing();
  await testLocalThreatIntelligence();
  console.log("Functional tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
