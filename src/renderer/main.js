const state = {
  report: null,
  threatStatus: null,
  evaluation: null,
  history: [],
  activeSection: "dashboard"
};

const instagramUrl = "https://www.instagram.com/advaitik_intelligence?igsh=YTRjYjVna2ZlbnFm";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const els = {
  urlInput: $("#urlInput"),
  clearButton: $("#clearButton"),
  fetchSite: $("#fetchSite"),
  scanButton: $("#scanButton"),
  dashboardPanel: $("#dashboardPanel"),
  featurePanel: $("#featurePanel"),
  featureKicker: $("#featureKicker"),
  featureTitle: $("#featureTitle"),
  featureBody: $("#featureBody"),
  featureAction: $("#featureAction"),
  menuButton: $("#menuButton"),
  minimizeButton: $("#minimizeButton"),
  maximizeButton: $("#maximizeButton"),
  closeButton: $("#closeButton"),
  verdictText: $("#verdictText"),
  riskLabel: $("#riskLabel"),
  riskScore: $("#riskScore"),
  riskOrb: $("#riskOrb"),
  summaryText: $("#summaryText"),
  findingsBody: $("#findingsBody"),
  whoisCards: $("#whoisCards"),
  rawReport: $("#rawReport"),
  exportHtml: $("#exportHtml"),
  exportJson: $("#exportJson"),
  instagramButton: $("#instagramButton")
};

init();

function init() {
  els.scanButton.addEventListener("click", runScan);
  els.urlInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") runScan();
  });
  els.clearButton.addEventListener("click", () => {
    els.urlInput.value = "";
    els.urlInput.focus();
  });
  els.menuButton.addEventListener("click", toggleMenu);
  els.exportHtml.addEventListener("click", () => exportReport("html"));
  els.exportJson.addEventListener("click", () => exportReport("json"));
  els.instagramButton.addEventListener("click", () => window.detector.openExternal(instagramUrl));
  els.minimizeButton.addEventListener("click", () => window.detector.minimize());
  els.maximizeButton.addEventListener("click", () => window.detector.maximize());
  els.closeButton.addEventListener("click", () => window.detector.close());
  $$(".side-item[data-section]").forEach((button) => {
    button.addEventListener("click", () => activateSection(button.dataset.section));
  });

  state.history = loadHistory();
  window.detector.threatStatus().then((status) => {
    state.threatStatus = status;
    if (state.activeSection === "settings" || state.activeSection === "threat") renderFeatureSection(state.activeSection);
  });

  els.urlInput.value = "https://secure-login-update.com/verify-account";
  renderEmptyWhois();
}

async function runScan() {
  const url = els.urlInput.value.trim();
  if (!url) return;

  setBusy(true);
  try {
    const report = await window.detector.scanUrl({ url, fetchSite: els.fetchSite.checked });
    state.report = report;
    addHistory(report);
    renderReport(report);
    if (state.activeSection !== "dashboard") renderFeatureSection(state.activeSection);
  } catch (error) {
    els.summaryText.textContent = error.message || "Unexpected scan failure.";
  } finally {
    setBusy(false);
  }
}

function activateSection(section) {
  state.activeSection = section;
  $$(".side-item[data-section]").forEach((button) => {
    button.classList.toggle("active", button.dataset.section === section);
  });
  const isDashboard = section === "dashboard";
  els.dashboardPanel.classList.toggle("hidden", !isDashboard);
  els.featurePanel.classList.toggle("hidden", isDashboard);
  if (!isDashboard) renderFeatureSection(section);
}

function renderFeatureSection(section) {
  els.featureAction.classList.add("hidden");
  els.featureAction.onclick = null;
  if (section === "history") renderHistorySection();
  if (section === "bulk") renderBulkSection();
  if (section === "domain") renderDomainSection();
  if (section === "threat") renderThreatSection();
  if (section === "settings") renderSettingsSection();
  if (section === "about") renderAboutSection();
}

function renderHistorySection() {
  els.featureKicker.textContent = "Scan records";
  els.featureTitle.textContent = "URL Scan History";
  els.featureAction.textContent = "Clear History";
  els.featureAction.classList.remove("hidden");
  els.featureAction.onclick = () => {
    state.history = [];
    saveHistory();
    renderHistorySection();
  };
  if (!state.history.length) {
    els.featureBody.innerHTML = `<div class="tool-card">No scan history yet. Run a URL scan from the dashboard to add records here.</div>`;
    return;
  }
  els.featureBody.innerHTML = `
    <div class="tool-table">
      <div class="tool-head"><span>URL</span><span>Verdict</span><span>Score</span><span>Scanned</span></div>
      ${state.history
        .map(
          (item) => `<div class="tool-row">
            <span class="truncate text-slate-100">${escapeHtml(item.url)}</span>
            <span class="${item.verdict === "Dangerous" ? "text-red-400" : item.verdict === "Suspicious" ? "text-orange-400" : "text-emerald-400"}">${escapeHtml(item.verdict)}</span>
            <span class="font-mono">${item.score}/100</span>
            <span class="text-slate-400">${escapeHtml(formatDateTime(item.scannedAt))}</span>
          </div>`
        )
        .join("")}
    </div>`;
}

function renderBulkSection() {
  els.featureKicker.textContent = "Batch URL checking";
  els.featureTitle.textContent = "Bulk Scan";
  els.featureAction.textContent = "Run Bulk Scan";
  els.featureAction.classList.remove("hidden");
  els.featureBody.innerHTML = `
    <div class="grid grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)] gap-5">
      <div>
        <label class="mb-2 block text-slate-400">Paste one URL per line</label>
        <textarea id="bulkInput" class="tool-textarea" placeholder="https://example.com&#10;http://paypal-login-verify-account.example.xyz/signin"></textarea>
      </div>
      <div>
        <div class="mb-2 text-slate-400">Bulk results</div>
        <div id="bulkResults" class="tool-table mt-0"><div class="empty-row">No bulk scan run yet.</div></div>
      </div>
    </div>`;
  els.featureAction.onclick = runBulkScan;
}

async function runBulkScan() {
  const input = $("#bulkInput");
  const resultBox = $("#bulkResults");
  const urls = input.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean).slice(0, 25);
  if (!urls.length) {
    resultBox.innerHTML = `<div class="empty-row">Add at least one URL.</div>`;
    return;
  }
  els.featureAction.disabled = true;
  els.featureAction.textContent = "Scanning...";
  const rows = [];
  for (const url of urls) {
    const report = await window.detector.scanUrl({ url, fetchSite: false });
    addHistory(report);
    rows.push(report);
    resultBox.innerHTML = renderBulkRows(rows);
  }
  els.featureAction.disabled = false;
  els.featureAction.textContent = "Run Bulk Scan";
}

function renderBulkRows(reports) {
  return `
    <div class="tool-head"><span>URL</span><span>Verdict</span><span>Score</span><span>Top finding</span></div>
    ${reports
      .map(
        (report) => `<div class="tool-row">
          <span class="truncate text-slate-100">${escapeHtml(report.normalizedUrl)}</span>
          <span class="${report.verdict === "Dangerous" ? "text-red-400" : report.verdict === "Suspicious" ? "text-orange-400" : "text-emerald-400"}">${escapeHtml(report.verdict)}</span>
          <span class="font-mono">${report.riskScore}/100</span>
          <span class="truncate text-slate-400">${escapeHtml(report.findings[0]?.title || "No notable finding")}</span>
        </div>`
      )
      .join("")}`;
}

function renderDomainSection() {
  els.featureKicker.textContent = "Domain registration";
  els.featureTitle.textContent = "Domain WHOIS";
  els.featureAction.textContent = "Lookup WHOIS";
  els.featureAction.classList.remove("hidden");
  const current = state.report?.domain || extractHost(els.urlInput.value) || "";
  els.featureBody.innerHTML = `
    <div class="flex gap-3">
      <input id="domainInput" class="tool-input" placeholder="example.com" value="${escapeHtml(current)}" />
      <button id="domainLookupButton" class="feature-action">Lookup</button>
    </div>
    <div id="domainResult" class="mt-5">${state.report ? renderWhoisDetailsHtml(state.report.whois || {}) : `<div class="tool-card">Run a WHOIS lookup to see clean registration details.</div>`}</div>`;
  els.featureAction.onclick = runDomainLookup;
  $("#domainLookupButton").addEventListener("click", runDomainLookup);
}

async function runDomainLookup() {
  const domain = $("#domainInput")?.value.trim();
  if (!domain) return;
  const result = $("#domainResult");
  result.innerHTML = `<div class="tool-card">Looking up WHOIS and DNS details...</div>`;
  try {
    const report = await window.detector.scanUrl({ url: domain, fetchSite: false });
    state.report = report;
    addHistory(report);
    renderWhois(report.whois || {});
    result.innerHTML = renderWhoisDetailsHtml(report.whois || {});
  } catch (error) {
    result.innerHTML = `<div class="tool-card"><span>Lookup failed</span><strong>${escapeHtml(error.message || "WHOIS lookup failed")}</strong></div>`;
  }
}

function renderThreatSection() {
  els.featureKicker.textContent = "Security intelligence";
  els.featureTitle.textContent = "Threat Intelligence";
  els.featureAction.textContent = "Evaluate Model";
  els.featureAction.classList.remove("hidden");
  els.featureAction.onclick = () => runModelEvaluation(els.featureAction);
  const rows = state.report ? buildAnalysisRows(state.report) : [];
  const local = state.report?.localIntelligence || {};
  const status = state.threatStatus || {};
  els.featureBody.innerHTML = `
    <div class="tool-grid">
      <div class="tool-card"><span>Current verdict</span><strong>${escapeHtml(state.report?.verdict || "No scan")}</strong></div>
      <div class="tool-card"><span>Risk score</span><strong>${state.report?.riskScore ?? "--"}/100</strong></div>
      <div class="tool-card"><span>Local model</span><strong>${state.report?.localIntelligence ? `${state.report.localIntelligence.trainedModelScore}/100` : "No scan"}</strong></div>
      <div class="tool-card"><span>Local database</span><strong>${escapeHtml(localBlocklistLabel(state.report))}</strong></div>
      <div class="tool-card"><span>Confidence</span><strong>${escapeHtml(local.confidence || "No scan")}</strong></div>
      <div class="tool-card"><span>Evaluation</span><strong>${escapeHtml(evaluationStatusSummary())}</strong></div>
    </div>
    <div class="mt-4 grid grid-cols-2 gap-4">
      <div class="tool-card long-card"><span>Top trained indicators</span><strong>${escapeHtml(localFeatureSummary(state.report))}</strong></div>
      <div class="tool-card long-card"><span>Exact threat feed hit</span><strong>${escapeHtml(feedMatchSummary(local.feedMatches || []))}</strong></div>
      <div class="tool-card long-card"><span>Model scores</span><strong>${escapeHtml(modelScoreSummary(local.modelScores || []))}</strong></div>
      <div class="tool-card long-card"><span>Database version</span><strong>${escapeHtml(local.databaseVersion || status.databaseVersion || "Not loaded")}</strong></div>
      <div class="tool-card long-card"><span>Database counts</span><strong>${escapeHtml(databaseCountSummary(local.counts || status.counts || {}))}</strong></div>
      <div class="tool-card long-card"><span>Evidence priority</span><strong>${escapeHtml(local.evidencePriority || "No scan")}</strong></div>
      <div class="tool-card long-card"><span>Inference time</span><strong>${escapeHtml(state.report?.performance?.inferenceMs !== undefined ? `${state.report.performance.inferenceMs} ms` : "No scan")}</strong></div>
    </div>
    ${renderEvaluationSummary()}
    <div class="tool-table">
      <div class="tool-head"><span>Indicator</span><span>Severity</span><span>Score</span><span>Meaning</span></div>
      ${(rows.length ? rows : [{ indicator: "No scan yet", severity: "Low", result: "Run a scan to populate intelligence." }])
        .map(
          (row) => `<div class="tool-row">
            <span class="text-slate-100">${escapeHtml(row.indicator)}</span>
            <span class="${resultClass(row.severity)}">${escapeHtml(row.severity)}</span>
            <span>${row.severity === "High" ? "Critical" : row.severity === "Medium" ? "Watch" : "Normal"}</span>
            <span class="text-slate-400">${escapeHtml(row.result)}</span>
          </div>`
        )
        .join("")}
    </div>`;
}

function renderSettingsSection() {
  els.featureKicker.textContent = "Preferences";
  els.featureTitle.textContent = "Settings";
  const status = state.threatStatus || {};
  els.featureBody.innerHTML = `
    <div class="space-y-3">
      <label class="settings-row"><span><strong class="block text-white">Scan website content</strong><small class="text-slate-400">Fetch page signals during single URL scans.</small></span><input id="settingsFetch" type="checkbox" ${els.fetchSite.checked ? "checked" : ""} /></label>
      <label class="settings-row"><span><strong class="block text-white">Compact sidebar</strong><small class="text-slate-400">Collapse or expand the navigation rail.</small></span><input id="settingsMenu" type="checkbox" ${$(".app-shell").classList.contains("sidebar-collapsed") ? "checked" : ""} /></label>
      <div class="settings-row items-start">
        <span><strong class="block text-white">Local threat database</strong><small class="text-slate-400">${escapeHtml(databaseStatusSummary(status))}</small></span>
        <button id="refreshThreatDb" class="feature-action">Refresh</button>
      </div>
      <div class="settings-row items-start">
        <span><strong class="block text-white">Accuracy evaluation</strong><small class="text-slate-400">${escapeHtml(evaluationStatusSummary())}</small></span>
        <button id="evaluateThreatModel" class="feature-action">Run Evaluation</button>
      </div>
      <div id="databaseRefreshResult" class="tool-card">${escapeHtml(refreshFailureSummary(status))}</div>
      <div id="evaluationResult" class="tool-card">${escapeHtml(evaluationStatusSummary())}</div>
      ${renderEvaluationSummary()}
    </div>`;
  $("#settingsFetch").addEventListener("change", (event) => {
    els.fetchSite.checked = event.target.checked;
  });
  $("#settingsMenu").addEventListener("change", (event) => {
    $(".app-shell").classList.toggle("sidebar-collapsed", event.target.checked);
  });
  $("#refreshThreatDb").addEventListener("click", refreshThreatDatabase);
  $("#evaluateThreatModel").addEventListener("click", (event) => runModelEvaluation(event.currentTarget));
}

async function refreshThreatDatabase() {
  const button = $("#refreshThreatDb");
  const result = $("#databaseRefreshResult");
  button.disabled = true;
  button.textContent = "Refreshing...";
  result.textContent = "Downloading enabled feeds and rebuilding compact local indexes.";
  try {
    state.threatStatus = await window.detector.refreshThreatDatabase();
    result.textContent = databaseStatusSummary(state.threatStatus);
  } catch (error) {
    result.textContent = `Refresh failed: ${error.message || "Unknown error"}`;
  } finally {
    button.disabled = false;
    button.textContent = "Refresh";
    if (state.activeSection === "settings") renderSettingsSection();
  }
}

async function runModelEvaluation(button = els.featureAction) {
  const result = $("#evaluationResult");
  button.disabled = true;
  button.textContent = "Evaluating...";
  if (result) result.textContent = "Running fast local accuracy evaluation...";
  try {
    state.evaluation = await window.detector.evaluateThreatModel();
    if (state.activeSection === "settings" || state.activeSection === "threat") renderFeatureSection(state.activeSection);
  } catch (error) {
    state.evaluation = { error: error.message || "Evaluation failed" };
    if (state.activeSection === "settings" || state.activeSection === "threat") renderFeatureSection(state.activeSection);
  } finally {
    button.disabled = false;
    button.textContent = button.id === "evaluateThreatModel" ? "Run Evaluation" : "Evaluate Model";
  }
}

function renderAboutSection() {
  els.featureKicker.textContent = "Product information";
  els.featureTitle.textContent = "About Us";
  els.featureBody.innerHTML = `
    <div class="tool-grid">
      <div class="tool-card"><span>Application</span><strong>Phishing URL Detector</strong></div>
      <div class="tool-card"><span>Version</span><strong>2.0.0</strong></div>
      <div class="tool-card"><span>Platform</span><strong>Windows Desktop</strong></div>
      <div class="tool-card"><span>Company</span><strong>Advaitik Intelligence</strong></div>
      <div class="tool-card"><span>Instagram</span><strong>@advaitik_intelligence</strong></div>
      <div class="tool-card"><span>Brand</span><strong>Made by Advaitik Intelligence</strong></div>
    </div>
    <button id="aboutInstagramButton" class="instagram-panel-button mt-5" type="button">
      <span data-icon="instagram"></span>
      Open Instagram @advaitik_intelligence
    </button>
    <div class="mt-5 rounded-xl border border-slate-500/25 bg-slate-900/45 p-5 leading-7">
      This software checks URL structure, DNS, TLS, website content signals, WHOIS data, local threat feeds, and trained dataset intelligence.
      No detector can guarantee 100 percent accuracy against every new or cloaked phishing campaign, so the app shows explainable evidence for every verdict.
    </div>`;
  $("#aboutInstagramButton").addEventListener("click", () => window.detector.openExternal(instagramUrl));
}

function toggleMenu() {
  $(".app-shell").classList.toggle("sidebar-collapsed");
  if (state.activeSection === "settings") renderSettingsSection();
}

function renderReport(report) {
  const score = report.riskScore ?? 0;
  els.verdictText.textContent = report.verdict;
  els.riskScore.textContent = score;
  els.riskLabel.textContent = riskLabel(report.verdict);
  els.summaryText.textContent = report.summary;
  els.rawReport.textContent = JSON.stringify(report, null, 2);
  styleOrb(report.verdict);
  renderFindings(buildAnalysisRows(report));
  renderWhois(report.whois || {});
}

function buildAnalysisRows(report) {
  const highCount = report.findings.filter((finding) => finding.severity === "High").length;
  const mediumCount = report.findings.filter((finding) => finding.severity === "Medium").length;
  const tlsValid = report.tls?.valid === true;
  const urlStructure = report.findings.find((finding) =>
    ["No HTTPS", "Userinfo trick", "Very long URL", "Many subdomains", "IP address host", "Punycode domain", "Risky top-level domain", "Possible brand impersonation"].includes(finding.title)
  );
  const contentRisk = report.findings.find((finding) =>
    ["Password form detected", "Complex form collection", "External form submission", "Blank credential form target", "Mostly external links", "Many external scripts", "Iframe usage"].includes(finding.title)
  );
  const local = report.localIntelligence || {};
  const localBlocklist = local.blocklistMatch || { status: "none" };
  const localHigh = localBlocklist.status === "active" || local.trainedModelScore >= 65;
  const localMedium = localBlocklist.status === "historical" || local.trainedModelScore >= 35;

  return [
    {
      icon: "◇",
      indicator: "Phishing Threat",
      result: highCount ? "Detected - phishing patterns found" : "No major phishing pattern detected",
      severity: highCount ? "High" : "Low"
    },
    {
      icon: "◇",
      indicator: "Domain Reputation",
      result: report.whois?.domainAgeDays !== null && report.whois?.domainAgeDays !== undefined && report.whois.domainAgeDays < 180
        ? "Poor reputation score"
        : "No age-based reputation warning",
      severity: report.whois?.domainAgeDays !== null && report.whois?.domainAgeDays !== undefined && report.whois.domainAgeDays < 180 ? "High" : "Low"
    },
    {
      icon: "▣",
      indicator: "SSL Certificate",
      result: tlsValid ? "Valid SSL certificate detected" : "SSL certificate issue detected",
      severity: tlsValid ? "Low" : "High"
    },
    {
      icon: "⌁",
      indicator: "URL Structure",
      result: urlStructure ? "Contains suspicious elements" : "URL structure looks normal",
      severity: urlStructure ? (mediumCount ? "Medium" : "High") : "Low"
    },
    {
      icon: "⊘",
      indicator: "Blacklist Status",
      result: localBlocklist.status === "active"
        ? `Active local ${localBlocklist.type} match`
        : localBlocklist.status === "historical"
          ? `Historical local ${localBlocklist.type} match`
          : "No local blocklist match",
      severity: localBlocklist.status === "active" ? "High" : localBlocklist.status === "historical" ? "Medium" : "Low"
    },
    {
      icon: "Σ",
      indicator: "Trained Dataset Model",
      result: local.matchedFeatures?.length
        ? `${local.trainedModelScore}/100 score from ${local.matchedFeatures.length} learned indicators`
        : "No trained dataset risk pattern",
      severity: localHigh ? "High" : localMedium ? "Medium" : "Low"
    },
    {
      icon: "▧",
      indicator: "Content Analysis",
      result: contentRisk ? "Matches credential harvesting patterns" : "No credential form warning",
      severity: contentRisk ? "High" : "Low"
    }
  ];
}

function renderFindings(rows) {
  els.findingsBody.innerHTML = rows
    .map(
      (row) => `<div class="analysis-row">
        <div class="analysis-indicator"><i class="${row.severity === "High" ? "text-red-400" : row.severity === "Medium" ? "text-orange-400" : "text-emerald-400"}">${row.icon}</i>${escapeHtml(row.indicator)}</div>
        <div class="${resultClass(row.severity)}">${escapeHtml(row.result)}</div>
        <div><span class="severity-pill ${severityClass(row.severity)}">${escapeHtml(row.severity)}</span></div>
      </div>`
    )
    .join("");
}

function renderWhois(whois) {
  const nameservers = whois.nameservers?.length ? whois.nameservers.slice(0, 3).map(cleanWhoisValue).join("\n") : "Not provided";
  const status = whois.status?.length ? whois.status.slice(0, 4).map(cleanWhoisValue).join("\n") : "Not provided";
  const ipv4 = whois.ipv4?.length ? whois.ipv4.slice(0, 3).join("\n") : "Not provided";
  const ipv6 = whois.ipv6?.length ? whois.ipv6.slice(0, 2).join("\n") : "";
  const domainAge = whois.domainAgeDays === null || whois.domainAgeDays === undefined ? "Not provided" : `${whois.domainAgeDays} days`;
  const cards = [
    { icon: "▥", label: "Registrar", value: whois.registrar || "Not provided" },
    { icon: "▣", label: "Domain Age", value: domainAge },
    { icon: "▣", label: "Creation Date", value: formatWhoisDate(whois.created) },
    { icon: "▣", label: "Expiry Date", value: expiryValue(whois.expires) },
    { icon: "▤", label: "Nameservers", value: nameservers },
    { icon: "◇", label: "Status", value: status },
    { icon: "⌁", label: "Resolved IPs", value: ipv6 ? `${ipv4}\n${ipv6}` : ipv4, wide: true }
  ];
  els.whoisCards.innerHTML = cards
    .map(
      (card) => `<div class="whois-card-ref ${card.wide ? "wide" : ""}">
        <span class="whois-icon">${card.icon}</span>
        <div><span>${escapeHtml(card.label)}</span><strong>${escapeHtml(card.value)}</strong></div>
      </div>`
    )
    .join("");
}

function renderEmptyWhois() {
  renderWhois({
    registrar: "Run scan",
    domainAgeDays: null,
    created: null,
    expires: null,
    nameservers: [],
    status: []
  });
}

function addHistory(report) {
  const item = {
    url: report.normalizedUrl,
    verdict: report.verdict,
    score: report.riskScore,
    scannedAt: report.scannedAt
  };
  state.history = [item, ...state.history.filter((entry) => entry.url !== item.url)].slice(0, 100);
  saveHistory();
}

function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem("scanHistory") || "[]");
  } catch {
    return [];
  }
}

function saveHistory() {
  localStorage.setItem("scanHistory", JSON.stringify(state.history));
}

function renderWhoisDetailsHtml(whois) {
  const nameservers = whois.nameservers?.length ? whois.nameservers.slice(0, 8).map(cleanWhoisValue).join("\n") : "Not provided";
  const status = whois.status?.length ? whois.status.slice(0, 8).map(cleanWhoisValue).join("\n") : "Not provided";
  const ipv4 = whois.ipv4?.length ? whois.ipv4.join("\n") : "Not provided";
  const ipv6 = whois.ipv6?.length ? whois.ipv6.join("\n") : "Not provided";
  const registrant = [
    whois.registrantOrganization,
    whois.registrantStateProvince,
    whois.registrantCountry
  ].filter((value) => value && value !== "Not provided").join("\n") || "Privacy protected or not provided";
  const contacts = [
    ["Abuse Email", whois.registrarAbuseContactEmail],
    ["Abuse Phone", whois.registrarAbuseContactPhone],
    ["Registrant Email", whois.registrantEmail],
    ["Admin Email", whois.adminEmail],
    ["Tech Email", whois.techEmail],
    ["Billing Email", whois.billingEmail]
  ]
    .filter(([, value]) => value && value !== "Not provided")
    .map(([label, value]) => `${label}: ${value}`)
    .join("\n") || "Not provided";
  const network = whois.ipNetwork
    ? [
        ["Network", whois.ipNetwork.name],
        ["Handle", whois.ipNetwork.handle],
        ["Range", `${whois.ipNetwork.startAddress} - ${whois.ipNetwork.endAddress}`],
        ["Country", whois.ipNetwork.country]
      ]
        .filter(([, value]) => value && value !== "Not provided")
        .map(([label, value]) => `${label}: ${value}`)
        .join("\n")
    : "";
  const dataset = state.report?.datasetProfile?.matchedFeatures?.length
    ? state.report.datasetProfile.matchedFeatures.slice(0, 8).map((item) => `${item.feature} (${Math.round(item.phishingRateWhenRisky * 100)}%)`).join("\n")
    : "No database feature match";
  const local = state.report?.localIntelligence;
  const localMatch = local
    ? [
        `Blocklist: ${localBlocklistLabel(state.report)}`,
        `Model score: ${local.trainedModelScore}/100`,
        `Confidence: ${local.confidence}`,
        `Version: ${local.databaseVersion}`,
        localFeatureSummary(state.report)
      ].filter(Boolean).join("\n")
    : dataset;
  return `
    <div class="tool-grid">
      <div class="tool-card"><span>Domain</span><strong>${escapeHtml(whois.domainName || whois.domain || "Not provided")}</strong></div>
      <div class="tool-card"><span>Registrar</span><strong>${escapeHtml(whois.registrar || "Not provided")}</strong></div>
      <div class="tool-card"><span>IANA ID</span><strong>${escapeHtml(whois.registrarIanaId || "Not provided")}</strong></div>
      <div class="tool-card"><span>Created</span><strong>${escapeHtml(formatWhoisDate(whois.created))}</strong></div>
      <div class="tool-card"><span>Expires</span><strong>${escapeHtml(expiryValue(whois.expires))}</strong></div>
      <div class="tool-card"><span>Domain Age</span><strong>${whois.domainAgeDays === null || whois.domainAgeDays === undefined ? "Not provided" : `${whois.domainAgeDays} days`}</strong></div>
      <div class="tool-card"><span>WHOIS Server</span><strong>${escapeHtml(whois.server || "Not provided")}</strong></div>
      <div class="tool-card"><span>Registration</span><strong>${whois.registered === false ? "Not registered" : whois.available === false ? "Unavailable" : "Registered"}</strong></div>
      <div class="tool-card"><span>DNSSEC</span><strong>${escapeHtml(whois.dnsSec || "Not provided")}</strong></div>
    </div>
    <div class="mt-4 grid grid-cols-2 gap-4">
      <div class="tool-card long-card"><span>Name Servers</span><strong>${escapeHtml(nameservers)}</strong></div>
      <div class="tool-card long-card"><span>Domain Status</span><strong>${escapeHtml(status)}</strong></div>
      <div class="tool-card long-card"><span>IPv4 Addresses</span><strong>${escapeHtml(ipv4)}</strong></div>
      <div class="tool-card long-card"><span>IPv6 Addresses</span><strong>${escapeHtml(ipv6)}</strong></div>
      <div class="tool-card long-card"><span>Registrant</span><strong>${escapeHtml(registrant)}</strong></div>
      <div class="tool-card long-card"><span>Contacts</span><strong>${escapeHtml(contacts)}</strong></div>
      ${network ? `<div class="tool-card long-card"><span>IP Network</span><strong>${escapeHtml(network)}</strong></div>` : ""}
      <div class="tool-card long-card"><span>Phishing Intelligence</span><strong>${escapeHtml(localMatch)}</strong></div>
    </div>`;
}

function localBlocklistLabel(report) {
  const match = report?.localIntelligence?.blocklistMatch;
  if (!match || match.status === "none") return "No local hit";
  const source = match.sources?.length ? ` (${match.sources.slice(0, 2).join(", ")})` : "";
  return `${match.status} ${match.type}: ${match.value}${source}`;
}

function localFeatureSummary(report) {
  const features = report?.localIntelligence?.matchedFeatures || [];
  if (!features.length) return "No trained feature match";
  return features
    .slice(0, 8)
    .map((item) => `${item.dataset}: ${item.feature} (${Math.round((item.phishingRate || 0) * 100)}%)`)
    .join("\n");
}

function feedMatchSummary(matches) {
  if (!matches.length) return "No exact local feed hit";
  return matches
    .slice(0, 5)
    .map((match) => `${match.status} ${match.type}: ${match.value}\n${(match.sources || []).join(", ") || match.dataset}`)
    .join("\n\n");
}

function modelScoreSummary(modelScores) {
  if (!modelScores.length) return "No model score available";
  return modelScores
    .slice(0, 4)
    .map((item) => `${item.dataset}: ${item.score}/100 (${item.matchedFeatureCount || 0} indicators)`)
    .join("\n");
}

function databaseCountSummary(counts) {
  const labels = [
    ["activeUrlHashes", "active URLs"],
    ["activeDomains", "active domains"],
    ["activeIps", "active IPs"],
    ["historicalUrlHashes", "historical URLs"],
    ["historicalDomains", "historical domains"],
    ["historicalIps", "historical IPs"]
  ];
  const summary = labels
    .filter(([key]) => counts[key] !== undefined)
    .map(([key, label]) => `${Number(counts[key] || 0).toLocaleString("en-US")} ${label}`)
    .join("\n");
  return summary || "No database counts loaded";
}

function databaseStatusSummary(status) {
  if (!status?.databaseVersion) return "Local threat intelligence has not loaded yet.";
  const refreshed = status.generatedAt ? formatDateTime(status.generatedAt) : "unknown time";
  return `${status.databaseVersion} refreshed ${refreshed}\n${databaseCountSummary(status.counts || {})}`;
}

function refreshFailureSummary(status) {
  const failures = status?.refreshFailures || [];
  if (!status?.databaseVersion) return "Refresh status will appear here.";
  if (!failures.length) return "All enabled local and remote threat sources refreshed without recorded failures.";
  return failures.slice(0, 6).map((item) => `${item.source}: ${item.message}`).join("\n");
}

function evaluationStatusSummary() {
  if (!state.evaluation) return "Runs a conservative precision, recall, F1, false-positive, and inference timing check.";
  if (state.evaluation.error) return state.evaluation.error;
  const metrics = state.evaluation.metrics || {};
  return `Precision ${percent(metrics.precision)}, recall ${percent(metrics.recall)}, F1 ${percent(metrics.f1)}, FPR ${percent(metrics.falsePositiveRate)}`;
}

function renderEvaluationSummary() {
  if (!state.evaluation) return "";
  if (state.evaluation.error) {
    return `<div class="mt-4 tool-card"><span>Evaluation</span><strong>${escapeHtml(state.evaluation.error)}</strong></div>`;
  }
  const metrics = state.evaluation.metrics || {};
  return `
    <div class="mt-4 tool-grid">
      <div class="tool-card"><span>Precision</span><strong>${percent(metrics.precision)}</strong></div>
      <div class="tool-card"><span>Recall</span><strong>${percent(metrics.recall)}</strong></div>
      <div class="tool-card"><span>F1 score</span><strong>${percent(metrics.f1)}</strong></div>
      <div class="tool-card"><span>False positive rate</span><strong>${percent(metrics.falsePositiveRate)}</strong></div>
      <div class="tool-card"><span>ROC-AUC approx</span><strong>${percent(metrics.rocAucApproximation)}</strong></div>
      <div class="tool-card"><span>Average inference</span><strong>${escapeHtml(metrics.averageInferenceMs ?? "--")} ms</strong></div>
    </div>`;
}

function percent(value) {
  return Number.isFinite(value) ? `${Math.round(value * 1000) / 10}%` : "--";
}

function extractHost(value) {
  try {
    const input = String(value || "").trim();
    if (!input) return "";
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`).hostname;
  } catch {
    return "";
  }
}

function formatDateTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value || "") : date.toLocaleString();
}

async function exportReport(format) {
  if (!state.report) return;
  const result = await window.detector.exportReport({ format, report: state.report });
  if (!result.canceled && format === "html") window.detector.openPath(result.filePath);
}

function styleOrb(verdict) {
  els.riskOrb.classList.remove("safe-orb", "suspicious-orb");
  if (verdict === "Safe") els.riskOrb.classList.add("safe-orb");
  if (verdict === "Suspicious") els.riskOrb.classList.add("suspicious-orb");
}

function setBusy(isBusy) {
  els.scanButton.disabled = isBusy;
  els.scanButton.innerHTML = isBusy ? `<span data-icon="target"></span> Scanning...` : `<span data-icon="target"></span> Scan URL`;
  els.riskOrb.classList.toggle("loading", isBusy);
}

function riskLabel(verdict) {
  if (verdict === "Dangerous") return "High Risk";
  if (verdict === "Suspicious") return "Medium Risk";
  if (verdict === "Safe") return "Low Risk";
  return "Not scanned";
}

function resultClass(severity) {
  if (severity === "High") return "result-high";
  if (severity === "Medium") return "result-medium";
  return "result-low";
}

function severityClass(severity) {
  if (severity === "High") return "severity-high";
  if (severity === "Medium") return "severity-medium";
  return "severity-low";
}

function cleanWhoisValue(value) {
  return String(value || "").replace(/\s*https?:\/\/\S+/g, "").trim();
}

function expiryValue(value) {
  const formatted = formatWhoisDate(value);
  if (formatted === "Not provided") return formatted;
  const date = parseDate(value);
  if (!date) return formatted;
  const days = Math.floor((date.getTime() - Date.now()) / 86_400_000);
  return days > 0 ? `${formatted} (in ${days} days)` : formatted;
}

function formatWhoisDate(value) {
  if (!value || value === "Not provided") return "Not provided";
  const date = parseDate(value);
  if (!date) return cleanWhoisValue(value);
  return date.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function parseDate(value) {
  const iso = String(value).match(/\d{4}-\d{2}-\d{2}/)?.[0];
  const date = new Date(iso ? `${iso}T00:00:00Z` : value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
