const { app, BrowserWindow, ipcMain } = require("electron");
const fs = require("node:fs");
const path = require("node:path");
const { scanUrl } = require("../src/main/scanner");
const { getLocalIntelligenceStatus } = require("../src/main/local-intelligence");

const outDir = path.join(process.cwd(), "qa");
const outPath = path.join(outDir, "electron-ui.png");

ipcMain.handle("scan:url", async (_event, payload) => scanUrl(payload.url, { fetchSite: payload.fetchSite !== false }));
ipcMain.handle("threat:status", async () => getLocalIntelligenceStatus());
ipcMain.handle("threat:refresh", async () => getLocalIntelligenceStatus());
ipcMain.handle("threat:evaluate", async () => ({
  metrics: { precision: 1, recall: 1, f1: 1, falsePositiveRate: 0, rocAucApproximation: 1, averageInferenceMs: 1 },
  samples: []
}));
ipcMain.handle("report:export", async () => ({ canceled: true }));
ipcMain.handle("shell:openPath", async () => "");
ipcMain.handle("shell:openExternal", async () => "");

app.whenReady().then(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const win = new BrowserWindow({
    width: 1440,
    height: 920,
    show: false,
    backgroundColor: "#050711",
    webPreferences: {
      preload: path.join(process.cwd(), "src", "preload.js"),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  await win.loadFile(path.join(process.cwd(), "src", "renderer", "index.html"));
  await win.webContents.executeJavaScript(`
    const seededReport = {
      inputUrl: "http://paypal-login-verify-account.example.xyz/signin?session=abc",
      normalizedUrl: "http://paypal-login-verify-account.example.xyz/signin?session=abc",
      scannedAt: new Date().toISOString(),
      verdict: "Dangerous",
      riskScore: 92,
      summary: "Multiple strong phishing and trust-risk signals were detected. Do not enter credentials or payment details.",
      finalUrl: null,
      domain: "paypal-login-verify-account.example.xyz",
      ipAddresses: [],
      tls: { valid: false, error: "TLS certificate or connection failed" },
      http: { error: "Website scan skipped in visual QA seed" },
      whois: {
        available: true,
        server: "whois.example",
        registrar: "Example Registrar LLC",
        created: "2026-05-18T10:12:00Z",
        updated: "2026-05-20T09:00:00Z",
        expires: "2027-05-18T10:12:00Z",
        domainAgeDays: 9,
        nameservers: ["ns1.example-dns.com", "ns2.example-dns.com"],
        status: ["clientTransferProhibited", "serverHold"]
      },
      pageSignals: { forms: 2, passwordInputs: 1, hiddenInputs: 7 },
      findings: [
        { severity: "High", title: "No HTTPS", detail: "The URL does not use HTTPS.", points: 25 },
        { severity: "High", title: "Possible brand impersonation", detail: "The host contains 'paypal' but is not the primary domain.", points: 22 },
        { severity: "High", title: "Password form detected", detail: "The page asks for a password or credential input.", points: 22 },
        { severity: "Medium", title: "Recently registered domain", detail: "WHOIS suggests the domain is 9 days old.", points: 13 },
        { severity: "Low", title: "Risky top-level domain", detail: ".xyz is frequently abused in phishing campaigns.", points: 7 }
      ]
    };
    document.querySelector("#urlInput").value = seededReport.normalizedUrl;
    state.report = seededReport;
    renderReport(seededReport);
  `);
  await new Promise((resolve) => setTimeout(resolve, 900));
  const image = await win.webContents.capturePage();
  fs.writeFileSync(outPath, image.toPNG());
  await app.quit();
});
