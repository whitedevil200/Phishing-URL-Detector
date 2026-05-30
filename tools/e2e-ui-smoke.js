const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("node:path");
const { scanUrl } = require("../src/main/scanner");
const { getLocalIntelligenceStatus } = require("../src/main/local-intelligence");

ipcMain.handle("scan:url", async (_event, payload) => scanUrl(payload.url, { fetchSite: payload.fetchSite !== false, timeoutMs: 5000 }));
ipcMain.handle("threat:status", async () => getLocalIntelligenceStatus());
ipcMain.handle("threat:refresh", async () => getLocalIntelligenceStatus());
ipcMain.handle("threat:evaluate", async () => ({
  metrics: { precision: 1, recall: 1, f1: 1, falsePositiveRate: 0, rocAucApproximation: 1, averageInferenceMs: 1 },
  samples: []
}));
ipcMain.handle("report:export", async () => ({ canceled: true }));
ipcMain.handle("shell:openPath", async () => "");
ipcMain.handle("shell:openExternal", async () => "");
ipcMain.on("window:minimize", () => {});
ipcMain.on("window:maximize", () => {});
ipcMain.on("window:close", () => {});

app.whenReady().then(async () => {
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
  const result = await win.webContents.executeJavaScript(`
    new Promise((resolve, reject) => {
      const input = document.querySelector("#urlInput");
      const fetchSite = document.querySelector("#fetchSite");
      const scan = document.querySelector("#scanButton");
      input.value = "http://paypal-login-verify-account.example.xyz/signin?session=abc";
      fetchSite.checked = false;
      scan.click();
      const started = Date.now();
      const timer = setInterval(() => {
        const verdict = document.querySelector("#verdictText").textContent;
        const score = Number(document.querySelector("#riskScore").textContent);
        const rows = document.querySelectorAll(".analysis-row").length;
        if (verdict === "Dangerous" && score >= 65 && rows >= 6) {
          clearInterval(timer);
          const expected = {
            history: "URL Scan History",
            bulk: "Bulk Scan",
            domain: "Domain WHOIS",
            threat: "Threat Intelligence",
            settings: "Settings",
            about: "About Us"
          };
          const seen = {};
          for (const [section, title] of Object.entries(expected)) {
            document.querySelector('[data-section="' + section + '"]').click();
            seen[section] = document.querySelector("#featureTitle").textContent;
            if (seen[section] !== title) {
              reject(new Error("Section failed: " + section + " -> " + seen[section]));
              return;
            }
          }
          if (document.body.textContent.includes(["Virus", "Total"].join(""))) {
            reject(new Error("External reputation UI should be removed"));
            return;
          }
          document.querySelector('[data-section="settings"]').click();
          if (document.querySelector("#refreshThreatDb").textContent.trim() !== "Refresh") {
            reject(new Error("Refresh button label is incorrect"));
            return;
          }
          document.querySelector("#evaluateThreatModel").click();
          const hasThemeButton = Boolean(document.querySelector("#themeButton"));
          const hasLightMode = document.body.classList.contains("light-mode");
          if (hasThemeButton || hasLightMode) {
            reject(new Error("Light mode controls should be removed"));
            return;
          }
          document.querySelector("#menuButton").click();
          const collapsed = document.querySelector(".app-shell").classList.contains("sidebar-collapsed");
          document.querySelector('[data-section="dashboard"]').click();
          const dashboardVisible = !document.querySelector("#dashboardPanel").classList.contains("hidden");
          resolve({ verdict, score, rows, hasThemeButton, hasLightMode, collapsed, dashboardVisible });
        }
        if (Date.now() - started > 15000) {
          clearInterval(timer);
          reject(new Error("UI scan workflow timed out"));
        }
      }, 250);
    })
  `);
  console.log(JSON.stringify(result));
  await app.quit();
});
