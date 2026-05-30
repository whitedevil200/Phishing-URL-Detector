const { app, BrowserWindow, ipcMain } = require("electron");
const fs = require("node:fs");
const path = require("node:path");
const { scanUrl } = require("../src/main/scanner");
const { getLocalIntelligenceStatus } = require("../src/main/local-intelligence");

const outDir = path.join(process.cwd(), "qa");
const outPath = path.join(outDir, "whois-ui.png");

ipcMain.handle("scan:url", async (_event, payload) => scanUrl(payload.url, { fetchSite: payload.fetchSite !== false, timeoutMs: 12000 }));
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
  const result = await win.webContents.executeJavaScript(`
    new Promise((resolve, reject) => {
      document.querySelector('[data-section="domain"]').click();
      const input = document.querySelector("#domainInput");
      input.value = "google.com";
      document.querySelector("#domainLookupButton").click();
      const started = Date.now();
      const timer = setInterval(() => {
        const text = document.querySelector("#domainResult").textContent;
        if (text.includes("MarkMonitor") && text.includes("Registered") && text.includes("NS1.GOOGLE.COM")) {
          clearInterval(timer);
          setTimeout(() => resolve({
            hasRegistrar: text.includes("MarkMonitor"),
            hasRegistered: text.includes("Registered"),
            hasNameserver: text.includes("NS1.GOOGLE.COM"),
            text: text.slice(0, 800)
          }), 1000);
        }
        if (Date.now() - started > 22000) {
          clearInterval(timer);
          reject(new Error("WHOIS UI workflow timed out: " + text.slice(0, 500)));
        }
      }, 300);
    })
  `);
  const image = await win.webContents.capturePage();
  fs.writeFileSync(outPath, image.toPNG());
  console.log(JSON.stringify({ ...result, screenshot: outPath }));
  await app.quit();
}).catch(async (error) => {
  console.error(error);
  await app.quit();
  process.exit(1);
});
