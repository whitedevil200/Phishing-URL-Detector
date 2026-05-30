const { app, BrowserWindow, dialog, ipcMain, shell } = require("electron");
const path = require("node:path");
const { exportReport, scanUrl } = require("./scanner");
const { buildLocalIntelligence } = require("./threat-intelligence-builder");
const { configureLocalIntelligence, getLocalIntelligenceStatus, reloadLocalIntelligence } = require("./local-intelligence");
const { evaluateThreatModel } = require("./evaluator");

let mainWindow;
let threatDataDir;
let threatConfigPath;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1240,
    height: 820,
    minWidth: 1040,
    minHeight: 700,
    frame: false,
    backgroundColor: "#050711",
    title: "Phishing URL Detector",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "..", "preload.js"),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, "..", "renderer", "index.html"));
}

app.whenReady().then(() => {
  threatDataDir = path.join(app.getPath("userData"), "threat-intelligence");
  threatConfigPath = app.isPackaged
    ? path.join(process.resourcesPath, "config", "threat-feeds.json")
    : path.join(__dirname, "..", "..", "config", "threat-feeds.json");
  configureLocalIntelligence({ dataDirs: [threatDataDir, path.join(__dirname, "..", "data")] });
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

ipcMain.handle("scan:url", async (_event, payload) => {
  return scanUrl(payload.url, { fetchSite: payload.fetchSite !== false });
});

ipcMain.handle("threat:status", async () => {
  return getLocalIntelligenceStatus();
});

ipcMain.handle("threat:refresh", async () => {
  const result = await buildLocalIntelligence({
    outputDir: threatDataDir,
    configPath: threatConfigPath
  });
  reloadLocalIntelligence();
  return {
    ...getLocalIntelligenceStatus(),
    build: result
  };
});

ipcMain.handle("threat:evaluate", async () => {
  return evaluateThreatModel();
});

ipcMain.handle("report:export", async (_event, payload) => {
  const extension = payload.format === "json" ? "json" : "html";
  const result = await dialog.showSaveDialog(mainWindow, {
    title: `Export ${extension.toUpperCase()} report`,
    defaultPath: `phishing-url-report.${extension}`,
    filters: [{ name: `${extension.toUpperCase()} report`, extensions: [extension] }]
  });
  if (result.canceled || !result.filePath) return { canceled: true };
  exportReport(payload.report, result.filePath, extension);
  return { canceled: false, filePath: result.filePath };
});

ipcMain.handle("shell:openPath", async (_event, filePath) => {
  return shell.openPath(filePath);
});

ipcMain.handle("shell:openExternal", async (_event, url) => {
  return shell.openExternal(url);
});

ipcMain.on("window:minimize", () => {
  BrowserWindow.getFocusedWindow()?.minimize();
});

ipcMain.on("window:maximize", () => {
  const win = BrowserWindow.getFocusedWindow();
  if (!win) return;
  if (win.isMaximized()) win.unmaximize();
  else win.maximize();
});

ipcMain.on("window:close", () => {
  BrowserWindow.getFocusedWindow()?.close();
});
