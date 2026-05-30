const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("detector", {
  scanUrl: (payload) => ipcRenderer.invoke("scan:url", payload),
  threatStatus: () => ipcRenderer.invoke("threat:status"),
  refreshThreatDatabase: () => ipcRenderer.invoke("threat:refresh"),
  evaluateThreatModel: () => ipcRenderer.invoke("threat:evaluate"),
  exportReport: (payload) => ipcRenderer.invoke("report:export", payload),
  openPath: (filePath) => ipcRenderer.invoke("shell:openPath", filePath),
  openExternal: (url) => ipcRenderer.invoke("shell:openExternal", url),
  minimize: () => ipcRenderer.send("window:minimize"),
  maximize: () => ipcRenderer.send("window:maximize"),
  close: () => ipcRenderer.send("window:close")
});
