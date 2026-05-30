from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .scanner import UrlReport, export_html, export_json, scan_url


APP_TITLE = "Phishing URL Detector"
APP_BG = "#eef2f7"
SURFACE = "#ffffff"
TEXT = "#172033"
MUTED = "#667085"
PRIMARY = "#2563eb"
DANGER = "#dc2626"
WARN = "#d97706"
SAFE = "#16a34a"


class DetectorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1120x760")
        self.minsize(940, 650)
        self.configure(bg=APP_BG)

        self._queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._current_report: UrlReport | None = None
        self._scanning = False

        self._configure_style()
        self._build_ui()
        self._poll_queue()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=APP_BG)
        style.configure("Surface.TFrame", background=SURFACE)
        style.configure("TLabel", background=APP_BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=SURFACE, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=APP_BG, foreground=TEXT, font=("Segoe UI Semibold", 22))
        style.configure("Subtitle.TLabel", background=APP_BG, foreground=MUTED, font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background=SURFACE, foreground=TEXT, font=("Segoe UI Semibold", 13))
        style.configure("Metric.TLabel", background=SURFACE, foreground=TEXT, font=("Segoe UI Semibold", 28))
        style.configure("TButton", font=("Segoe UI Semibold", 10), padding=(14, 9))
        style.map("TButton", background=[("active", "#dbeafe")])
        style.configure("Primary.TButton", background=PRIMARY, foreground="#ffffff", bordercolor=PRIMARY)
        style.map("Primary.TButton", background=[("active", "#1d4ed8")], foreground=[("active", "#ffffff")])
        style.configure("TCheckbutton", background=APP_BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Horizontal.TProgressbar", troughcolor="#dbe3ef", background=PRIMARY, bordercolor="#dbe3ef")
        style.configure("Treeview", font=("Segoe UI", 9), rowheight=30, background="#ffffff", fieldbackground="#ffffff")
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9), background="#f8fafc")

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=22)
        root.pack(fill="both", expand=True)

        header = ttk.Frame(root)
        header.pack(fill="x")
        ttk.Label(header, text=APP_TITLE, style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Layered defensive analysis for suspicious URLs, website signals, TLS, DNS, and WHOIS.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(3, 16))

        input_row = ttk.Frame(root)
        input_row.pack(fill="x")
        self.url_var = tk.StringVar()
        entry = ttk.Entry(input_row, textvariable=self.url_var, font=("Segoe UI", 12))
        entry.pack(side="left", fill="x", expand=True, ipady=9)
        entry.bind("<Return>", lambda _event: self.start_scan())
        ttk.Button(input_row, text="Scan URL", style="Primary.TButton", command=self.start_scan).pack(side="left", padx=(10, 0))

        options = ttk.Frame(root)
        options.pack(fill="x", pady=(10, 16))
        self.fetch_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options, text="Scan website content", variable=self.fetch_var).pack(side="left")
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(options, textvariable=self.status_var, style="Subtitle.TLabel").pack(side="right")

        self.progress = ttk.Progressbar(root, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 16))

        content = ttk.Frame(root)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=0)
        content.columnconfigure(1, weight=1)
        content.rowconfigure(0, weight=1)

        left = ttk.Frame(content, style="Surface.TFrame", padding=18)
        left.grid(row=0, column=0, sticky="nsw", padx=(0, 16))
        left.configure(width=300)
        left.grid_propagate(False)

        ttk.Label(left, text="Verdict", style="CardTitle.TLabel").pack(anchor="w")
        self.verdict_var = tk.StringVar(value="Not scanned")
        self.verdict_label = tk.Label(
            left,
            textvariable=self.verdict_var,
            bg="#e5e7eb",
            fg="#374151",
            font=("Segoe UI Semibold", 17),
            padx=14,
            pady=12,
            anchor="center",
        )
        self.verdict_label.pack(fill="x", pady=(10, 18))

        self.score_var = tk.StringVar(value="--")
        ttk.Label(left, textvariable=self.score_var, style="Metric.TLabel").pack(anchor="w")
        ttk.Label(left, text="Risk score / 100", style="Muted.TLabel").pack(anchor="w", pady=(0, 18))

        self.summary_var = tk.StringVar(value="Enter a URL to begin analysis.")
        tk.Label(
            left,
            textvariable=self.summary_var,
            bg=SURFACE,
            fg=MUTED,
            font=("Segoe UI", 10),
            wraplength=250,
            justify="left",
        ).pack(anchor="w", fill="x")

        actions = ttk.Frame(left, style="Surface.TFrame")
        actions.pack(side="bottom", fill="x", pady=(18, 0))
        ttk.Button(actions, text="Export HTML", command=self.export_html_report).pack(fill="x", pady=(0, 8))
        ttk.Button(actions, text="Export JSON", command=self.export_json_report).pack(fill="x")

        right = ttk.Notebook(content)
        right.grid(row=0, column=1, sticky="nsew")

        findings_tab = ttk.Frame(right, style="Surface.TFrame", padding=10)
        network_tab = ttk.Frame(right, style="Surface.TFrame", padding=14)
        whois_tab = ttk.Frame(right, style="Surface.TFrame", padding=14)
        raw_tab = ttk.Frame(right, style="Surface.TFrame", padding=14)
        right.add(findings_tab, text="Findings")
        right.add(network_tab, text="Network")
        right.add(whois_tab, text="WHOIS")
        right.add(raw_tab, text="Report")

        columns = ("severity", "title", "detail", "points")
        self.findings_tree = ttk.Treeview(findings_tab, columns=columns, show="headings")
        for col, width in (("severity", 95), ("title", 210), ("detail", 560), ("points", 70)):
            self.findings_tree.heading(col, text=col.title())
            self.findings_tree.column(col, width=width, anchor="w")
        self.findings_tree.pack(fill="both", expand=True)

        self.network_text = self._make_text(network_tab)
        self.whois_text = self._make_text(whois_tab)
        self.raw_text = self._make_text(raw_tab)

    def _make_text(self, parent: ttk.Frame) -> tk.Text:
        text = tk.Text(
            parent,
            wrap="word",
            borderwidth=0,
            bg=SURFACE,
            fg=TEXT,
            insertbackground=TEXT,
            font=("Consolas", 10),
        )
        scrollbar = ttk.Scrollbar(parent, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return text

    def start_scan(self) -> None:
        if self._scanning:
            return
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning(APP_TITLE, "Please enter a URL to scan.")
            return
        self._scanning = True
        self._set_status("Scanning URL, network, TLS, page signals, and WHOIS...")
        self.progress.start(12)
        self._clear_results()
        thread = threading.Thread(target=self._scan_worker, args=(url, self.fetch_var.get()), daemon=True)
        thread.start()

    def _scan_worker(self, url: str, fetch_site: bool) -> None:
        try:
            report = scan_url(url, fetch_site=fetch_site)
            self._queue.put(("done", report))
        except Exception as exc:  # noqa: BLE001 - keep UI alive for unexpected scanner bugs.
            self._queue.put(("error", str(exc)))

    def _poll_queue(self) -> None:
        try:
            while True:
                event, payload = self._queue.get_nowait()
                if event == "done":
                    self._show_report(payload)
                elif event == "error":
                    self._show_error(str(payload))
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _show_report(self, report: UrlReport) -> None:
        self._scanning = False
        self.progress.stop()
        self._current_report = report
        self._set_status("Scan complete")
        self.verdict_var.set(report.verdict)
        self.score_var.set(str(report.risk_score))
        self.summary_var.set(report.summary)
        self._style_verdict(report.verdict)

        for finding in report.findings:
            self.findings_tree.insert(
                "",
                "end",
                values=(finding.severity, finding.title, finding.detail, finding.points),
            )
        if not report.findings:
            self.findings_tree.insert("", "end", values=("Info", "No notable findings", "No strong indicators were detected.", 0))

        network_lines = [
            f"Input URL: {report.input_url}",
            f"Normalized URL: {report.normalized_url}",
            f"Final URL: {report.final_url or 'Not fetched'}",
            f"Domain: {report.domain or 'Unknown'}",
            f"IP addresses: {', '.join(report.ip_addresses) or 'Not resolved'}",
            "",
            "TLS:",
            _pretty(report.tls),
            "",
            "HTTP:",
            _pretty(report.http),
            "",
            "Page signals:",
            _pretty(report.page_signals),
        ]
        self._set_text(self.network_text, "\n".join(network_lines))
        self._set_text(self.whois_text, _pretty(report.whois))
        self._set_text(self.raw_text, _pretty(report.to_dict()))

    def _show_error(self, error: str) -> None:
        self._scanning = False
        self.progress.stop()
        self._set_status("Scan failed")
        messagebox.showerror(APP_TITLE, f"Scan failed:\n{error}")

    def _style_verdict(self, verdict: str) -> None:
        if verdict == "Dangerous":
            self.verdict_label.configure(bg="#fee2e2", fg=DANGER)
        elif verdict == "Suspicious":
            self.verdict_label.configure(bg="#fef3c7", fg=WARN)
        elif verdict == "Safe":
            self.verdict_label.configure(bg="#dcfce7", fg=SAFE)
        else:
            self.verdict_label.configure(bg="#e5e7eb", fg="#374151")

    def _clear_results(self) -> None:
        self._current_report = None
        self.verdict_var.set("Scanning")
        self.score_var.set("--")
        self.summary_var.set("Working through URL, network, certificate, content, and WHOIS checks.")
        self._style_verdict("Unknown")
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        self._set_text(self.network_text, "")
        self._set_text(self.whois_text, "")
        self._set_text(self.raw_text, "")

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)

    def _set_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def export_html_report(self) -> None:
        self._export("html")

    def export_json_report(self) -> None:
        self._export("json")

    def _export(self, kind: str) -> None:
        if not self._current_report:
            messagebox.showinfo(APP_TITLE, "Run a scan before exporting a report.")
            return
        extension = f".{kind}"
        path = filedialog.asksaveasfilename(
            title=f"Export {kind.upper()} report",
            defaultextension=extension,
            filetypes=[(f"{kind.upper()} report", f"*{extension}")],
            initialfile="phishing-url-report" + extension,
        )
        if not path:
            return
        if kind == "html":
            export_html(self._current_report, path)
            if messagebox.askyesno(APP_TITLE, "HTML report saved. Open it now?"):
                webbrowser.open(Path(path).as_uri())
        else:
            export_json(self._current_report, path)
            messagebox.showinfo(APP_TITLE, f"JSON report saved:\n{path}")


def _pretty(value: object) -> str:
    import json

    return json.dumps(value, indent=2, ensure_ascii=False)


def main() -> None:
    os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")
    app = DetectorApp()
    app.mainloop()


if __name__ == "__main__":
    main()

