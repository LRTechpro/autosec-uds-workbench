"""
main.py
=======
AutoSec UDS Conformance Workbench - Tkinter GUI layer.

DESIGN RULE: This file contains presentation logic ONLY. Every diagnostic
decision is delegated to the engine modules (uds_decoder, spec_loader,
rules_engine, report_writer). The GUI could be deleted and replaced with a
CLI or CI job without touching any validation logic -- that separation is
deliberate and is the main architecture talking point of this project.

Layout (three panes, workbench style):
    +--------------------------------------------------------------+
    | toolbar: Open Trace | Load Spec | Run Validation | Export ...|
    +------------------------------+-------------------------------+
    | Trace table                  |  Decoded detail               |
    | Step|Req|Rsp|Session|Verdict |  (selected row OR finding)    |
    |                              +-------------------------------+
    |                              |  Findings list                |
    +------------------------------+-------------------------------+
    | status bar                                                   |
    +--------------------------------------------------------------+

Column sizing: every column uses stretch=False and the _autosize_*
handlers (bound to <Configure>) recompute flexible-column widths on every
resize, so both tables always fit their pane exactly -- no manual column
dragging, no overflow.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import uds_decoder as dec
from spec_loader import load_spec, SpecError
from rules_engine import (load_trace_csv, validate_trace, verdict_for_step,
                          worst_verdict, PASS, FAIL, BLOCKED, INFO)
from report_writer import build_report, save_report
from trace_metrics import (MetricsError, build_trace_analytics,
                           build_metrics_report, export_metrics_csv)

APP_NAME = "AutoSec UDS Conformance Workbench"
APP_VERSION = "1.1.0"

# Dark workbench palette. Verdicts use conventional test-report colors.
COLORS = {
    "bg": "#1e1f24",
    "panel": "#26282f",
    "field": "#2d3038",
    "text": "#d6d8de",
    "dim": "#8a8f9c",
    "accent": "#4f9cf5",
    "pass": "#3fb96f",
    "fail": "#e05555",
    "blocked": "#e0a030",
    "info": "#4f9cf5",
}
MONO = ("Consolas", 10)  # monospace for hex payloads
UI_FONT = ("Segoe UI", 10)

# Fixed column widths (px). Flexible columns absorb the remaining width.
TRACE_FIXED = {"step": 45, "session": 90, "security": 75, "verdict": 80}
FINDINGS_FIXED = {"verdict": 75, "category": 120, "step": 45}


class WorkbenchApp(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME}  v{APP_VERSION}")
        self.geometry("1240x720")
        self.minsize(980, 560)
        self.configure(bg=COLORS["bg"])

        # ---- application state (data only; logic lives in the engine) ----
        self.spec = None
        self.spec_path = None
        self.trace_steps = []
        self.trace_path = None
        self.findings = []
        self.metrics = None

        self._build_style()
        self._build_menu()
        self._build_toolbar()
        self._build_panes()
        self._build_statusbar()
        self._try_load_default_spec()

    # ------------------------------------------------------------------
    # Styling
    # ------------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")  # clam accepts full color customization
        style.configure(".", background=COLORS["bg"],
                        foreground=COLORS["text"], font=UI_FONT)
        style.configure("Treeview", background=COLORS["field"],
                        fieldbackground=COLORS["field"],
                        foreground=COLORS["text"], rowheight=24,
                        font=MONO, borderwidth=0)
        style.configure("Treeview.Heading", background=COLORS["panel"],
                        foreground=COLORS["text"], font=(UI_FONT[0], 9, "bold"))
        style.map("Treeview", background=[("selected", COLORS["accent"])],
                  foreground=[("selected", "#ffffff")])
        style.configure("TButton", background=COLORS["panel"],
                        foreground=COLORS["text"], padding=(10, 5))
        style.map("TButton", background=[("active", COLORS["accent"])])
        style.configure("TLabel", background=COLORS["bg"],
                        foreground=COLORS["text"])
        style.configure("Status.TLabel", background=COLORS["panel"],
                        foreground=COLORS["dim"], padding=(8, 3))
        style.configure("TPanedwindow", background=COLORS["bg"])

    # ------------------------------------------------------------------
    # Menu / toolbar
    # ------------------------------------------------------------------
    def _build_menu(self):
        menubar = tk.Menu(self)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open Trace...", command=self.open_trace,
                             accelerator="Ctrl+O")
        filemenu.add_command(label="Load Spec...", command=self.load_spec_file,
                             accelerator="Ctrl+L")
        filemenu.add_separator()
        filemenu.add_command(label="Export Report...", command=self.export_report,
                             accelerator="Ctrl+E")
        filemenu.add_command(label="Export Metrics CSV...", command=self.export_metrics,
                             accelerator="Ctrl+Shift+E")
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=filemenu)

        runmenu = tk.Menu(menubar, tearoff=0)
        runmenu.add_command(label="Run Validation", command=self.run_validation,
                            accelerator="F5")
        runmenu.add_command(label="Analyze Trace Metrics", command=self.analyze_trace_metrics,
                            accelerator="Ctrl+M")
        runmenu.add_command(label="Clear Output", command=self.clear_output)
        menubar.add_cascade(label="Run", menu=runmenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self._about)
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.config(menu=menubar)

        # Keyboard shortcuts -- small touch, but it reads "tool", not "demo".
        self.bind("<Control-o>", lambda e: self.open_trace())
        self.bind("<Control-l>", lambda e: self.load_spec_file())
        self.bind("<Control-e>", lambda e: self.export_report())
        self.bind("<Control-M>", lambda e: self.analyze_trace_metrics())
        self.bind("<F5>", lambda e: self.run_validation())

    def _build_toolbar(self):
        bar = tk.Frame(self, bg=COLORS["panel"])
        bar.pack(fill="x")
        for label, cmd in (("Open Trace", self.open_trace),
                           ("Load Spec", self.load_spec_file),
                           ("Run Validation", self.run_validation),
                           ("Trace Metrics", self.analyze_trace_metrics),
                           ("Export Report", self.export_report),
                           ("Clear Output", self.clear_output)):
            ttk.Button(bar, text=label, command=cmd).pack(
                side="left", padx=4, pady=4)
        self.verdict_label = tk.Label(bar, text="", bg=COLORS["panel"],
                                      font=(UI_FONT[0], 11, "bold"))
        self.verdict_label.pack(side="right", padx=12)

    # ------------------------------------------------------------------
    # Panes
    # ------------------------------------------------------------------
    def _build_panes(self):
        outer = ttk.Panedwindow(self, orient="horizontal")
        outer.pack(fill="both", expand=True, padx=6, pady=6)

        # ---- left: trace table ----
        left = tk.Frame(outer, bg=COLORS["bg"])
        cols = ("step", "request", "response", "session", "security", "verdict")
        self.trace_tree = ttk.Treeview(left, columns=cols, show="headings",
                                       selectmode="browse")
        for c in cols:
            self.trace_tree.heading(c, text=c.capitalize())
            # stretch=False on every column: _autosize_trace_columns owns
            # the geometry so the table always fits the pane exactly.
            self.trace_tree.column(c, width=TRACE_FIXED.get(c, 210),
                                   anchor="w", stretch=False)
        # Verdict row coloring via tags.
        for verdict, color in (("PASS", COLORS["pass"]), ("FAIL", COLORS["fail"]),
                               ("BLOCKED", COLORS["blocked"]), ("INFO", COLORS["info"])):
            self.trace_tree.tag_configure(verdict, foreground=color)
        ysb = ttk.Scrollbar(left, orient="vertical",
                            command=self.trace_tree.yview)
        self.trace_tree.configure(yscrollcommand=ysb.set)
        self.trace_tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")
        self.trace_tree.bind("<<TreeviewSelect>>", self._on_row_selected)
        # Re-fit flexible columns whenever the pane/window is resized.
        self.trace_tree.bind("<Configure>", self._autosize_trace_columns)
        outer.add(left, weight=3)

        # ---- right: detail (top) + findings (bottom) ----
        right = ttk.Panedwindow(outer, orient="vertical")

        detail_frame = tk.Frame(right, bg=COLORS["bg"])
        tk.Label(detail_frame, text="DECODED DETAIL", bg=COLORS["bg"],
                 fg=COLORS["dim"], font=(UI_FONT[0], 8, "bold")).pack(anchor="w")
        self.detail_text = tk.Text(detail_frame, height=12, bg=COLORS["field"],
                                   fg=COLORS["text"], font=MONO, wrap="word",
                                   relief="flat", state="disabled",
                                   insertbackground=COLORS["text"])
        self.detail_text.pack(fill="both", expand=True)
        right.add(detail_frame, weight=2)

        findings_frame = tk.Frame(right, bg=COLORS["bg"])
        tk.Label(findings_frame, text="FINDINGS", bg=COLORS["bg"],
                 fg=COLORS["dim"], font=(UI_FONT[0], 8, "bold")).pack(anchor="w")
        fcols = ("verdict", "category", "step", "message")
        self.findings_tree = ttk.Treeview(findings_frame, columns=fcols,
                                          show="headings", selectmode="browse")
        for c in fcols:
            self.findings_tree.heading(c, text=c.capitalize())
            # stretch=False: _autosize_findings_columns sizes 'message' to
            # exactly the remaining pane width, so nothing overflows.
            self.findings_tree.column(c, width=FINDINGS_FIXED.get(c, 460),
                                      anchor="w", stretch=False)
        for verdict, color in (("PASS", COLORS["pass"]), ("FAIL", COLORS["fail"]),
                               ("BLOCKED", COLORS["blocked"]), ("INFO", COLORS["info"])):
            self.findings_tree.tag_configure(verdict, foreground=color)
        fsb = ttk.Scrollbar(findings_frame, orient="vertical",
                            command=self.findings_tree.yview)
        self.findings_tree.configure(yscrollcommand=fsb.set)
        self.findings_tree.pack(side="left", fill="both", expand=True)
        fsb.pack(side="right", fill="y")
        # Clicking a finding shows its FULL text (message, expected/actual,
        # cause, next step) in the detail pane -- long findings are never
        # lost to column clipping.
        self.findings_tree.bind("<<TreeviewSelect>>", self._on_finding_selected)
        self.findings_tree.bind("<Configure>", self._autosize_findings_columns)
        right.add(findings_frame, weight=3)

        outer.add(right, weight=4)

    def _build_statusbar(self):
        self.status = ttk.Label(self, text="Ready.", style="Status.TLabel",
                                anchor="w")
        self.status.pack(fill="x", side="bottom")

    # ------------------------------------------------------------------
    # Auto-fit column sizing (bound to <Configure> on each Treeview)
    # ------------------------------------------------------------------
    def _autosize_trace_columns(self, event=None):
        """Fit request/response columns to the pane so the trace table
        always fills its box exactly -- no manual column dragging."""
        total = event.width if event else self.trace_tree.winfo_width()
        fixed = sum(TRACE_FIXED.values())
        flex = max(140, (total - fixed - 4) // 2)
        self.trace_tree.column("request", width=flex)
        self.trace_tree.column("response", width=flex)

    def _autosize_findings_columns(self, event=None):
        """Give the message column exactly the remaining pane width."""
        total = event.width if event else self.findings_tree.winfo_width()
        fixed = sum(FINDINGS_FIXED.values())
        self.findings_tree.column("message", width=max(200, total - fixed - 4))

    # ------------------------------------------------------------------
    # Event handlers (each one delegates real work to the engine)
    # ------------------------------------------------------------------
    def _try_load_default_spec(self):
        """Convenience: auto-load the bundled APIM spec if it exists."""
        default = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "specs", "apim_spec.json")
        if os.path.exists(default):
            try:
                self.spec = load_spec(default)
                self.spec_path = default
                self._set_status(f"Loaded default spec: {self.spec.ecu} "
                                 f"(v{self.spec.spec_version})")
            except SpecError as exc:
                self._set_status(f"Default spec failed to load: {exc}")

    def open_trace(self):
        path = filedialog.askopenfilename(
            title="Open Trace CSV",
            filetypes=[("Trace CSV", "*.csv"), ("All files", "*.*")],
            initialdir=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "traces"))
        if not path:
            return
        try:
            self.trace_steps = load_trace_csv(path)
        except (ValueError, OSError) as exc:
            messagebox.showerror("Trace error", str(exc))
            return
        self.trace_path = path
        self.findings = []
        self.metrics = None
        self._refresh_trace_table()
        self._set_findings([])
        self.verdict_label.config(text="")
        self._set_status(f"Loaded {len(self.trace_steps)} steps from "
                         f"{os.path.basename(path)}. Press F5 to validate.")

    def load_spec_file(self):
        path = filedialog.askopenfilename(
            title="Load Diagnostic Spec (JSON)",
            filetypes=[("Spec JSON", "*.json"), ("All files", "*.*")],
            initialdir=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "specs"))
        if not path:
            return
        try:
            self.spec = load_spec(path)
        except (SpecError, OSError) as exc:
            messagebox.showerror("Spec error", str(exc))
            return
        self.spec_path = path
        self._set_status(f"Loaded spec: {self.spec.ecu} "
                         f"(v{self.spec.spec_version}) - "
                         f"{len(self.spec.services)} services")

    def run_validation(self):
        if self.spec is None:
            messagebox.showwarning("No spec", "Load a diagnostic spec first "
                                   "(File > Load Spec).")
            return
        if not self.trace_steps:
            messagebox.showwarning("No trace", "Open a trace CSV first "
                                   "(File > Open Trace).")
            return
        # The one line where the GUI asks the engine to do the real work:
        self.findings = validate_trace(self.trace_steps, self.spec)
        self.metrics = None
        self._refresh_trace_table()
        self._set_findings(self.findings)
        overall = worst_verdict(self.findings)
        color = {PASS: COLORS["pass"], FAIL: COLORS["fail"],
                 BLOCKED: COLORS["blocked"], INFO: COLORS["info"]}[overall]
        self.verdict_label.config(text=f"OVERALL: {overall}", fg=color)
        counts = {v: sum(1 for f in self.findings if f.verdict == v)
                  for v in (PASS, FAIL, BLOCKED, INFO)}
        self._set_status(f"Validation complete: {counts[PASS]} PASS, "
                         f"{counts[FAIL]} FAIL, {counts[BLOCKED]} BLOCKED, "
                         f"{counts[INFO]} INFO.")

    def export_report(self):
        if not self.findings:
            messagebox.showwarning("Nothing to export",
                                   "Run a validation first (F5).")
            return
        path = filedialog.asksaveasfilename(
            title="Export Triage Report",
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("All files", "*.*")],
            initialdir=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "reports"),
            initialfile="triage_report.md")
        if not path:
            return
        report = build_report(
            self.findings,
            ecu=self.spec.ecu,
            trace_file=os.path.basename(self.trace_path or "unknown"),
            spec_file=os.path.basename(self.spec_path or "unknown"),
            spec_version=self.spec.spec_version)
        save_report(report, path)
        self._set_status(f"Report exported to {path}")

    def analyze_trace_metrics(self):
        """Build pandas-based trace analytics and show them in the detail pane."""
        if not self.trace_path:
            messagebox.showwarning("No trace", "Open a trace CSV before running analytics.")
            return
        try:
            self.metrics = build_trace_analytics(self.trace_path, self.findings)
        except MetricsError as exc:
            messagebox.showerror("Metrics error", str(exc))
            return
        self._set_detail(build_metrics_report(self.metrics))
        self._set_status("Trace analytics complete using pandas: "
                         f"{self.metrics.row_count} rows analyzed from "
                         f"{os.path.basename(self.trace_path)}.")

    def export_metrics(self):
        """Export pandas-based metrics to CSV for review or reporting."""
        if self.metrics is None:
            if not self.trace_path:
                messagebox.showwarning("No trace", "Open a trace CSV before exporting metrics.")
                return
            try:
                self.metrics = build_trace_analytics(self.trace_path, self.findings)
            except MetricsError as exc:
                messagebox.showerror("Metrics error", str(exc))
                return
        path = filedialog.asksaveasfilename(
            title="Export Trace Metrics CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
            initialdir=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "reports"),
            initialfile="trace_metrics.csv")
        if not path:
            return
        saved_path = export_metrics_csv(self.metrics, path)
        self._set_status(f"Metrics CSV exported to {saved_path}")

    def clear_output(self):
        self.trace_steps = []
        self.trace_path = None
        self.findings = []
        self.metrics = None
        self._refresh_trace_table()
        self._set_findings([])
        self._set_detail("")
        self.verdict_label.config(text="")
        self._set_status("Workspace cleared.")

    # ------------------------------------------------------------------
    # View refresh helpers
    # ------------------------------------------------------------------
    def _refresh_trace_table(self):
        self.trace_tree.delete(*self.trace_tree.get_children())
        for s in self.trace_steps:
            verdict = (verdict_for_step(self.findings, s.step)
                       if self.findings else "")
            self.trace_tree.insert(
                "", "end", iid=str(s.step),
                values=(s.step, s.request, s.response, s.declared_session,
                        s.declared_security, verdict),
                tags=(verdict,) if verdict else ())

    def _finding_preview(self, finding, limit=52):
        """Return a short table-safe preview for one finding.

        The Findings table is intentionally a quick triage list. Tkinter
        Treeview cells do not wrap like a Word document or web table, so the
        table shows a short preview while the Decoded Detail pane shows the
        complete engineering explanation when the user selects a finding.
        """
        message = " ".join(str(finding.message).split())
        if len(message) <= limit:
            return message
        return message[:limit - 3].rstrip() + "..."

    def _set_findings(self, findings):
        # Keep the list so _on_finding_selected can show full triage text.
        self._shown_findings = list(findings)
        self.findings_tree.delete(*self.findings_tree.get_children())
        for i, f in enumerate(findings):
            preview = self._finding_preview(f)
            self.findings_tree.insert(
                "", "end", iid=str(i),
                values=(f.verdict, f.category,
                        f.step if f.step is not None else "-", preview),
                tags=(f.verdict,))

    def _on_row_selected(self, _event):
        sel = self.trace_tree.selection()
        if not sel:
            return
        step_no = int(sel[0])
        step = next((s for s in self.trace_steps if s.step == step_no), None)
        if step is None:
            return
        # Decode on the fly so the detail pane works even before validation.
        try:
            req = step.req_decoded or dec.decode_request(step.request)
            rsp = step.rsp_decoded or dec.decode_response(step.response,
                                                          request_sid=req.sid)
        except ValueError as exc:
            self._set_detail(f"Decode error: {exc}")
            return
        lines = [
            f"Step:       {step.step}   Module: {step.module}",
            f"Note:       {step.note or '-'}",
            "",
            f"Request:    {req.raw_hex}",
            f"  {req.summary}",
            "",
            f"Response:   {rsp.raw_hex}",
            f"  {rsp.summary}",
            "",
            f"Declared session/security: {step.declared_session} / "
            f"{step.declared_security}",
        ]
        if rsp.kind == "negative" and rsp.nrc is not None:
            lines.append("")
            lines.append(f"NRC 0x{rsp.nrc:02X} = {rsp.nrc_name}")
        self._set_detail("\n".join(lines))

    def _on_finding_selected(self, _event):
        """Render the complete finding in the detail pane. The table shows
        a one-line preview; this is the full triage text."""
        sel = self.findings_tree.selection()
        if not sel or not hasattr(self, "_shown_findings"):
            return
        idx = int(sel[0])
        if idx >= len(self._shown_findings):
            return
        f = self._shown_findings[idx]
        lines = [
            f"[{f.verdict}] {f.category}"
            + (f"  (trace step {f.step})" if f.step is not None else ""),
            "",
            f"Finding:  {f.message}",
        ]
        if f.expected:
            lines += ["", f"Expected: {f.expected}"]
        if f.actual:
            lines += ["", f"Actual:   {f.actual}"]
        if f.possible_cause:
            lines += ["", f"Possible cause: {f.possible_cause}"]
        if f.next_step:
            lines += ["", f"Next step: {f.next_step}"]
        self._set_detail("\n".join(lines))

    def _set_detail(self, text):
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.config(state="disabled")

    def _set_status(self, text):
        self.status.config(text=text)

    def _about(self):
        messagebox.showinfo(
            "About",
            f"{APP_NAME} v{APP_VERSION}\n\n"
            "Spec-driven UDS (ISO 14229) conformance validation:\n"
            "ingests diagnostic traces, compares ECU behavior against a\n"
            "machine-readable diagnostic spec, generates V&V-style\n"
            "findings, and uses pandas for trace analytics metrics.")


if __name__ == "__main__":
    WorkbenchApp().mainloop()
