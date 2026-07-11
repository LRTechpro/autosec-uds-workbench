"""
trace_metrics.py
================
Pandas-powered trace analytics for AutoSec UDS Conformance Workbench.

This module is intentionally separate from the Tkinter GUI. The GUI can call
these functions, but the analytics logic can also be tested, reused from a CLI,
or later placed into a CI pipeline.

The assignment/library requirement is satisfied here through pandas. Pandas is
used to load CSV trace files, normalize diagnostic fields, derive additional
columns, summarize service usage, summarize NRC usage, and build exportable
metrics tables.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pandas as pd

import uds_decoder as dec
from rules_engine import Finding, PASS, FAIL, BLOCKED, INFO


class MetricsError(Exception):
    """Raised when trace analytics cannot be built from the input file."""


@dataclass
class TraceAnalytics:
    """Container for all pandas-derived trace analytics."""

    trace_file: str
    row_count: int
    request_service_counts: pd.DataFrame
    response_type_counts: pd.DataFrame
    nrc_counts: pd.DataFrame
    did_counts: pd.DataFrame
    verdict_counts: pd.DataFrame
    security_related_rows: int
    programming_related_rows: int
    dataframe: pd.DataFrame


SERVICE_NAMES = {
    0x10: "Diagnostic Session Control",
    0x11: "ECU Reset",
    0x22: "Read Data By Identifier",
    0x27: "Security Access",
    0x2E: "Write Data By Identifier",
    0x31: "Routine Control",
    0x34: "Request Download",
    0x36: "Transfer Data",
    0x37: "Request Transfer Exit",
    0x3E: "Tester Present",
}

PROGRAMMING_SERVICES = {0x34, 0x36, 0x37, 0x31, 0x11}
SECURITY_RELATED_SERVICES = {0x27, 0x2E, 0x34, 0x36, 0x37, 0x31}


def normalize_hex_text(value: object) -> str:
    """Return uppercase space-separated hex text from a CSV cell value."""

    if pd.isna(value):
        return ""
    return " ".join(str(value).replace("0x", "").replace("0X", "").split()).upper()


def first_byte(hex_text: str) -> int | None:
    """Return the first byte from a hex payload, or None if it cannot parse."""

    parts = normalize_hex_text(hex_text).split()
    if not parts:
        return None
    try:
        return int(parts[0], 16)
    except ValueError:
        return None


def did_from_request(hex_text: str) -> str:
    """Return a DID string for UDS services that normally carry a DID."""

    parts = normalize_hex_text(hex_text).split()
    if len(parts) >= 3 and parts[0] in {"22", "2E"}:
        return f"{parts[1]}{parts[2]}"
    return ""


def response_type_from_payload(hex_text: str, request_sid: int | None) -> str:
    """Classify a UDS response as positive, negative, empty, malformed, or unknown."""

    response_sid = first_byte(hex_text)
    if response_sid is None:
        return "empty_or_malformed"
    if response_sid == 0x7F:
        return "negative"
    if request_sid is not None and response_sid == dec.positive_response_sid(request_sid):
        return "positive"
    return "unmatched"


def nrc_from_response(hex_text: str) -> str:
    """Return NRC text from a negative response, such as 0x33 securityAccessDenied."""

    parts = normalize_hex_text(hex_text).split()
    if len(parts) >= 3 and parts[0] == "7F":
        try:
            nrc = int(parts[2], 16)
        except ValueError:
            return "malformed_nrc"
        return f"0x{nrc:02X} {dec.NRC_TABLE.get(nrc, 'unknownNrc')}"
    return ""


def load_trace_dataframe(trace_path: str | Path, service_names: dict[int, str]) -> pd.DataFrame:
    """Load a trace CSV with pandas and derive analytics-friendly columns."""

    path = Path(trace_path)
    if not path.exists():
        raise MetricsError(f"Trace file does not exist: {path}")

    dataframe = pd.read_csv(path, dtype=str).fillna("")
    required = {"step", "module", "request", "response", "session", "security_state"}
    missing = required - set(dataframe.columns)
    if missing:
        raise MetricsError(f"Trace CSV missing required columns: {sorted(missing)}")

    dataframe["request_norm"] = dataframe["request"].map(normalize_hex_text)
    dataframe["response_norm"] = dataframe["response"].map(normalize_hex_text)
    dataframe["request_sid"] = dataframe["request_norm"].map(first_byte)
    dataframe["service"] = dataframe["request_sid"].map(
        lambda sid: service_names.get(sid, "Unknown") if sid is not None else "Unknown"
    )
    dataframe["did"] = dataframe["request_norm"].map(did_from_request)
    dataframe["response_type"] = dataframe.apply(
        lambda row: response_type_from_payload(row["response_norm"], row["request_sid"]), axis=1
    )
    dataframe["nrc"] = dataframe["response_norm"].map(nrc_from_response)
    dataframe["is_security_related"] = dataframe["request_sid"].map(
        lambda sid: sid in SECURITY_RELATED_SERVICES if sid is not None else False
    )
    dataframe["is_programming_related"] = dataframe["request_sid"].map(
        lambda sid: sid in PROGRAMMING_SERVICES if sid is not None else False
    )
    return dataframe


def count_column(dataframe: pd.DataFrame, column_name: str, label_name: str, count_name: str = "count") -> pd.DataFrame:
    """Return a value-count table for one dataframe column."""

    if column_name not in dataframe.columns:
        raise MetricsError(f"Column not found for metrics: {column_name}")
    counts = dataframe[column_name].replace("", pd.NA).dropna().value_counts().reset_index()
    counts.columns = [label_name, count_name]
    return counts


def verdict_count_table(findings: Iterable[Finding]) -> pd.DataFrame:
    """Return PASS/FAIL/BLOCKED/INFO counts from validation findings."""

    verdicts = [finding.verdict for finding in findings]
    frame = pd.DataFrame({"verdict": verdicts})
    if frame.empty:
        return pd.DataFrame({"verdict": [PASS, FAIL, BLOCKED, INFO], "count": [0, 0, 0, 0]})
    counts = frame["verdict"].value_counts().reindex([PASS, FAIL, BLOCKED, INFO], fill_value=0)
    return pd.DataFrame({"verdict": counts.index.tolist(), "count": counts.astype(int).tolist()})


def build_trace_analytics(trace_path: str | Path, findings: Iterable[Finding], top_n: int = 10) -> TraceAnalytics:
    """Build a complete analytics package from a trace path and findings list."""

    dataframe = load_trace_dataframe(trace_path, SERVICE_NAMES)
    request_counts = count_column(dataframe, "service", "service").head(top_n)
    response_counts = count_column(dataframe, "response_type", "response_type").head(top_n)
    nrc_counts = count_column(dataframe, "nrc", "nrc").head(top_n)
    did_counts = count_column(dataframe, "did", "did").head(top_n)
    verdict_counts = verdict_count_table(findings)
    return TraceAnalytics(
        trace_file=Path(trace_path).name,
        row_count=len(dataframe),
        request_service_counts=request_counts,
        response_type_counts=response_counts,
        nrc_counts=nrc_counts,
        did_counts=did_counts,
        verdict_counts=verdict_counts,
        security_related_rows=int(dataframe["is_security_related"].sum()),
        programming_related_rows=int(dataframe["is_programming_related"].sum()),
        dataframe=dataframe,
    )


def format_table(dataframe: pd.DataFrame) -> str:
    """Format a small pandas dataframe into aligned plain text for Tkinter."""

    if dataframe.empty:
        return "  none"
    return dataframe.to_string(index=False)


def build_metrics_report(metrics: TraceAnalytics, include_preview_rows: int = 8) -> str:
    """Return a readable multi-section text report for the GUI detail pane."""

    lines = [
        "UDS Trace Analytics - pandas summary",
        "====================================",
        f"Trace file: {metrics.trace_file}",
        f"Trace rows: {metrics.row_count}",
        f"Security-related requests: {metrics.security_related_rows}",
        f"Programming-related requests: {metrics.programming_related_rows}",
        "",
        "Service usage",
        "-------------",
        format_table(metrics.request_service_counts),
        "",
        "Response classification",
        "-----------------------",
        format_table(metrics.response_type_counts),
        "",
        "Negative Response Codes",
        "-----------------------",
        format_table(metrics.nrc_counts),
        "",
        "DID usage",
        "---------",
        format_table(metrics.did_counts),
        "",
        "Validation verdict counts",
        "-------------------------",
        format_table(metrics.verdict_counts),
        "",
        "Trace preview with derived analytics columns",
        "--------------------------------------------",
        metrics.dataframe[
            ["step", "module", "request_norm", "response_norm", "service", "did", "response_type", "nrc"]
        ].head(include_preview_rows).to_string(index=False),
    ]
    return "\n".join(lines)


def export_metrics_csv(metrics: TraceAnalytics, output_path: str | Path) -> str:
    """Export analytics tables to one CSV using pandas and return the saved path."""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    sections = []
    for section_name, table in (
        ("service_usage", metrics.request_service_counts),
        ("response_classification", metrics.response_type_counts),
        ("negative_response_codes", metrics.nrc_counts),
        ("did_usage", metrics.did_counts),
        ("verdict_counts", metrics.verdict_counts),
    ):
        copy = table.copy()
        copy.insert(0, "section", section_name)
        sections.append(copy)

    export_frame = pd.concat(sections, ignore_index=True, sort=False).fillna("")
    export_frame.to_csv(output, index=False)
    return str(output)
