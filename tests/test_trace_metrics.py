from pathlib import Path

import pandas as pd

from rules_engine import load_trace_csv, validate_trace
from spec_loader import load_spec
from trace_metrics import (
    SERVICE_NAMES,
    build_metrics_report,
    build_trace_analytics,
    export_metrics_csv,
    load_trace_dataframe,
)

ROOT = Path(__file__).resolve().parents[1]


def test_pandas_trace_dataframe_derives_service_and_nrc_columns():
    trace_path = ROOT / "traces" / "apim_security_fail_trace.csv"
    dataframe = load_trace_dataframe(trace_path, SERVICE_NAMES)

    assert isinstance(dataframe, pd.DataFrame)
    assert "service" in dataframe.columns
    assert "response_type" in dataframe.columns
    assert "nrc" in dataframe.columns
    assert "Security Access" in set(dataframe["service"])
    assert "0x35 invalidKey" in set(dataframe["nrc"])


def test_trace_analytics_counts_rows_and_verdicts():
    spec = load_spec(ROOT / "specs" / "apim_spec.json")
    trace_path = ROOT / "traces" / "apim_security_fail_trace.csv"
    steps = load_trace_csv(trace_path)
    findings = validate_trace(steps, spec)

    metrics = build_trace_analytics(trace_path, findings)

    assert metrics.row_count == 4
    assert metrics.security_related_rows >= 3
    assert int(metrics.verdict_counts.loc[metrics.verdict_counts["verdict"] == "FAIL", "count"].iloc[0]) == 2


def test_metrics_report_contains_pandas_summary_sections():
    trace_path = ROOT / "traces" / "apim_did_out_of_range_trace.csv"
    metrics = build_trace_analytics(trace_path, [])
    report = build_metrics_report(metrics)

    assert "UDS Trace Analytics - pandas summary" in report
    assert "Service usage" in report
    assert "Response classification" in report
    assert "DID usage" in report


def test_export_metrics_csv_writes_file(tmp_path):
    trace_path = ROOT / "traces" / "apim_did_out_of_range_trace.csv"
    metrics = build_trace_analytics(trace_path, [])
    output_path = tmp_path / "metrics.csv"

    saved = export_metrics_csv(metrics, output_path)

    assert Path(saved).exists()
    exported = pd.read_csv(saved)
    assert "section" in exported.columns
    assert "service_usage" in set(exported["section"])
