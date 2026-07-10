"""
Tests for cli.py -- the headless entry point.

The exit-code contract matters: it is what lets a CI pipeline fail a
firmware build when a diagnostic trace stops conforming. These tests
pin that contract down.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cli import main

ROOT = os.path.join(os.path.dirname(__file__), "..")


def trace(name):
    return os.path.join(ROOT, "traces", name)


def test_pass_trace_exits_zero(capsys):
    assert main([trace("apim_pass_trace.csv"), "--quiet"]) == 0
    assert "OVERALL: PASS" in capsys.readouterr().out


def test_fail_trace_exits_one(capsys):
    assert main([trace("apim_security_fail_trace.csv"), "--quiet"]) == 1
    assert "OVERALL: FAIL" in capsys.readouterr().out


def test_info_trace_exits_zero():
    # INFO findings (trace-consistency) must not fail a pipeline.
    assert main([trace("apim_state_mismatch_trace.csv"), "--quiet"]) == 0


def test_missing_trace_exits_two(capsys):
    assert main([trace("does_not_exist.csv"), "--quiet"]) == 2
    assert "error" in capsys.readouterr().err


def test_bad_spec_exits_two(tmp_path, capsys):
    bad_spec = tmp_path / "bad.json"
    bad_spec.write_text("{ not json }")
    assert main([trace("apim_pass_trace.csv"),
                 "--spec", str(bad_spec), "--quiet"]) == 2
    assert "error" in capsys.readouterr().err


def test_report_flag_writes_markdown(tmp_path):
    out = tmp_path / "note.md"
    main([trace("apim_security_fail_trace.csv"), "--quiet",
          "--report", str(out)])
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# UDS V&V Triage Report")
    assert "securityAccessDenied" in text
