"""
Unit tests for rules_engine.py -- the spec-driven validation layer.

Each test builds a tiny trace in memory and checks the engine produces
the expected verdicts. The bundled sample traces are also validated
end-to-end so the shipped demo assets can never silently rot.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from spec_loader import load_spec
from rules_engine import (TraceStep, load_trace_csv, validate_trace,
                          worst_verdict, PASS, FAIL, BLOCKED, INFO,
                          CAT_SECURITY, CAT_PROCEDURE, CAT_SEQUENCE, CAT_TRACE)

ROOT = os.path.join(os.path.dirname(__file__), "..")
SPEC = load_spec(os.path.join(ROOT, "specs", "apim_spec.json"))


def step(n, req, rsp, session="default", security="locked", note=""):
    """Shorthand TraceStep factory for readable tests."""
    return TraceStep(step=n, module="APIM", request=req, response=rsp,
                     declared_session=session, declared_security=security,
                     note=note)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_clean_read_trace_passes():
    steps = [
        step(1, "10 03", "50 03"),
        step(2, "22 F1 90", "62 F1 90 41", session="extended"),
    ]
    findings = validate_trace(steps, SPEC)
    assert worst_verdict(findings) == PASS


# ---------------------------------------------------------------------------
# Derived state: session and security come from ECU responses, not columns
# ---------------------------------------------------------------------------

def test_declared_vs_derived_session_mismatch_flagged():
    steps = [
        step(1, "10 03", "50 03"),
        # Tester CLAIMS default, but the ECU said extended in step 1.
        step(2, "22 F1 90", "62 F1 90 41", session="default"),
    ]
    findings = validate_trace(steps, SPEC)
    assert any(f.category == CAT_TRACE for f in findings)


def test_session_change_relocks_security():
    steps = [
        step(1, "10 03", "50 03"),
        step(2, "27 01", "67 01 11 22", session="extended"),
        step(3, "27 02 AA BB", "67 02", session="extended"),   # unlocked...
        step(4, "10 03", "50 03", session="extended", security="unlocked"),
        # ...but re-entering a session relocks. Write must now FAIL procedure.
        step(5, "2E F1 90 01", "7F 2E 33", session="extended"),
    ]
    findings = validate_trace(steps, SPEC)
    step5 = [f for f in findings if f.step == 5]
    assert any(f.verdict == FAIL and f.category == CAT_PROCEDURE
               for f in step5)


# ---------------------------------------------------------------------------
# Security findings (the cybersecurity angle)
# ---------------------------------------------------------------------------

def test_positive_response_to_undocumented_did_is_security_fail():
    steps = [
        step(1, "10 03", "50 03"),
        step(2, "22 D0 12", "62 D0 12 01", session="extended"),
    ]
    findings = validate_trace(steps, SPEC)
    assert any(f.verdict == FAIL and f.category == CAT_SECURITY
               for f in findings)


def test_write_accepted_while_locked_is_security_fail():
    steps = [
        step(1, "10 03", "50 03"),
        # Spec requires security for 0x2E, but ECU answers positively
        # while derived security is still locked -> missing gate.
        step(2, "2E F1 90 01", "6E F1 90", session="extended"),
    ]
    findings = validate_trace(steps, SPEC)
    assert any(f.verdict == FAIL and f.category == CAT_SECURITY
               for f in findings)


def test_correct_rejection_of_unknown_did_passes():
    steps = [
        step(1, "10 03", "50 03"),
        step(2, "22 F1 99", "7F 22 31", session="extended"),
    ]
    findings = validate_trace(steps, SPEC)
    assert worst_verdict(findings) == PASS


# ---------------------------------------------------------------------------
# Programming sequence
# ---------------------------------------------------------------------------

def test_out_of_order_sequence_fails_and_blocks_rest():
    steps = [
        step(1, "10 03", "50 03"),
        step(2, "10 02", "50 02", session="extended"),
        # 0x34 before the 27 01/27 02 unlock -> sequence violation.
        step(3, "34 00 44 00 08", "7F 34 33", session="programming"),
    ]
    findings = validate_trace(steps, SPEC)
    seq = [f for f in findings if f.category == CAT_SEQUENCE]
    assert any(f.verdict == FAIL for f in seq)
    assert any(f.verdict == BLOCKED for f in seq)


def test_sequence_check_skipped_for_plain_read_trace():
    steps = [
        step(1, "10 03", "50 03"),
        step(2, "22 F1 90", "62 F1 90 41", session="extended"),
    ]
    findings = validate_trace(steps, SPEC)
    assert not any(f.category == CAT_SEQUENCE for f in findings)


# ---------------------------------------------------------------------------
# Protocol pairing
# ---------------------------------------------------------------------------

def test_mispaired_response_fails():
    steps = [
        # Response 0x62 belongs to 0x22, not to the 0x2E request sent.
        step(1, "2E F1 90 01", "62 F1 90 41", session="default"),
    ]
    findings = validate_trace(steps, SPEC)
    assert worst_verdict(findings) == FAIL


# ---------------------------------------------------------------------------
# End-to-end: every bundled sample trace must produce its intended verdict.
# This keeps the shipped demo assets honest.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("trace_file,expected_overall", [
    ("apim_pass_trace.csv", PASS),
    ("apim_flash_pass_trace.csv", PASS),
    ("apim_did_out_of_range_trace.csv", PASS),
    ("apim_security_fail_trace.csv", FAIL),
    ("apim_undocumented_did_trace.csv", FAIL),
    ("apim_flash_sequence_fail_trace.csv", FAIL),
    ("apim_state_mismatch_trace.csv", INFO),
])
def test_bundled_traces_end_to_end(trace_file, expected_overall):
    steps = load_trace_csv(os.path.join(ROOT, "traces", trace_file))
    findings = validate_trace(steps, SPEC)
    assert worst_verdict(findings) == expected_overall
