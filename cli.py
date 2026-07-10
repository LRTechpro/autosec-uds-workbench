"""
cli.py
======
Headless command-line entry point for the AutoSec UDS Conformance Workbench.

WHY THIS FILE EXISTS:
The GUI (main.py) and this CLI are thin shells over the SAME engine
modules. Nothing here re-implements validation -- which is the point:
the engine that a test engineer drives interactively is byte-for-byte
the engine a CI pipeline runs on every firmware commit.

Usage:
    python cli.py traces/apim_pass_trace.csv
    python cli.py traces/apim_security_fail_trace.csv --spec specs/apim_spec.json
    python cli.py traces/apim_flash_pass_trace.csv --report reports/flash.md
    python cli.py traces/apim_pass_trace.csv --quiet   # summary line only

Exit codes (CI-friendly -- a failing trace fails the pipeline):
    0  overall verdict PASS or INFO
    1  overall verdict FAIL or BLOCKED
    2  usage / file / spec error
"""

import argparse
import os
import sys

from spec_loader import load_spec, SpecError
from rules_engine import (load_trace_csv, validate_trace, worst_verdict,
                          PASS, FAIL, BLOCKED, INFO)
from report_writer import build_report, save_report

# Default spec ships with the repo; override with --spec for other ECUs.
DEFAULT_SPEC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "specs", "apim_spec.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autosec-uds-workbench",
        description="Spec-driven UDS conformance validation (headless).")
    parser.add_argument("trace", help="Trace CSV file to validate")
    parser.add_argument("--spec", default=DEFAULT_SPEC,
                        help="Diagnostic spec JSON (default: bundled APIM spec)")
    parser.add_argument("--report", metavar="FILE",
                        help="Also write a Markdown triage report to FILE")
    parser.add_argument("--quiet", action="store_true",
                        help="Print only the summary line (still sets exit code)")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    # ---- load inputs; any problem is exit code 2 (usage error) ----------
    try:
        spec = load_spec(args.spec)
    except (SpecError, OSError) as exc:
        print(f"error: cannot load spec: {exc}", file=sys.stderr)
        return 2
    try:
        steps = load_trace_csv(args.trace)
    except (ValueError, OSError) as exc:
        print(f"error: cannot load trace: {exc}", file=sys.stderr)
        return 2

    # ---- the one real call: same engine the GUI uses ---------------------
    findings = validate_trace(steps, spec)
    overall = worst_verdict(findings)

    # ---- output -----------------------------------------------------------
    if not args.quiet:
        print(f"AutoSec UDS Conformance Workbench - {spec.ecu} "
              f"(spec v{spec.spec_version})")
        print(f"Trace: {args.trace} ({len(steps)} steps)")
        print("-" * 72)
        for f in findings:
            step_txt = f"step {f.step}" if f.step is not None else "trace"
            print(f"[{f.verdict:^7}] {f.category:<17} {step_txt:<8} {f.message}")
        print("-" * 72)

    counts = {v: sum(1 for f in findings if f.verdict == v)
              for v in (PASS, FAIL, BLOCKED, INFO)}
    print(f"OVERALL: {overall}  "
          f"({counts[PASS]} PASS, {counts[FAIL]} FAIL, "
          f"{counts[BLOCKED]} BLOCKED, {counts[INFO]} INFO)")

    if args.report:
        report = build_report(findings, ecu=spec.ecu,
                              trace_file=os.path.basename(args.trace),
                              spec_file=os.path.basename(args.spec),
                              spec_version=spec.spec_version)
        save_report(report, args.report)
        print(f"Report written: {args.report}")

    # ---- exit code drives CI pass/fail -----------------------------------
    return 0 if overall in (PASS, INFO) else 1


if __name__ == "__main__":
    sys.exit(main())
