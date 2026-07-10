"""
rules_engine.py
===============
The heart of the workbench: spec-driven conformance validation.

WHAT MAKES THIS A V&V TOOL AND NOT A DECODER:
1. Every check compares OBSERVED behavior (the trace) against EXPECTED
   behavior (the spec). No expectations are hardcoded here.
2. Session and security state are DERIVED from the ECU's own responses
   (50 03 = extended entered, 67 02 = unlocked, 51 01 = reset...), never
   trusted from the trace's declared columns. Validating against declared
   state would be circular -- you'd be checking the ECU against the
   tester's claim instead of against reality. Declared vs. derived
   mismatches are reported as trace-consistency findings.
3. Verdicts follow test-engineering semantics:
       PASS    - observed behavior conforms to the spec
       FAIL    - observed behavior violates the spec (or the test
                 procedure made a request the spec says cannot succeed)
       BLOCKED - a check could not be evaluated because an earlier step
                 failed (distinct from FAIL: nothing is known to be wrong,
                 it simply could not be tested)
       INFO    - context worth recording, no conformance judgement
"""

import csv
from dataclasses import dataclass, field
from typing import Optional

import uds_decoder as dec
from spec_loader import DiagnosticSpec

# Verdict constants -- keep as plain strings so reports/GUI need no imports.
PASS, FAIL, BLOCKED, INFO = "PASS", "FAIL", "BLOCKED", "INFO"

# Finding categories (used for filtering/reporting).
CAT_CONFORMANCE = "conformance"          # ECU behavior vs spec
CAT_PROCEDURE = "procedure"              # test-procedure problem (tester side)
CAT_SECURITY = "security"                # attack-surface finding
CAT_SEQUENCE = "sequence"                # programming-sequence order
CAT_TRACE = "trace_consistency"          # declared vs derived state mismatch
CAT_DECODE = "decode"                    # malformed payloads / protocol errors


@dataclass
class TraceStep:
    """One request/response exchange from the trace CSV."""
    step: int
    module: str
    request: str          # raw hex text, e.g. "22 F1 90"
    response: str
    declared_session: str
    declared_security: str  # "locked" | "unlocked"
    note: str = ""
    # Filled during validation:
    req_decoded: Optional[dec.DecodedMessage] = None
    rsp_decoded: Optional[dec.DecodedMessage] = None


@dataclass
class Finding:
    """One validation result. Optional triage fields feed the report."""
    verdict: str
    category: str
    message: str
    step: Optional[int] = None            # trace step number, if applicable
    expected: Optional[str] = None
    actual: Optional[str] = None
    possible_cause: Optional[str] = None
    next_step: Optional[str] = None


@dataclass
class EcuState:
    """Session/security state DERIVED from ECU responses only."""
    session: str = "default"
    security: str = "locked"


# ---------------------------------------------------------------------------
# Trace loading
# ---------------------------------------------------------------------------

REQUIRED_COLUMNS = {"step", "module", "request", "response",
                    "session", "security_state"}


def load_trace_csv(path: str) -> list:
    """Load a trace CSV into TraceStep objects, validating the header."""
    steps = []
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"Trace CSV missing required columns: {sorted(missing)}")
        for row in reader:
            steps.append(TraceStep(
                step=int(row["step"]),
                module=row["module"].strip(),
                request=row["request"].strip(),
                response=row["response"].strip(),
                declared_session=row["session"].strip().lower(),
                declared_security=row["security_state"].strip().lower(),
                note=(row.get("note") or "").strip(),
            ))
    return steps


# ---------------------------------------------------------------------------
# State derivation
# ---------------------------------------------------------------------------

def _advance_state(state: EcuState, rsp: dec.DecodedMessage) -> None:
    """
    Update derived state from a POSITIVE ECU response.

    Session-change and reset both relock security -- ISO 14229-1 requires
    security access to be re-earned after a session transition.
    """
    if rsp.kind != "positive":
        return  # negative responses never change session/security state
    if rsp.sid == 0x10 and rsp.subfunction is not None:
        state.session = dec.SESSION_TYPES.get(rsp.subfunction, "unknown")
        state.security = "locked"      # session change relocks security
    elif rsp.sid == 0x27 and rsp.subfunction is not None:
        if rsp.subfunction % 2 == 0:   # even sub-function = sendKey accepted
            state.security = "unlocked"
    elif rsp.sid == 0x11:
        state.session = "default"      # ECU reset returns to default session
        state.security = "locked"


# ---------------------------------------------------------------------------
# Per-step checks
# ---------------------------------------------------------------------------

def _check_step(step: TraceStep, spec: DiagnosticSpec,
                state: EcuState) -> list:
    """Run every per-step check against the state BEFORE this request."""
    findings = []
    add = findings.append

    # ---- decode both payloads; malformed hex is a finding, not a crash ----
    try:
        req = dec.decode_request(step.request)
        rsp = dec.decode_response(step.response, request_sid=req.sid)
    except ValueError as exc:
        add(Finding(FAIL, CAT_DECODE, f"Malformed payload: {exc}",
                    step=step.step,
                    next_step="Fix the trace row; hex bytes must be valid."))
        return findings
    step.req_decoded, step.rsp_decoded = req, rsp

    # ---- 0. declared vs derived state (trace quality) --------------------
    if step.declared_session and step.declared_session != state.session:
        add(Finding(INFO, CAT_TRACE,
                    f"Declared session '{step.declared_session}' does not match "
                    f"state derived from ECU responses ('{state.session}'). "
                    f"The trace log may be unreliable.",
                    step=step.step,
                    expected=f"derived session '{state.session}'",
                    actual=f"declared session '{step.declared_session}'",
                    next_step="Verify the tester logged session state correctly."))
    if step.declared_security and step.declared_security != state.security:
        add(Finding(INFO, CAT_TRACE,
                    f"Declared security '{step.declared_security}' does not "
                    f"match derived state ('{state.security}').",
                    step=step.step,
                    expected=f"derived security '{state.security}'",
                    actual=f"declared security '{step.declared_security}'",
                    next_step="Verify the tester logged security state correctly."))

    # ---- 1. response must actually belong to this request ----------------
    if not dec.response_matches_request(req.sid, rsp):
        add(Finding(FAIL, CAT_DECODE,
                    f"Response {rsp.raw_hex} is not a valid reply to request "
                    f"{req.raw_hex} (expected 0x{dec.positive_response_sid(req.sid):02X} "
                    f"or 7F {req.sid:02X} <NRC>).",
                    step=step.step,
                    expected=f"SID 0x{dec.positive_response_sid(req.sid):02X} (+0x40 rule) or 7F {req.sid:02X} xx",
                    actual=rsp.raw_hex,
                    possible_cause="Interleaved traffic from another request, or a gateway/routing defect.",
                    next_step="Capture the exchange again and confirm request/response pairing."))
        return findings  # remaining checks assume a paired response

    rule = spec.service(req.sid)

    # ---- 2. is the service in the spec at all? ----------------------------
    if rule is None:
        if rsp.kind == "positive":
            # ECU accepted a service the spec says it does not implement.
            # That is an attack-surface / documentation-gap finding.
            add(Finding(FAIL, CAT_SECURITY,
                        f"ECU returned a POSITIVE response to service "
                        f"0x{req.sid:02X} ({req.service_name}), which is not in "
                        f"the diagnostic spec. Undocumented service = "
                        f"unreviewed attack surface.",
                        step=step.step,
                        expected=f"7F {req.sid:02X} 11 (serviceNotSupported)",
                        actual=rsp.summary,
                        possible_cause="Spec is incomplete, or the ECU exposes an undocumented service.",
                        next_step="Confirm with the diagnostic spec owner; if the service is real, add it to the spec and review its security requirements."))
        else:
            add(Finding(PASS, CAT_CONFORMANCE,
                        f"ECU correctly rejected unsupported service "
                        f"0x{req.sid:02X} ({rsp.nrc_name}).",
                        step=step.step))
        return findings

    # ---- 3. session precondition (uses DERIVED session) -------------------
    session_ok = state.session in rule.allowed_sessions
    if not session_ok:
        if rsp.kind == "negative" and rsp.nrc in (0x7F, 0x7E, 0x22):
            add(Finding(PASS, CAT_CONFORMANCE,
                        f"ECU correctly rejected 0x{req.sid:02X} in "
                        f"'{state.session}' session (NRC 0x{rsp.nrc:02X} "
                        f"{rsp.nrc_name}); spec allows it only in "
                        f"{rule.allowed_sessions}.",
                        step=step.step))
        elif rsp.kind == "positive":
            add(Finding(FAIL, CAT_CONFORMANCE,
                        f"ECU accepted 0x{req.sid:02X} ({rule.name}) in "
                        f"'{state.session}' session, but the spec restricts it "
                        f"to {rule.allowed_sessions}.",
                        step=step.step,
                        expected=f"Rejection (e.g. NRC 0x7F) outside sessions {rule.allowed_sessions}",
                        actual=rsp.summary,
                        possible_cause="Session enforcement is missing or the spec's session mapping is wrong.",
                        next_step="Confirm the session table in the diagnostic spec, then review the ECU's session gating."))
        else:
            add(Finding(FAIL, CAT_PROCEDURE,
                        f"Test procedure sent 0x{req.sid:02X} in "
                        f"'{state.session}' session where the spec does not "
                        f"allow it, and the ECU rejected it "
                        f"(NRC 0x{rsp.nrc:02X} {rsp.nrc_name}).",
                        step=step.step,
                        expected=f"Enter one of {rule.allowed_sessions} before sending 0x{req.sid:02X}",
                        actual=f"Session '{state.session}' at time of request",
                        possible_cause="Missing or failed 0x10 session transition earlier in the sequence.",
                        next_step="Verify the session transition steps preceding this request."))
        return findings  # precondition failed; later checks are moot

    # ---- 4. security precondition (uses DERIVED security) -----------------
    if rule.requires_security and state.security == "locked":
        if rsp.kind == "negative" and rsp.nrc == 0x33:
            # ECU behaved correctly, but the TEST PROCEDURE is broken:
            # it requested something the spec says cannot succeed here.
            add(Finding(FAIL, CAT_PROCEDURE,
                        f"0x{req.sid:02X} ({rule.name}) was requested while "
                        f"security is locked. ECU correctly answered NRC 0x33 "
                        f"(securityAccessDenied) -- ECU conforms, but the test "
                        f"step cannot pass as written.",
                        step=step.step,
                        expected="Successful 0x27 seed/key unlock before this request",
                        actual=f"Security '{state.security}' at time of request; response {rsp.raw_hex}",
                        possible_cause="Security Access unlock (27 01 / 27 02) missing, failed, or relocked by a session change.",
                        next_step="Verify the session transition, the 0x27 unlock exchange, and this service's access permissions in the spec."))
        elif rsp.kind == "positive":
            # This is the serious one: security gate absent.
            add(Finding(FAIL, CAT_SECURITY,
                        f"ECU accepted 0x{req.sid:02X} ({rule.name}) while "
                        f"security is LOCKED, but the spec requires security "
                        f"access. Missing security enforcement.",
                        step=step.step,
                        expected="NRC 0x33 (securityAccessDenied) while locked",
                        actual=rsp.summary,
                        possible_cause="Security gate not implemented for this service, or unlock state leaked across sessions.",
                        next_step="Escalate: verify security access enforcement in the ECU firmware for this service."))
        else:
            add(Finding(INFO, CAT_CONFORMANCE,
                        f"0x{req.sid:02X} rejected with NRC 0x{rsp.nrc:02X} "
                        f"({rsp.nrc_name}) while locked; spec expects 0x33 for "
                        f"security-gated services.",
                        step=step.step))
        return findings

    # ---- 5. DID checks for 0x22 / 0x2E -----------------------------------
    if req.sid in dec.SERVICES_WITH_DID and rule.supported_dids is not None:
        if req.did is None:
            add(Finding(FAIL, CAT_DECODE,
                        f"Request {req.raw_hex} is too short to carry a DID.",
                        step=step.step))
            return findings
        did_known = req.did in rule.supported_dids
        if not did_known:
            if rsp.kind == "positive":
                # Undocumented DID answered positively = security finding.
                add(Finding(FAIL, CAT_SECURITY,
                            f"ECU returned data for DID {req.did}, which is NOT "
                            f"in the diagnostic spec for 0x{req.sid:02X}. "
                            f"Undocumented DID = unreviewed data exposure.",
                            step=step.step,
                            expected="7F 22 31 (requestOutOfRange) for out-of-spec DIDs",
                            actual=rsp.summary,
                            possible_cause="Spec is incomplete, or the ECU exposes an undocumented data identifier.",
                            next_step="Confirm with the spec owner. If the DID is real, document it and review what data it exposes and at what access level."))
            elif rsp.nrc == 0x31:
                add(Finding(PASS, CAT_CONFORMANCE,
                            f"ECU correctly rejected out-of-spec DID {req.did} "
                            f"with NRC 0x31 (requestOutOfRange).",
                            step=step.step))
            else:
                add(Finding(INFO, CAT_CONFORMANCE,
                            f"Out-of-spec DID {req.did} rejected with NRC "
                            f"0x{rsp.nrc:02X} ({rsp.nrc_name}); 0x31 is the "
                            f"conventional NRC for unknown DIDs.",
                            step=step.step))
            return findings
        # DID is in spec: a positive response should echo it back.
        if rsp.kind == "positive" and rsp.did != req.did:
            add(Finding(FAIL, CAT_CONFORMANCE,
                        f"Positive response echoes DID {rsp.did}, but the "
                        f"request asked for DID {req.did}.",
                        step=step.step,
                        expected=f"Response DID {req.did}",
                        actual=f"Response DID {rsp.did}",
                        possible_cause="Response pairing error in the trace, or an ECU echo defect.",
                        next_step="Re-capture the exchange; if reproducible, file against the ECU."))
            return findings

    # ---- 6. all preconditions satisfied: judge the outcome ---------------
    if rsp.kind == "positive":
        add(Finding(PASS, CAT_CONFORMANCE,
                    f"0x{req.sid:02X} ({rule.name})"
                    + (f" DID {req.did}" if req.did and req.sid in dec.SERVICES_WITH_DID else "")
                    + f" answered positively ({rsp.raw_hex}) with all spec "
                      f"preconditions met.",
                    step=step.step))
    else:
        # Preconditions were met, yet the ECU rejected the request.
        cause_map = {
            0x22: "An internal condition (voltage, speed, state) blocked the request.",
            0x24: "The ECU believes a prerequisite step was skipped -- check the sequence.",
            0x31: "The ECU considers the request parameters out of range despite the spec.",
            0x35: "The security key sent in 27 02 was wrong (seed/key algorithm mismatch?).",
            0x36: "Too many failed unlock attempts; the ECU is in attempt-lockout.",
            0x37: "Unlock attempted before the ECU's retry delay expired.",
            0x72: "Programming step failed inside the ECU (memory/driver error).",
            0x78: "Response pending -- the tester must wait for the final response.",
        }
        add(Finding(FAIL, CAT_CONFORMANCE,
                    f"0x{req.sid:02X} ({rule.name}) rejected with NRC "
                    f"0x{rsp.nrc:02X} ({rsp.nrc_name}) even though all spec "
                    f"preconditions (session '{state.session}', security "
                    f"'{state.security}') were satisfied.",
                    step=step.step,
                    expected=f"Positive response 0x{dec.positive_response_sid(req.sid):02X}",
                    actual=rsp.summary,
                    possible_cause=cause_map.get(rsp.nrc,
                        "ECU-internal condition not modeled by the spec."),
                    next_step="Reproduce with the same preconditions; if consistent, file a defect against the ECU or correct the spec."))
    return findings


# ---------------------------------------------------------------------------
# Programming-sequence check
# ---------------------------------------------------------------------------

def _check_programming_sequence(steps: list, spec: DiagnosticSpec) -> list:
    """
    Verify observed programming-related messages follow the spec's expected
    order. Only runs when the trace actually attempts programming (contains
    0x34/0x36/0x37) -- a plain read trace should not be judged against a
    flash sequence.
    """
    findings = []
    expected = spec.programming_sequence
    if not expected:
        return findings

    attempted = any(s.req_decoded and s.req_decoded.sid in (0x34, 0x36, 0x37)
                    for s in steps)
    if not attempted:
        return findings

    sequence_sids = {e.sid for e in expected}
    observed = [(s.req_decoded.sid, s.req_decoded.subfunction, s.step)
                for s in steps
                if s.req_decoded and s.req_decoded.sid in sequence_sids]

    def matches(entry, sid, sub):
        if entry.sid != sid:
            return False
        return entry.subfunction is None or entry.subfunction == sub

    i = 0  # index into expected
    for sid, sub, step_no in observed:
        advanced = False
        while i < len(expected):
            entry = expected[i]
            if matches(entry, sid, sub):
                if not entry.repeat:
                    i += 1  # consume the expected slot
                advanced = True
                break
            if entry.repeat:
                i += 1      # a repeatable step may end at any time
                continue
            # Mandatory expected step skipped or out of order -> FAIL,
            # and everything after it is BLOCKED, not failed.
            findings.append(Finding(
                FAIL, CAT_SEQUENCE,
                f"Programming sequence violation at trace step {step_no}: "
                f"observed 0x{sid:02X}"
                + (f" sub 0x{sub:02X}" if sub is not None else "")
                + f" while the spec expects {entry.label()} next.",
                step=step_no,
                expected=f"Next sequence step: {entry.label()}",
                actual=f"0x{sid:02X}" + (f" sub 0x{sub:02X}" if sub is not None else ""),
                possible_cause="Test script skipped a step, or steps were reordered.",
                next_step="Correct the test sequence to match the spec's expected programming flow."))
            for later in expected[i + 1:]:
                findings.append(Finding(
                    BLOCKED, CAT_SEQUENCE,
                    f"Sequence step {later.label()} not evaluated: sequence "
                    f"already broken at trace step {step_no}.",
                    step=step_no))
            return findings
        if not advanced and i >= len(expected):
            findings.append(Finding(
                INFO, CAT_SEQUENCE,
                f"Extra programming-related message 0x{sid:02X} at trace step "
                f"{step_no} after the expected sequence completed.",
                step=step_no))

    # Skip trailing repeat entries when deciding completeness.
    remaining = [e for e in expected[i:] if not e.repeat]
    if remaining:
        findings.append(Finding(
            INFO, CAT_SEQUENCE,
            f"Programming sequence incomplete: trace ends before "
            f"{', '.join(e.label() for e in remaining)}.",
            next_step="Confirm whether the trace intentionally stops early."))
    else:
        findings.append(Finding(
            PASS, CAT_SEQUENCE,
            "Observed programming sequence conforms to the spec's expected "
            "order."))
    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def validate_trace(steps: list, spec: DiagnosticSpec) -> list:
    """
    Run the full validation: per-step checks with derived state tracking,
    then the programming-sequence check. Returns a flat list of Findings.
    """
    findings = []
    state = EcuState()  # ECU boots in default session, security locked
    for step in steps:
        # Checks run against the state BEFORE this request...
        findings.extend(_check_step(step, spec, state))
        # ...then the ECU's response advances the derived state.
        if step.rsp_decoded is not None:
            _advance_state(state, step.rsp_decoded)
    findings.extend(_check_programming_sequence(steps, spec))
    return findings


def worst_verdict(findings: list) -> str:
    """Collapse findings to a single overall verdict (for GUI/report)."""
    order = {FAIL: 3, BLOCKED: 2, INFO: 1, PASS: 0}
    if not findings:
        return INFO
    return max(findings, key=lambda f: order.get(f.verdict, 0)).verdict


def verdict_for_step(findings: list, step_no: int) -> str:
    """Worst verdict among findings attached to one trace step."""
    step_findings = [f for f in findings if f.step == step_no]
    if not step_findings:
        return PASS
    return worst_verdict(step_findings)
