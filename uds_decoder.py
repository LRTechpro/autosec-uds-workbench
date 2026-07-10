"""
uds_decoder.py
==============
UDS (ISO 14229-1) request/response decoder for the AutoSec UDS Conformance
Workbench.

DESIGN RULE: This module contains ONLY protocol knowledge. It has no idea
what an "expected" behavior is (that lives in the spec + rules engine) and
it never imports Tkinter. That separation is what lets the decoder be
reused later in a CLI tool, a pytest fixture, or a CI pipeline.

KEY PROTOCOL FACT implemented here (not hardcoded per-service):
    Positive Response SID = Request SID + 0x40        (ISO 14229-1)
    e.g. 0x22 -> 0x62, 0x27 -> 0x67, 0x34 -> 0x74, 0x2E -> 0x6E
    Negative responses always start with 0x7F followed by the rejected
    request SID and a Negative Response Code (NRC):  7F <SID> <NRC>
"""

from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Protocol tables (ISO 14229-1)
# ---------------------------------------------------------------------------

NEGATIVE_RESPONSE_SID = 0x7F     # First byte of every negative response
POSITIVE_RESPONSE_OFFSET = 0x40  # The "+0x40 rule"

# Diagnostic services supported by the decoder (v1 scope).
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

# Negative Response Codes. The names matter in triage: two different NRCs
# after the same request usually point at two different root-cause owners
# (e.g. 0x31 = the request itself is wrong; 0x33 = preconditions are wrong).
NRC_TABLE = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceived-ResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

# Sub-function decode tables per service.
SESSION_TYPES = {  # 0x10 sub-functions
    0x01: "default",
    0x02: "programming",
    0x03: "extended",
    0x04: "safetySystem",
}
RESET_TYPES = {  # 0x11 sub-functions
    0x01: "hardReset",
    0x02: "keyOffOnReset",
    0x03: "softReset",
}
ROUTINE_CONTROL_TYPES = {  # 0x31 sub-functions
    0x01: "startRoutine",
    0x02: "stopRoutine",
    0x03: "requestRoutineResults",
}

# Services whose second byte is a sub-function (v1 scope).
SERVICES_WITH_SUBFUNCTION = {0x10, 0x11, 0x27, 0x31, 0x3E}
# Services whose payload carries a 2-byte Data Identifier (DID).
SERVICES_WITH_DID = {0x22, 0x2E}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DecodedMessage:
    """Everything the workbench knows about one UDS payload."""
    raw: list                      # raw bytes as list of ints
    kind: str = "unknown"          # "request" | "positive" | "negative"
    sid: Optional[int] = None      # service id of the REQUEST this relates to
    service_name: str = "Unknown Service"
    subfunction: Optional[int] = None
    subfunction_name: Optional[str] = None
    did: Optional[str] = None      # e.g. "F190" (uppercase hex, no 0x)
    nrc: Optional[int] = None
    nrc_name: Optional[str] = None
    summary: str = ""              # one-line human-readable description
    data_bytes: list = field(default_factory=list)  # payload after header

    @property
    def raw_hex(self) -> str:
        """'22 F1 90' style rendering for GUI panes and reports."""
        return " ".join(f"{b:02X}" for b in self.raw)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_hex(text: str) -> list:
    """
    Parse a hex string like '22 F1 90' or '22F190' into [0x22, 0xF1, 0x90].
    Raises ValueError on malformed input so callers can surface a clean
    error instead of silently mis-decoding.
    """
    cleaned = text.replace(",", " ").replace("0x", " ").strip()
    # Support both space-separated and continuous hex.
    if " " in cleaned:
        parts = cleaned.split()
    else:
        if len(cleaned) % 2 != 0:
            raise ValueError(f"Odd-length hex string: {text!r}")
        parts = [cleaned[i:i + 2] for i in range(0, len(cleaned), 2)]
    try:
        data = [int(p, 16) for p in parts]
    except ValueError:
        raise ValueError(f"Invalid hex byte in: {text!r}")
    if not data:
        raise ValueError("Empty payload")
    if any(not (0 <= b <= 0xFF) for b in data):
        raise ValueError(f"Byte out of range in: {text!r}")
    return data


def positive_response_sid(request_sid: int) -> int:
    """ISO 14229-1 +0x40 rule. One line, applies to every service."""
    return request_sid + POSITIVE_RESPONSE_OFFSET


def service_name(sid: int) -> str:
    return SERVICE_NAMES.get(sid, f"Unknown/Unsupported (0x{sid:02X})")


def _subfunction_name(sid: int, sub: int) -> Optional[str]:
    """Look up the human name for a sub-function, per service."""
    table = {
        0x10: SESSION_TYPES,
        0x11: RESET_TYPES,
        0x31: ROUTINE_CONTROL_TYPES,
    }.get(sid)
    if table is not None:
        return table.get(sub, f"unknown(0x{sub:02X})")
    if sid == 0x27:
        # Odd sub-function = requestSeed, even = sendKey (ISO 14229-1).
        return "requestSeed" if sub % 2 == 1 else "sendKey"
    if sid == 0x3E:
        return "zeroSubFunction" if sub == 0x00 else f"unknown(0x{sub:02X})"
    return None


def _extract_did(payload: list) -> Optional[str]:
    """DID = bytes 2..3 of a 0x22/0x2E request (or its echo in the response)."""
    if len(payload) >= 3:
        return f"{payload[1]:02X}{payload[2]:02X}"
    return None


# ---------------------------------------------------------------------------
# Public decode API
# ---------------------------------------------------------------------------

def decode_request(payload) -> DecodedMessage:
    """Decode a tester->ECU request. Accepts a hex string or list of ints."""
    raw = parse_hex(payload) if isinstance(payload, str) else list(payload)
    sid = raw[0]
    msg = DecodedMessage(raw=raw, kind="request", sid=sid,
                         service_name=service_name(sid))

    if sid in SERVICES_WITH_SUBFUNCTION and len(raw) >= 2:
        # Bit 7 of the sub-function byte is suppressPosRspMsgIndicationBit;
        # mask it off so 3E 80 (tester present, suppressed) decodes cleanly.
        msg.subfunction = raw[1] & 0x7F
        msg.subfunction_name = _subfunction_name(sid, msg.subfunction)
        msg.data_bytes = raw[2:]
    elif sid in SERVICES_WITH_DID:
        msg.did = _extract_did(raw)
        msg.data_bytes = raw[3:]
    else:
        msg.data_bytes = raw[1:]

    # Routine Control also carries a 2-byte routine identifier after the
    # sub-function: 31 <type> <RID hi> <RID lo> ...
    if sid == 0x31 and len(raw) >= 4:
        msg.did = f"{raw[2]:02X}{raw[3]:02X}"  # reuse .did slot for the RID

    parts = [f"0x{sid:02X} {msg.service_name}"]
    if msg.subfunction_name:
        parts.append(f"sub-function 0x{msg.subfunction:02X} ({msg.subfunction_name})")
    if msg.did and sid in SERVICES_WITH_DID:
        parts.append(f"DID {msg.did}")
    if msg.did and sid == 0x31:
        parts.append(f"RID {msg.did}")
    msg.summary = " - ".join(parts)
    return msg


def decode_response(payload, request_sid: Optional[int] = None) -> DecodedMessage:
    """
    Decode an ECU->tester response.

    `request_sid` (when known from the trace) lets the caller verify the
    +0x40 rule via response_matches_request(): a "positive" response whose
    SID doesn't equal request SID + 0x40 is itself a protocol violation.
    """
    raw = parse_hex(payload) if isinstance(payload, str) else list(payload)
    first = raw[0]

    # ---- Negative response: 7F <rejected SID> <NRC> ----
    if first == NEGATIVE_RESPONSE_SID:
        msg = DecodedMessage(raw=raw, kind="negative")
        if len(raw) >= 2:
            msg.sid = raw[1]
            msg.service_name = service_name(raw[1])
        if len(raw) >= 3:
            msg.nrc = raw[2]
            msg.nrc_name = NRC_TABLE.get(raw[2], f"unknownNRC(0x{raw[2]:02X})")
        msg.summary = (f"Negative Response to 0x{msg.sid:02X} {msg.service_name} "
                       f"- NRC 0x{msg.nrc:02X} ({msg.nrc_name})"
                       if msg.nrc is not None else "Malformed negative response")
        return msg

    # ---- Positive response: derive the original SID via the +0x40 rule ----
    original_sid = first - POSITIVE_RESPONSE_OFFSET
    msg = DecodedMessage(raw=raw, kind="positive", sid=original_sid,
                         service_name=service_name(original_sid))

    if original_sid in SERVICES_WITH_SUBFUNCTION and len(raw) >= 2:
        msg.subfunction = raw[1] & 0x7F
        msg.subfunction_name = _subfunction_name(original_sid, msg.subfunction)
        msg.data_bytes = raw[2:]
    elif original_sid in SERVICES_WITH_DID:
        msg.did = _extract_did(raw)  # positive 0x62/0x6E echoes the DID
        msg.data_bytes = raw[3:]
    else:
        msg.data_bytes = raw[1:]

    msg.summary = (f"Positive Response 0x{first:02X} "
                   f"(0x{original_sid:02X} {msg.service_name})")
    if msg.did:
        msg.summary += f" - DID {msg.did}"
    if msg.subfunction_name:
        msg.summary += f" - 0x{msg.subfunction:02X} ({msg.subfunction_name})"
    return msg


def response_matches_request(request_sid: int, response: DecodedMessage) -> bool:
    """
    True if the response is a valid reply to `request_sid`:
    either 7F <request_sid> <nrc>, or first byte == request_sid + 0x40.
    """
    if response.kind == "negative":
        return response.sid == request_sid
    if response.kind == "positive":
        return response.raw[0] == positive_response_sid(request_sid)
    return False
