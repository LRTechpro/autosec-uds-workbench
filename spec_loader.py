"""
spec_loader.py
==============
Loads and validates the machine-readable diagnostic specification (JSON).

WHY A SPEC FILE INSTEAD OF HARDCODED RULES:
In production diagnostics, expected ECU behavior is defined in artifacts
like CDD (CANdela) or ODX files, and test tools validate observed behavior
against them. This JSON spec is a lightweight stand-in for that workflow:
the rules engine never "knows" what an APIM should do -- it only knows what
THIS spec says the ECU under test should do. Swap the spec, and the same
engine validates a different ECU.
"""

import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ServiceRule:
    """Expected behavior for one UDS service, as declared by the spec."""
    sid: int
    name: str
    allowed_sessions: list          # e.g. ["default", "extended"]
    requires_security: bool
    supported_dids: Optional[list] = None  # None = service has no DID concept


@dataclass
class SequenceEntry:
    """One step of the expected programming sequence."""
    sid: int
    subfunction: Optional[int] = None  # None = any sub-function accepted
    repeat: bool = False               # True = step may occur 1..n times (0x36)

    def label(self) -> str:
        if self.subfunction is not None:
            return f"0x{self.sid:02X} sub 0x{self.subfunction:02X}"
        return f"0x{self.sid:02X}"


@dataclass
class DiagnosticSpec:
    """Parsed, validated diagnostic spec for one ECU."""
    ecu: str
    can_id: str
    description: str
    spec_version: str
    services: dict = field(default_factory=dict)   # sid(int) -> ServiceRule
    programming_sequence: list = field(default_factory=list)  # [SequenceEntry]

    def service(self, sid: int) -> Optional[ServiceRule]:
        return self.services.get(sid)

    def is_supported(self, sid: int) -> bool:
        return sid in self.services


class SpecError(Exception):
    """Raised when a spec file is malformed. The GUI shows this verbatim,
    so messages should tell the user exactly what to fix."""


def _parse_hex_id(value: str, context: str) -> int:
    """Accept '0x22' or '22' style keys and normalize to int."""
    try:
        return int(str(value), 16)
    except ValueError:
        raise SpecError(f"Invalid hex id {value!r} in {context}")


def load_spec(path: str) -> DiagnosticSpec:
    """Load a diagnostic spec JSON file, validating structure as we go."""
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise SpecError(f"Spec is not valid JSON: {exc}")

    # --- required top-level fields -----------------------------------
    for key in ("ecu", "supported_services"):
        if key not in data:
            raise SpecError(f"Spec missing required field: {key!r}")

    spec = DiagnosticSpec(
        ecu=data["ecu"],
        can_id=data.get("can_id", "unknown"),
        description=data.get("description", ""),
        spec_version=data.get("spec_version", "0.0"),
    )

    # --- services ------------------------------------------------------
    for sid_str, rule in data["supported_services"].items():
        sid = _parse_hex_id(sid_str, "supported_services")
        if "allowed_sessions" not in rule:
            raise SpecError(f"Service {sid_str}: missing 'allowed_sessions'")
        dids = rule.get("supported_dids")
        if dids is not None:
            # Normalize DIDs to uppercase-no-prefix so comparisons are exact.
            dids = [d.upper().replace("0X", "") for d in dids]
        spec.services[sid] = ServiceRule(
            sid=sid,
            name=rule.get("name", f"Service 0x{sid:02X}"),
            allowed_sessions=[s.lower() for s in rule["allowed_sessions"]],
            requires_security=bool(rule.get("requires_security", False)),
            supported_dids=dids,
        )

    # --- expected programming sequence ----------------------------------
    # Entries are OBJECTS, not bare SIDs, because the sequence must be able
    # to distinguish 10 02 (programming session) from 10 03 (extended) and
    # to model the two-step Security Access exchange (27 01 seed / 27 02 key).
    for i, entry in enumerate(data.get("expected_programming_sequence", [])):
        if isinstance(entry, str):
            # Tolerate legacy bare-SID entries but normalize them.
            spec.programming_sequence.append(
                SequenceEntry(sid=_parse_hex_id(entry, "sequence")))
            continue
        if "service" not in entry:
            raise SpecError(f"Sequence entry {i}: missing 'service'")
        sub = entry.get("subfunction")
        spec.programming_sequence.append(SequenceEntry(
            sid=_parse_hex_id(entry["service"], "sequence"),
            subfunction=(_parse_hex_id(sub, "sequence") if sub is not None else None),
            repeat=bool(entry.get("repeat", False)),
        ))

    return spec
