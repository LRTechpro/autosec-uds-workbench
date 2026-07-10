"""
Unit tests for uds_decoder.py -- the protocol-knowledge layer.

These tests pin down ISO 14229-1 behavior so a future refactor cannot
silently break protocol decoding. A V&V tool must itself be verified.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

import uds_decoder as dec


# ---------------------------------------------------------------------------
# parse_hex
# ---------------------------------------------------------------------------

def test_parse_hex_space_separated():
    assert dec.parse_hex("22 F1 90") == [0x22, 0xF1, 0x90]


def test_parse_hex_continuous():
    assert dec.parse_hex("22F190") == [0x22, 0xF1, 0x90]


def test_parse_hex_rejects_garbage():
    with pytest.raises(ValueError):
        dec.parse_hex("22 GG 90")


def test_parse_hex_rejects_empty():
    with pytest.raises(ValueError):
        dec.parse_hex("   ")


# ---------------------------------------------------------------------------
# The +0x40 rule -- applies to EVERY service, not just memorized examples.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sid,expected", [
    (0x10, 0x50), (0x11, 0x51), (0x22, 0x62), (0x27, 0x67),
    (0x2E, 0x6E), (0x31, 0x71), (0x34, 0x74), (0x36, 0x76),
    (0x37, 0x77), (0x3E, 0x7E),
])
def test_positive_response_sid_rule(sid, expected):
    assert dec.positive_response_sid(sid) == expected


# ---------------------------------------------------------------------------
# Request decoding
# ---------------------------------------------------------------------------

def test_decode_session_control_request():
    msg = dec.decode_request("10 03")
    assert msg.sid == 0x10
    assert msg.subfunction == 0x03
    assert msg.subfunction_name == "extended"


def test_decode_rdbi_request_extracts_did():
    msg = dec.decode_request("22 F1 90")
    assert msg.sid == 0x22
    assert msg.did == "F190"


def test_decode_security_access_seed_vs_key():
    seed = dec.decode_request("27 01")
    key = dec.decode_request("27 02 AA BB")
    assert seed.subfunction_name == "requestSeed"   # odd = seed
    assert key.subfunction_name == "sendKey"        # even = key


def test_decode_routine_control_extracts_rid():
    msg = dec.decode_request("31 01 02 02")
    assert msg.subfunction_name == "startRoutine"
    assert msg.did == "0202"  # RID stored in the did slot


def test_suppress_positive_response_bit_masked():
    # 3E 80 = Tester Present with suppressPosRspMsgIndicationBit set.
    msg = dec.decode_request("3E 80")
    assert msg.subfunction == 0x00


# ---------------------------------------------------------------------------
# Response decoding
# ---------------------------------------------------------------------------

def test_decode_positive_response_via_offset():
    msg = dec.decode_response("62 F1 90 41 50 49 4D")
    assert msg.kind == "positive"
    assert msg.sid == 0x22          # derived: 0x62 - 0x40
    assert msg.did == "F190"        # echoed DID


def test_decode_negative_response_structure():
    msg = dec.decode_response("7F 22 31")
    assert msg.kind == "negative"
    assert msg.sid == 0x22
    assert msg.nrc == 0x31
    assert msg.nrc_name == "requestOutOfRange"


def test_decode_nrc_33_security_access_denied():
    msg = dec.decode_response("7F 2E 33")
    assert msg.nrc_name == "securityAccessDenied"


def test_response_matches_request_positive():
    rsp = dec.decode_response("62 F1 90 00")
    assert dec.response_matches_request(0x22, rsp)


def test_response_matches_request_wrong_sid():
    rsp = dec.decode_response("62 F1 90 00")      # reply to 0x22...
    assert not dec.response_matches_request(0x2E, rsp)  # ...not to 0x2E


def test_negative_response_matches_only_its_request():
    rsp = dec.decode_response("7F 22 31")
    assert dec.response_matches_request(0x22, rsp)
    assert not dec.response_matches_request(0x34, rsp)
