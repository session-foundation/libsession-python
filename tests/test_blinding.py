"""Tests for 15xxx Community blinding.

Run with `pytest` against an installed build:

    sudo apt install libsession-util-dev pybind11-dev
    pip install .
    pytest
"""

import pytest

from session_util import blinding

# From libsession-util's own blinding tests.
SEED = bytes.fromhex("c010d89eccbaf5d1c6d19df766c6eedf965d4a28a56f87c9fc819edb59896dd9")
SESSION_ID = "0588672ccb97f40bb57238989226cf429b575ba355443f47bc76c5ab144a96c65b"
SERVER_PK = "c3b3c6f32f0ab5a57f853cc4f30f5da7fda5624b0c77b3fb0829de562ada081d"
BLINDED_POS = "1598932d4bccbe595a8789d7eb1629cefc483a0eaddc7e20e8fe5c771efafd9a75"
BLINDED_NEG = "1598932d4bccbe595a8789d7eb1629cefc483a0eaddc7e20e8fe5c771efafd9af5"

server_pk_bytes = bytes.fromhex(SERVER_PK)
session_id_bytes = bytes.fromhex(SESSION_ID)


def test_blind15_id_hex():
    assert blinding.blind15_id(SESSION_ID, SERVER_PK) == (BLINDED_POS, BLINDED_NEG)


def test_blind15_id_bytes():
    pos, neg = blinding.blind15_id(session_id_bytes, server_pk_bytes)
    assert (pos.hex(), neg.hex()) == (BLINDED_POS, BLINDED_NEG)
    assert len(pos) == len(neg) == 33


def test_blind15_id_bytes_accepts_an_unprefixed_session_id():
    assert blinding.blind15_id(session_id_bytes[1:], server_pk_bytes) == blinding.blind15_id(
        session_id_bytes, server_pk_bytes
    )


def test_the_two_ids_differ_only_in_the_sign_bit():
    pos, neg = blinding.blind15_id(session_id_bytes, server_pk_bytes)
    assert pos[:32] == neg[:32]
    assert pos[32] ^ neg[32] == 0x80


def test_hex_and_bytes_forms_agree():
    from_hex = blinding.blind15_id(SESSION_ID, SERVER_PK)
    from_bytes = blinding.blind15_id(session_id_bytes, server_pk_bytes)
    assert from_hex == tuple(b.hex() for b in from_bytes)


def test_the_real_blinded_id_is_one_of_the_two():
    """The point of returning both: with the secret key the sign is known, and the
    result has to be one of the candidates derived without it."""
    real = "15" + blinding.blind15_key_pair(SEED, server_pk_bytes).pubkey.hex()
    assert real in blinding.blind15_id(SESSION_ID, SERVER_PK)


def test_blind15_id_rejects_wrong_sizes():
    with pytest.raises(ValueError):
        blinding.blind15_id(session_id_bytes[:16], server_pk_bytes)
    with pytest.raises(ValueError):
        blinding.blind15_id(session_id_bytes, server_pk_bytes[:16])
