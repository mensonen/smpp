"""
Run from parent directory:
~# python3 -m pytest -W ignore::UserWarning -W ignore::DeprecationWarning -vv smpp/
"""
import pytest

from smpp.encoding import gsm0338


def test_encode_alphanumeric():
    assert "Abc1234".encode("gsm0338") == b"Abc1234"


def test_encode_special_chars():
    assert "ü and € is à".encode("gsm0338") == b"~ and \x1be is \x7f"


def test_encode_escaped():
    assert "{ brackets text }".encode("gsm0338") == b"\x1b( brackets text \x1b)"


def test_decode_alphanumeric():
    assert b"Abc1234".decode("gsm0338") == "Abc1234"


def test_decode_special_chars():
    assert b"~ and \x1be is \x7f".decode("gsm0338") == "ü and € is à"


def test_decode_escaped():
    assert b"\x1b( brackets text \x1b)".decode("gsm0338") == "{ brackets text }"
