"""
Run from parent directory:
~# python3 -m pytest -W ignore::UserWarning -W ignore::DeprecationWarning -vv smpp/
"""
import pytest

from smpp import constants, sm

# 89 chars
MSG_SHORT = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendi"
             "sse mi lacus massa nunc.")
# 7 chars
MSG_SHORT_UNICODE = "可輸入英文單字"

# 203 chars
MSG_LONG = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc lobo"
            "rtis faucibus ante, eget tristique nibh. Mauris feugiat rutrum nis"
            "l et dignissim. Suspendisse quam nulla, vulputate vel mi sit amet "
            "nunc.")


def test_split_short_gsm0338():
    esm_class, data_coding, msg_parts = sm.split_short_message(
        MSG_SHORT, constants.DATA_CODING_DEFAULT)

    assert esm_class == 0x00
    assert data_coding == constants.DATA_CODING_DEFAULT
    assert len(msg_parts) == 1


def test_split_short_latin1():
    esm_class, data_coding, msg_parts = sm.split_short_message(
        MSG_SHORT, constants.DATA_CODING_LATIN1)

    assert esm_class == 0x00
    assert data_coding == constants.DATA_CODING_LATIN1
    assert len(msg_parts) == 1


def test_split_short_ucs2():
    esm_class, data_coding, msg_parts = sm.split_short_message(
        MSG_SHORT, constants.DATA_CODING_UCS2)

    assert esm_class == 0x40
    assert data_coding == constants.DATA_CODING_UCS2
    assert len(msg_parts) == 2


def test_split_short_gsm0338_ucs2_fallback():
    esm_class, data_coding, msg_parts = sm.split_short_message(
        MSG_SHORT_UNICODE, constants.DATA_CODING_DEFAULT)

    assert esm_class == 0x00
    assert data_coding == constants.DATA_CODING_UCS2
    assert len(msg_parts) == 1


def test_split_long_gsm0338():
    esm_class, data_coding, msg_parts = sm.split_short_message(
        MSG_LONG, constants.DATA_CODING_DEFAULT)

    assert esm_class == 0x40
    assert data_coding == constants.DATA_CODING_DEFAULT
    assert len(msg_parts) == 2


def test_split_long_latin1():
    esm_class, data_coding, msg_parts = sm.split_short_message(
        MSG_LONG, constants.DATA_CODING_LATIN1)

    assert esm_class == 0x40
    assert data_coding == constants.DATA_CODING_LATIN1
    assert len(msg_parts) == 2


def test_split_long_ucs2():
    esm_class, data_coding, msg_parts = sm.split_short_message(
        MSG_LONG, constants.DATA_CODING_UCS2)

    assert esm_class == 0x40
    assert data_coding == constants.DATA_CODING_UCS2
    assert len(msg_parts) == 4


def test_split_long_udh():
    esm_class, data_coding, msg_parts = sm.split_short_message(
        MSG_LONG, constants.DATA_CODING_UCS2)

    for msg_part in msg_parts:
        assert msg_part[0] == 0x05
        assert msg_part[1] == 0x00
        assert msg_part[2] == 0x03
        assert msg_part[4] == 0x04  # there are four messages

        identifier = msg_part[3]

    # every identifier in every UDH must be equal
    identifiers = [m[3] for m in msg_parts]
    assert all(i == identifier for i in identifiers)
