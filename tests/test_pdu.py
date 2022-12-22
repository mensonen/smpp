"""
Run from parent directory:
~# python3 -m pytest -W ignore::UserWarning -W ignore::DeprecationWarning -vv smpp/
"""
import pytest

import os
import random
import string

from smpp import constants, pdu, PduParseError


def _gen_bytes(size):
    return os.urandom(size)


def _gen_int(size):
    return random.randint(10 ** (size - 1), 10 ** size - 1)


def _gen_str(size):
    return "".join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(size))


def _field_value(field_type, field_params):
    if field_type is pdu.IntegerParam:
        value = _gen_int(field_params["size"])
    elif field_type is pdu.StringParam:
        if "size" in field_params:
            value = _gen_str(field_params["size"])
        else:
            value = _gen_str(field_params["max_len"])
    else:
        if "size" in field_params:
            value = _gen_bytes(field_params["size"])
        else:
            value = _gen_bytes(field_params["max_len"])

    return value


def test_pdu_new():
    p = pdu.PDU.new(constants.CMD_BIND_TRANSCEIVER,
                    system_id="pytest",
                    password="secret")

    assert p.system_id == "pytest"
    assert p.password == "secret"


def test_pdu_header():
    p = pdu.PDU.new(constants.CMD_BIND_TRANSCEIVER,
                    system_id="demofoo",
                    password="secret!")

    assert p.header == b"\x00\x00\x00%\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00"


def test_pdu_body():
    p = pdu.PDU.new(constants.CMD_BIND_TRANSCEIVER,
                    system_id="demofoo",
                    password="secret!")

    assert p.body == b"demofoo\x00secret!\x00\x004\x00\x00\x00"


def test_pdu_in_out():
    p1 = pdu.PDU.new(constants.CMD_BIND_TRANSMITTER,
                     system_id="pytest",
                     password="secret",
                     system_type="SMS",
                     interface_version=0x33)

    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)
    assert p2.system_id == p1.system_id
    assert p2.password == p1.password
    assert p2.system_type == p1.system_type
    assert p2.interface_version == p1.interface_version


def test_pdu_param_len():
    p1 = pdu.PDU.new(constants.CMD_BIND_TRANSCEIVER,
                     system_id="pytest",
                     password="toolongforapassword")

    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)
    assert p2.system_id == "pytest"
    assert p2.password == "toolongf"


def test_pdu_optional_params():
    p1 = pdu.PDU.new(constants.CMD_DATA_SM,
                     source_addr="4178480884810",
                     payload_type=0x01,
                     callback_num=b"417175102032")

    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)
    assert p2.source_addr == "4178480884810"
    assert p2.payload_type == 1
    assert p2.callback_num == b"417175102032"


def test_parse_pdu():
    raw_pdu = bytes.fromhex(
        "0000019800000004000000000000587b000500497073756d496e666f00010134313731"
        "37353130323033320003000000001100f100000424015e4c6f72656d20697073756d20"
        "646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363"
        "696e6720656c69742e205072616573656e74207669746165206e657175652062696265"
        "6e64756d206f72636920636f6e67756520766573746962756c756d2e20446f6e656320"
        "76697461652074696e636964756e742072697375732e204d617572697320657520636f"
        "6e677565206573742e2053757370656e64697373652072686f6e637573206469616d20"
        "72697375732e20496e2073656d7065722073656d207175697320636f6e64696d656e74"
        "756d2072686f6e6375732e20496e2076656c2075726e612072697375732e204e616d20"
        "75742070757275732073697420616d6574206c696265726f206c6163696e696120736f"
        "6c6c696369747564696e2e20446f6e6563207072657469756d206f726e617265206475"
        "6920696e206d616c65737561646120706f73756572652e")

    p = pdu.PDU.new_from_raw(raw_pdu)
    assert p.sequence_number == 22651
    assert p.source_addr_ton == 5
    assert p.source_addr == "IpsumInfo"
    assert p.registered_delivery == 17
    assert len(p.message_payload) == 350


def test_parse_pdu_unknown_tlv():
    # this data contains a TLV with tag value 0x1401 at the end and two bytes
    # of unknown data
    raw_pdu = bytes.fromhex(
        "000001ac00000103000000000000587b000500497073756d496e666f00010134313731"
        "37353130323033320000000000190001010424015e4c6f72656d20697073756d20646f"
        "6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e"
        "6720656c69742e205072616573656e74207669746165206e6571756520626962656e64"
        "756d206f72636920636f6e67756520766573746962756c756d2e20446f6e6563207669"
        "7461652074696e636964756e742072697375732e204d617572697320657520636f6e67"
        "7565206573742e2053757370656e64697373652072686f6e637573206469616d207269"
        "7375732e20496e2073656d7065722073656d207175697320636f6e64696d656e74756d"
        "2072686f6e6375732e20496e2076656c2075726e612072697375732e204e616d207574"
        "2070757275732073697420616d6574206c696265726f206c6163696e696120736f6c6c"
        "696369747564696e2e20446f6e6563207072657469756d206f726e6172652064756920"
        "696e206d616c65737561646120706f73756572652e0381000c34313731373531303230"
        "333214010002f4e0")

    p = pdu.PDU.new_from_raw(raw_pdu)
    assert p.sequence_number == 22651
    assert p.payload_type == 0x01


def test_parse_pdu_custom_tlv():
    pdu.define_optional_param(pdu.DataSm, pdu.OctetStringParam, 0x1401,
                              "vendor_tag", size=2)

    # this data contains a TLV with tag value 0x1401 at the end and two bytes
    # of unknown data
    raw_pdu = bytes.fromhex(
        "000001ac00000103000000000000587b000500497073756d496e666f00010134313731"
        "37353130323033320000000000190001010424015e4c6f72656d20697073756d20646f"
        "6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e"
        "6720656c69742e205072616573656e74207669746165206e6571756520626962656e64"
        "756d206f72636920636f6e67756520766573746962756c756d2e20446f6e6563207669"
        "7461652074696e636964756e742072697375732e204d617572697320657520636f6e67"
        "7565206573742e2053757370656e64697373652072686f6e637573206469616d207269"
        "7375732e20496e2073656d7065722073656d207175697320636f6e64696d656e74756d"
        "2072686f6e6375732e20496e2076656c2075726e612072697375732e204e616d207574"
        "2070757275732073697420616d6574206c696265726f206c6163696e696120736f6c6c"
        "696369747564696e2e20446f6e6563207072657469756d206f726e6172652064756920"
        "696e206d616c65737561646120706f73756572652e0381000c34313731373531303230"
        "333214010002f4e0")

    p = pdu.PDU.new_from_raw(raw_pdu)
    assert p.sequence_number == 22651
    assert p.payload_type == 0x01
    assert p.vendor_tag == b"\xf4\xe0"


def test_fail_ostr_nonbytes():
    p = pdu.PDU.new(constants.CMD_DATA_SM, message_payload="not binary")

    with pytest.raises(PduParseError):
        body = p.body


def test_cmd_alert_notification():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.AlertNotification.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_ALERT_NOTIFICATION, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_bind_transmitter():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.BindTransmitter.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_BIND_TRANSMITTER, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_bind_transmitter_resp():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.BindTransmitterResp.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_BIND_TRANSMITTER_RESP, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_cancel_sm():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.CancelSm.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_CANCEL_SM, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_cancel_sm_resp():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.CancelSmResp.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_CANCEL_SM_RESP, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_data_sm():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.DataSm.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_DATA_SM, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_data_sm_resp():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.DataSmResp.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_DATA_SM_RESP, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_deliver_sm_w_short_message():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.DeliverSm.params_config:
        if field_name == "message_payload":
            continue
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_DELIVER_SM, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_deliver_sm_w_message_payload():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.DeliverSm.params_config:
        if field_name == "short_message":
            pdu_args[field_name] = b""
        else:
            pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_DELIVER_SM, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    assert p2.sm_length == 0

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_deliver_sm_resp():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.DeliverSmResp.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_DELIVER_SM_RESP, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_enquire_link():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.EnquireLink.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_ENQUIRE_LINK, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_enquire_link_resp():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.EnquireLinkResp.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_ENQUIRE_LINK_RESP, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_generic_nack():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.GenericNack.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_GENERIC_NACK, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_query_sm():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.QuerySm.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_QUERY_SM, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_query_sm_resp():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.QuerySmResp.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_QUERY_SM_RESP, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_replace_sm():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.ReplaceSm.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_REPLACE_SM, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_replace_sm_resp():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.ReplaceSmResp.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_REPLACE_SM_RESP, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_submit_multi():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.SubmitMulti.params_config:
        if field_name == "dest_address":
            pdu_args[field_name] = [
                 {"dest_flag": 1, "dest_addr_ton": 1, "dest_addr_npi": 1, "destination_addr": "4178481581"},
                 {"dest_flag": 1, "dest_addr_ton": 1, "dest_addr_npi": 1, "destination_addr": "4178481582"},
                 {"dest_flag": 2, "dl_name": "distlist"},
                 {"dest_flag": 1, "dest_addr_ton": 1, "dest_addr_npi": 1, "destination_addr": "4178481583"}
             ]
        elif field_name == "message_payload":
            continue
        else:
            pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_SUBMIT_MULTI, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)

    assert p2.number_of_dests == 4


def test_cmd_submit_multi_resp():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.SubmitMultiResp.params_config:
        if field_name == "unsuccess_sme":
            pdu_args[field_name] = [
                 {"dest_addr_ton": 1, "dest_addr_npi": 1, "destination_addr": "4178481581", "error_status_code": 4},
                 {"dest_addr_ton": 1, "dest_addr_npi": 1, "destination_addr": "4178481582", "error_status_code": 5}
             ]
        elif field_name == "no_unsuccess":
            pdu_args[field_name] = 2
        else:
            pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_SUBMIT_MULTI_RESP, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_submit_sm_w_short_message():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.SubmitSm.params_config:
        if field_name == "message_payload":
            continue
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_SUBMIT_SM, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_submit_sm_w_message_payload():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.SubmitSm.params_config:
        if field_name == "short_message":
            pdu_args[field_name] = b""
        else:
            pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_SUBMIT_SM, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    assert p2.sm_length == 0

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_submit_sm_resp():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.SubmitSmResp.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_SUBMIT_SM_RESP, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_unbind():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.Unbind.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_UNBIND, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)


def test_cmd_unbind_resp():
    pdu_args = {}
    for field_name, field_type, field_params in pdu.UnbindResp.params_config:
        pdu_args[field_name] = _field_value(field_type, field_params)

    p1 = pdu.PDU.new(constants.CMD_UNBIND_RESP, **pdu_args)
    p2 = pdu.PDU.new_from_raw(p1.header + p1.body)

    for f in pdu_args.keys():
        assert getattr(p1, f) == getattr(p2, f)
