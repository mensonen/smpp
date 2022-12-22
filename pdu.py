"""
SMPP PDU generation and parsing

Sample usage:

>>> from smpp import constants
>>> from smpp.pdu import PDU
>>>
>>> # command parameters can be set during creation
>>> p = PDU.new(constants.CMD_DATA_SM,
>>>             sequence_number=1,
>>>             source_addr="sender")
>>> # or later as attributes of a command instance
>>> p.destination_addr = "147897987"
>>>
>>> # raw PDU data in bytes, header is the command header containing status,
>>> # length and command id, body is the parameters encoded in proper order
>>> raw_pdu = p.header + p.body
>>>
>>> # new PDUs can also be parsed from raw network bytes:
>>> p = PDU.new_from_raw(raw_pdu)
>>> print(p.destination_addr)  # produces 147897987

"""
from __future__ import annotations

import logging
import struct
from typing import Any, Dict, List, Optional, Tuple, Type, Union

from . import constants
from . import PduParseError, SequenceGenerator

logger = logging.getLogger("smpp.pdu")

# supported TLVs
OPTIONAL_PARAM_TAGS = {
    "dest_addr_subunit": 0x0005,
    "dest_network_type": 0x0006,
    "dest_bearer_type": 0x0007,
    "dest_telematics_id": 0x0008,
    "source_addr_subunit": 0x000D,
    "source_network_type": 0x000E,
    "source_bearer_type": 0x000F,
    "source_telematics_id": 0x010,
    "qos_time_to_live": 0x0017,
    "payload_type": 0x0019,
    "additional_status_info_text": 0x01D,
    "receipted_message_id": 0x001E,
    "ms_msg_wait_facilities": 0x0030,
    "privacy_indicator": 0x0201,
    "source_subaddress": 0x0202,
    "dest_subaddress": 0x0203,
    "user_message_reference": 0x0204,
    "user_response_code": 0x0205,
    "source_port": 0x020A,
    "destination_port": 0x020B,
    "sar_msg_ref_num": 0x020C,
    "language_indicator": 0x020D,
    "sar_total_segments": 0x020E,
    "sar_segment_seqnum": 0x020F,
    "sc_interface_version": 0x0210,
    "callback_num_pres_ind": 0x0302,
    "callback_num_atag": 0x0303,
    "number_of_messages": 0x0304,
    "callback_num": 0x0381,
    "dpf_result": 0x0420,
    "set_dpf": 0x0421,
    "ms_availability_status": 0x0422,
    "network_error_code": 0x0423,
    "message_payload": 0x0424,
    "delivery_failure_reason": 0x0425,
    "more_messages_to_send": 0x0426,
    "message_state": 0x0427,
    "ussd_service_op": 0x0501,
    "display_time": 0x1201,
    "sms_signal": 0x1203,
    "ms_validity": 0x1204,
    "alert_on_message_delivery": 0x130C,
    "its_reply_type": 0x1380,
    "its_session_info": 0x1383}


def _field_tag_to_name(tag_value: str) -> str:
    for tag_name, value in OPTIONAL_PARAM_TAGS.items():
        if value == tag_value:
            return tag_name


class PDU:
    command_id: int
    """PDU command ID."""
    command_status: int
    """PDU command status code."""
    sequence_number: int
    """PDU running sequence number."""
    command: str
    """Name for the command ID."""
    params: Dict[str, Param]
    """Fields available for the PDU. These are also accessible as direct 
    attributes of the PDU instance."""

    params_config: List[Tuple[str, Type[Param], Union[dict, list]]]
    need_sequence: bool = False

    def __setattr__(self, item, value):
        if item in self.params:
            self.params[item].data = value
            # reset when values change
            self._encoded_body = None
        else:
            self.__dict__[item] = value

    def __getattr__(self, item):
        if item in self.params:
            return self.params[item].data
        raise AttributeError

    def __init__(self, **kwargs):
        self.__dict__["params"] = {}

        self._encoded_body = None

        self.command_status = constants.ESME_ROK
        self.sequence_number = 0

        for field_name, param, param_config in self.params_config:
            if issubclass(param, ListParam):
                p = param(param_config)
            else:
                p = param(**param_config)
            p.field_name = field_name
            # flag as TLV unless parameter config specifically requested not to,
            # e.g parameters "message_state", which is both an optional TLV and
            # a mandatory parameter
            if field_name in OPTIONAL_PARAM_TAGS and p.is_optional is None:
                p.is_optional = True
                p.field_tag = OPTIONAL_PARAM_TAGS[field_name]

            self.params[field_name] = p

        for key, value in kwargs.items():
            setattr(self, key, value)

    def _prepare_body(self):
        pass

    def _set_sequence(self, sequence: int):
        self.sequence_number = sequence

    @property
    def header(self) -> bytes:
        """Encoded PDU header.

        Returns a PDU header that is 16 bytes long and contains the length of
        the entire PDU (including header), the command ID, the command status
        and the sequence number.
        """
        return struct.pack(">LLLL",
                           len(self.body) + 16, self.command_id,
                           self.command_status, self.sequence_number)

    @property
    def body(self) -> bytes:
        """Encoded PDU body.

        When retrieved, will encode each individual command parameter set at the
        time, concatenate them together as one byte string. If called multiple
        times, will return a cached copy of last parameter generation, unless
        parameter values have been changed in the meantime.
        """
        if self._encoded_body is not None:
            return self._encoded_body

        self._prepare_body()

        b = b""
        for param in self.params.values():
            encoded_param = param.encoded
            # TLVs are always optional
            if param.is_optional and encoded_param:
                # print(f"adding {param.field_name} with value {encoded_param} (optional)")
                b += encoded_param
            elif not param.is_optional:
                # ostr may not return data
                if param.has_optional_value and encoded_param:
                    # print(f"adding {param.field_name} with value {encoded_param}")
                    b += encoded_param
                else:
                    # print(f"adding {param.field_name} with value {encoded_param}")
                    b += encoded_param

        self._encoded_body = b

        return self._encoded_body

    @classmethod
    def new(cls, command_id: int, sequence_generator: SequenceGenerator = None,
            **kwargs: Any) -> PDU:
        """Generate a new, blank, SMPP PDU.

        Args:
            command_id: A valid command ID. The `constants.CMD_*` constants can
                be used instead of manually specifying IDs
            sequence_generator: An instance of a class that implements
                `SequenceGenerator`: used to automatically set the value for
                the `sequence` parameter, if command requires a sequence and
                none was provided. If not given, all commands default to a
                sequence value of 0

        Keyword Arguments:
            command_status (int): Command status or one of the `constants.ESME_*`
                constant values. If not given defaults to `ESME_ROK`
            sequence_number (int): Command sequence. If not given and no
                sequence generator was provided, defaults to 0. If not given and
                a sequence generator was provided, defaults to next sequence
                from the generator
            **kwargs (Any): Passed on to the PDU constructor, can be used to set
                command parameters while creating a PDU

        >>> p1 = PDU.new(constants.CMD_BIND_RECEIVER,
        >>>              system_id="test", password="test")
        >>>
        >>> seq = SequenceGenerator()
        >>> p2 = PDU.new(constants.CMD_SUBMIT_SM, sequence_generator=seq,
        >>>              source_addr="131313", destination_addr="141414",
        >>>              short_message=b"test")

        Returns:
            An instance of PDU that matches the command ID given. I.e
            `constants.CMD_UNBIND` would return an instance of `Unbind`.

        """
        commands = {
            constants.CMD_ALERT_NOTIFICATION: AlertNotification,
            constants.CMD_BIND_RECEIVER: BindReceiver,
            constants.CMD_BIND_RECEIVER_RESP: BindReceiverResp,
            constants.CMD_BIND_TRANSCEIVER: BindTransceiver,
            constants.CMD_BIND_TRANSCEIVER_RESP: BindTransceiverResp,
            constants.CMD_BIND_TRANSMITTER: BindTransmitter,
            constants.CMD_BIND_TRANSMITTER_RESP: BindTransmitterResp,
            constants.CMD_CANCEL_SM: CancelSm,
            constants.CMD_CANCEL_SM_RESP: CancelSmResp,
            constants.CMD_DATA_SM: DataSm,
            constants.CMD_DATA_SM_RESP: DataSmResp,
            constants.CMD_DELIVER_SM: DeliverSm,
            constants.CMD_DELIVER_SM_RESP: DeliverSmResp,
            constants.CMD_ENQUIRE_LINK: EnquireLink,
            constants.CMD_ENQUIRE_LINK_RESP: EnquireLinkResp,
            constants.CMD_GENERIC_NACK: GenericNack,
            constants.CMD_QUERY_SM: QuerySm,
            constants.CMD_QUERY_SM_RESP: QuerySmResp,
            constants.CMD_REPLACE_SM: ReplaceSm,
            constants.CMD_REPLACE_SM_RESP: ReplaceSmResp,
            constants.CMD_SUBMIT_MULTI: SubmitMulti,
            constants.CMD_SUBMIT_MULTI_RESP: SubmitMultiResp,
            constants.CMD_SUBMIT_SM: SubmitSm,
            constants.CMD_SUBMIT_SM_RESP: SubmitSmResp,
            constants.CMD_UNBIND: Unbind,
            constants.CMD_UNBIND_RESP: UnbindResp}

        if command_id not in commands:
            raise PduParseError(f"Invalid command code {hex(command_id)}")

        cmd = commands[command_id](**kwargs)
        cmd.command = constants.COMMAND_IDS[command_id]
        cmd.command_id = command_id

        if cmd.need_sequence and sequence_generator and "sequence_number" not in kwargs:
            cmd._set_sequence(sequence_generator.next_sequence())

        return cmd

    @classmethod
    def new_from_raw(cls, raw_data: bytes) -> PDU:
        """Parse raw PDU bytes into a PDU instance."""
        try:
            length, command_id, status, sequence = struct.unpack(
                ">LLLL", raw_data[:16])
        except struct.error as e:
            raise PduParseError(f"PDU has invalid header: {e}")
        cmd = PDU.new(command_id, command_status=status, sequence_number=sequence)

        data_length = len(raw_data)
        if data_length == 16:
            return cmd

        pos = 16

        # first do mandatory parameters in pre-determined order
        for param in cmd.params.values():
            length = None

            if pos >= data_length:
                break
            if param.is_optional:
                break
            if param.len_param:
                length = cmd.params[param.len_param].data

            pos = param.extract_from_data(raw_data, pos, length)

        # then do TLVs until data is exhausted
        while pos < data_length:
            field_tag, length = struct.unpack(">HH", raw_data[pos:pos + 4])
            param_name = _field_tag_to_name(field_tag)

            if not param_name:
                logger.warning(f"unknown TLV tag value '{field_tag}' with "
                               f"length {length} at position {pos}; ignored")
                # spec says ignore unknown optional parameters
                pos += 4 + length
                continue

            if param_name not in cmd.params:
                logger.warning(f"unexpected TLV tag '{param_name}' "
                               f"({hex(field_tag)} at position {pos}; not part "
                               f"of {cmd.command} definition; ignored")
                # spec says ignore unexpected optional parameters
                pos += 4 + length
                continue

            pos += 4  # skip header
            param = cmd.params[param_name]
            pos = param.extract_from_data(raw_data, pos, length)

        return cmd

    @property
    def ok(self) -> bool:
        """True as long as command_status is ESME_ROK."""
        return self.command_status == constants.ESME_ROK


class Param:
    """An individual PDU parameter definition."""
    has_optional_value = False

    def __init__(self, size: int = None, min_len: int = None, max_len: int = None,
                 len_param: str = None, initial: Any = None,
                 is_optional: bool = None):
        self.size = size
        self.min_len = min_len
        self.max_len = max_len

        self.field_name = None
        # for TLVs
        self.is_optional = is_optional
        self.field_tag = None

        # reference to another parameter that stores an OctetString length
        self.len_param = len_param

        self._data = initial

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value

    @property
    def encoded(self) -> bytes:
        return b""

    def extract_from_data(self, raw_data: bytes, pos: int, length: int = None) -> int:
        return pos


class ListParam:
    """An individual PDU parameter definition that accepts lists as values."""
    params: Dict[str, Param]
    has_optional_value = False
    is_optional = False

    def __init__(self, params_config: List[Tuple]):
        self.params = {}

        for field_name, param, param_kwargs in params_config:
            p = param(**param_kwargs)
            p.field_name = field_name
            # flag as TLV unless parameter config specifically requested not to,
            # e.g parameters "message_state", which is both an optional TLV and
            # a mandatory parameter
            if field_name in OPTIONAL_PARAM_TAGS and p.is_optional is None:
                p.is_optional = True
                p.field_tag = OPTIONAL_PARAM_TAGS[field_name]

            self.params[field_name] = p

        self.len_param = None
        self.field_name = None
        self.data = []

    @property
    def encoded(self) -> bytes:
        b = b""
        for param in self.data:
            for key, value in param.items():
                param = self.params[key]
                param.data = value
                encoded_param = param.encoded
                # TLVs are always optional
                if param.is_optional and encoded_param:
                    # print(f"adding {param.field_name} with value {encoded_param} (optional)")
                    b += encoded_param
                elif not param.is_optional:
                    # ostr may not return data
                    if param.has_optional_value and encoded_param:
                        # print(f"adding {param.field_name} with value {encoded_param}")
                        b += encoded_param
                    else:
                        # print(f"adding {param.field_name} with value {encoded_param}")
                        b += encoded_param
        return b

    def extract_from_data(self, raw_data: bytes, pos: int, length: int = None) -> int:
        return pos


class DestAddressList(ListParam):
    def __init__(self, params_config):
        super().__init__(params_config)
        self.len_param = "number_of_dests"

    def extract_from_data(self, raw_data: bytes, pos: int, length: int = None) -> int:
        data = []
        for _ in range(length):
            dest_flag = self.params["dest_flag"]
            pos = dest_flag.extract_from_data(raw_data, pos)

            if dest_flag.data == 1:
                dest_addr_ton = self.params["dest_addr_ton"]
                pos = dest_addr_ton.extract_from_data(raw_data, pos)
                dest_addr_npi = self.params["dest_addr_npi"]
                pos = dest_addr_npi.extract_from_data(raw_data, pos)
                destination_addr = self.params["destination_addr"]
                pos = destination_addr.extract_from_data(raw_data, pos)

                data.append({"dest_flag": dest_flag.data,
                             "dest_addr_ton": dest_addr_ton.data,
                             "dest_addr_npi": dest_addr_npi.data,
                             "destination_addr": destination_addr.data})

            else:
                dl_name = self.params["dl_name"]
                pos = dl_name.extract_from_data(raw_data, pos)

                data.append({"dest_flag": dest_flag.data,
                             "dl_name": dl_name.data})
        self.data = data
        return pos


class UnsuccessSmeList(ListParam):
    def __init__(self, params_config):
        super().__init__(params_config)
        self.len_param = "no_unsuccess"

    def extract_from_data(self, raw_data: bytes, pos: int, length: int = None) -> int:
        data = []
        for _ in range(length):
            dest_addr_ton = self.params["dest_addr_ton"]
            pos = dest_addr_ton.extract_from_data(raw_data, pos)
            dest_addr_npi = self.params["dest_addr_npi"]
            pos = dest_addr_npi.extract_from_data(raw_data, pos)
            destination_addr = self.params["destination_addr"]
            pos = destination_addr.extract_from_data(raw_data, pos)
            error_status_code = self.params["error_status_code"]
            pos = error_status_code.extract_from_data(raw_data, pos)

            data.append({"dest_addr_ton": dest_addr_ton.data,
                         "dest_addr_npi": dest_addr_npi.data,
                         "destination_addr": destination_addr.data,
                         "error_status_code": error_status_code.data})

        self.data = data
        return pos


class IntegerParam(Param):
    # int, short, long
    pack_format = {1: "B", 2: "H", 4: "L"}

    @property
    def encoded(self) -> Optional[bytes]:
        fmt = self.pack_format[self.size]
        if self.data is None and not self.is_optional:
            return b"\0"
        elif self.data is None and self.is_optional:
            return None
        elif not self.is_optional:
            return struct.pack(f">{fmt}", self.data)
        else:
            return struct.pack(f">HH{fmt}", self.field_tag, self.size, self.data)

    def extract_from_data(self, raw_data: bytes, pos: int, length: int = None) -> int:
        # unused for integers, always fixed size
        _ = length

        fmt = self.pack_format[self.size]
        self.data, = struct.unpack(f">{fmt}", raw_data[pos:pos + self.size])

        return pos + self.size


class StringParam(Param):
    @property
    def encoded(self) -> Optional[bytes]:
        if self.size is not None:
            value = self.data.ljust(self.size, chr(0))
            if not isinstance(value, bytes):
                value = value.encode("latin-1")
            if not self.is_optional:
                return value

            return struct.pack(">HH", self.field_tag, self.size) + value

        elif self.max_len is not None:
            if self.data is None and not self.is_optional:
                # non tlv and empty - always return at least NULL
                value = chr(0)
            elif self.data is None and self.is_optional:
                # tlv and empty, just abort
                return None
            elif len(self.data) > self.max_len:
                value = self.data[0:self.max_len - 1] + chr(0)
            else:
                value = self.data + chr(0)

            value = value.encode("latin-1")

            if not self.is_optional:
                return value

            return struct.pack(">HH", self.field_tag, len(value)) + value

        else:
            raise PduParseError(f"Misconfigured parameter {self.field_name}, "
                                f"either size or max length has to be set for a "
                                f"string value")

    def extract_from_data(self, raw_data: bytes, pos: int, length: int = None) -> int:
        if length is None:
            end_pos = raw_data.find(b"\0", pos)
            length = end_pos - pos + 1  # extracting including the \0

        self.data = raw_data[pos:pos + length - 1].decode()  # set data without trailing \0
        return pos + length


class OctetStringParam(Param):
    has_optional_value = True

    @property
    def encoded(self) -> Optional[bytes]:
        if self.data is None:
            return None

        value = self.data
        if not isinstance(value, bytes):
            raise PduParseError(f"Value of {self.field_name} must be in bytes")
        if not self.is_optional:
            return value

        return struct.pack(">HH", self.field_tag, len(value)) + value

    def extract_from_data(self, raw_data: bytes, pos: int, length: int = None) -> int:
        if length is None:
            raise PduParseError("Cannot extract Octet-String from data without "
                                f"length for parameter {self.field_name}")

        self.data = raw_data[pos:pos + length]
        return pos + length


class AlertNotification(PDU):
    need_sequence = True

    params_config = [
        ("source_addr_ton", IntegerParam, {"size": 1}),
        ("source_addr_npi", IntegerParam, {"size": 1}),
        ("source_addr", StringParam, {"max_len": 21}),
        ("esme_addr_ton", IntegerParam, {"size": 1}),
        ("esme_addr_npi", IntegerParam, {"size": 1}),
        ("esme_addr", StringParam, {"max_len": 21}),
        ("ms_availability_status", IntegerParam, {"size": 1})]


class BindTransmitter(PDU):
    params_config = [
        ("system_id", StringParam, {"max_len": 16}),
        ("password", StringParam, {"max_len": 9}),
        ("system_type", StringParam, {"max_len": 13}),
        ("interface_version", IntegerParam, {"size": 1, "initial": 0x34}),
        ("addr_ton", IntegerParam, {"size": 1}),
        ("addr_npi", IntegerParam, {"size": 1}),
        ("address_range", StringParam, {"max_len": 41})]


class BindTransmitterResp(PDU):
    params_config = [
        ("system_id", StringParam, {"max_len": 16}),
        ("sc_interface_version", IntegerParam, {"size": 1})]


class BindReceiver(BindTransmitter):
    pass


class BindReceiverResp(BindTransmitterResp):
    pass


class BindTransceiver(BindTransmitter):
    pass


class BindTransceiverResp(BindTransmitterResp):
    pass


class CancelSm(PDU):
    need_sequence = True

    params_config = [
        ("service_type", StringParam, {"max_len": 6}),
        ("message_id", StringParam, {"max_len": 65}),
        ("source_addr_ton", IntegerParam, {"size": 1}),
        ("source_addr_npi", IntegerParam, {"size": 1}),
        ("source_addr", StringParam, {"max_len": 21}),
        ("dest_addr_ton", IntegerParam, {"size": 1}),
        ("dest_addr_npi", IntegerParam, {"size": 1}),
        ("destination_addr", StringParam, {"max_len": 21})]


class CancelSmResp(PDU):
    params_config = []


class DataSm(PDU):
    need_sequence = True

    params_config = [
        ("service_type", StringParam, {"max_len": 6}),
        ("source_addr_ton", IntegerParam, {"size": 1}),
        ("source_addr_npi", IntegerParam, {"size": 1}),
        ("source_addr", StringParam, {"max_len": 21}),
        ("dest_addr_ton", IntegerParam, {"size": 1}),
        ("dest_addr_npi", IntegerParam, {"size": 1}),
        ("destination_addr", StringParam, {"max_len": 21}),
        ("esm_class", IntegerParam, {"size": 1}),
        ("registered_delivery", IntegerParam, {"size": 1}),
        ("data_coding", IntegerParam, {"size": 1}),
        ("source_port", IntegerParam, {"size": 2}),
        ("source_addr_subunit", IntegerParam, {"size": 1}),
        ("source_network_type", IntegerParam, {"size": 1}),
        ("source_bearer_type", IntegerParam, {"size": 1}),
        ("source_telematics_id", IntegerParam, {"size": 2}),
        ("destination_port", IntegerParam, {"size": 2}),
        ("dest_addr_subunit", IntegerParam, {"size": 1}),
        ("dest_network_type", IntegerParam, {"size": 1}),
        ("dest_bearer_type", IntegerParam, {"size": 1}),
        ("dest_telematics_id", IntegerParam, {"size": 2}),
        ("sar_msg_ref_num", IntegerParam, {"size": 2}),
        ("sar_total_segments", IntegerParam, {"size": 1}),
        ("sar_segment_seqnum", IntegerParam, {"size": 1}),
        ("more_messages_to_send", IntegerParam, {"size": 1}),
        ("qos_time_to_live", IntegerParam, {"size": 4}),
        ("payload_type", IntegerParam, {"size": 1}),
        ("message_payload", OctetStringParam, {"max_len": 260}),
        ("receipted_message_id", StringParam, {"max_len": 65}),
        ("message_state", IntegerParam, {"size": 1}),
        ("network_error_code", OctetStringParam, {"size": 3}),
        ("user_message_reference", IntegerParam, {"size": 2}),
        ("privacy_indicator", IntegerParam, {"size": 1}),
        ("callback_num", OctetStringParam, {"min_len": 4, "max_len": 19}),
        ("callback_num_pres_ind", IntegerParam, {"size": 1}),
        ("callback_num_atag", StringParam, {"max_len": 65}),
        ("source_subaddress", StringParam, {"min_len": 2, "max_len": 23}),
        ("dest_subaddress", StringParam, {"min_len": 2, "max_len": 23}),
        ("user_response_code", IntegerParam, {"size": 1}),
        ("display_time", IntegerParam, {"size": 1}),
        ("sms_signal", IntegerParam, {"size": 2}),
        ("ms_validity", IntegerParam, {"size": 1}),
        ("ms_msg_wait_facilities", IntegerParam, {"size": 1}),
        ("number_of_messages", IntegerParam, {"size": 1}),
        ("alert_on_message_delivery", IntegerParam, {"size": 1}),
        ("language_indicator", IntegerParam, {"size": 1}),
        ("its_reply_type", IntegerParam, {"size": 1}),
        ("its_session_info", IntegerParam, {"size": 2})]


class DataSmResp(PDU):
    params_config = [
        ("message_id", StringParam, {"max_len": 65}),
        ("delivery_failure_reason", IntegerParam, {"size": 1}),
        ("network_error_code", OctetStringParam, {"size": 3}),
        ("additional_status_info_text", StringParam, {"max_len": 256}),
        ("dpf_result", IntegerParam, {"size": 1})]


class DeliverSm(PDU):
    need_sequence = True

    params_config = [
        ("service_type", StringParam, {"max_len": 6}),
        ("source_addr_ton", IntegerParam, {"size": 1}),
        ("source_addr_npi", IntegerParam, {"size": 1}),
        ("source_addr", StringParam, {"max_len": 21}),
        ("dest_addr_ton", IntegerParam, {"size": 1}),
        ("dest_addr_npi", IntegerParam, {"size": 1}),
        ("destination_addr", StringParam, {"max_len": 21}),
        ("esm_class", IntegerParam, {"size": 1}),
        ("protocol_id", IntegerParam, {"size": 1}),
        ("priority_flag", IntegerParam, {"size": 1}),
        ("schedule_delivery_time", StringParam, {"max_len": 17}),
        ("validity_period", StringParam, {"max_len": 17}),
        ("registered_delivery", IntegerParam, {"size": 1}),
        ("replace_if_present_flag", IntegerParam, {"size": 1}),
        ("data_coding", IntegerParam, {"size": 1}),
        ("sm_default_msg_id", IntegerParam, {"size": 1}),
        ("sm_length", IntegerParam, {"size": 1}),
        ("short_message", OctetStringParam, {"max_len": 254, "len_param": "sm_length"}),

        ("user_message_reference", IntegerParam, {"size": 1}),
        ("source_port", IntegerParam, {"size": 2}),
        ("destination_port", IntegerParam, {"size": 2}),
        ("sar_msg_ref_num", IntegerParam, {"size": 2}),
        ("sar_total_segments", IntegerParam, {"size": 1}),
        ("sar_segment_seqnum", IntegerParam, {"size": 1}),
        ("user_response_code", IntegerParam, {"size": 1}),
        ("privacy_indicator", IntegerParam, {"size": 1}),
        ("payload_type", IntegerParam, {"size": 1}),
        ("message_payload", OctetStringParam, {"max_len": 260}),
        ("callback_num", OctetStringParam, {"min_len": 4, "max_len": 19}),
        ("source_subaddress", StringParam, {"min_len": 2, "max_len": 23}),
        ("dest_subaddress", StringParam, {"min_len": 2, "max_len": 23}),
        ("language_indicator", IntegerParam, {"size": 1}),
        ("its_session_info", IntegerParam, {"size": 2}),
        ("network_error_code", OctetStringParam, {"size": 3}),
        ("message_state", IntegerParam, {"size": 1}),
        ("receipted_message_id", StringParam, {"max_len": 65}),
        ("source_network_type", IntegerParam, {"size": 1}),
        ("dest_network_type", IntegerParam, {"size": 1}),
        ("more_messages_to_send", IntegerParam, {"size": 1})]

    def _prepare_body(self):
        if self.short_message:
            if self.message_payload is not None:
                raise PduParseError("message_payload and short_message cannot "
                                    "coexist")
            self.sm_length = len(self.short_message)
        else:
            self.sm_length = 0


class DeliverSmResp(PDU):
    params_config = [
        ("message_id", StringParam, {"max_len": 65})]


class EnquireLink(PDU):
    need_sequence = True
    params_config = []


class EnquireLinkResp(PDU):
    params_config = []


class GenericNack(PDU):
    params_config = []


class QuerySm(PDU):
    need_sequence = True

    params_config = [
        ("message_id", StringParam, {"max_len": 65}),
        ("source_addr_ton", IntegerParam, {"size": 1}),
        ("source_addr_npi", IntegerParam, {"size": 1}),
        ("source_addr", StringParam, {"max_len": 21})]


class QuerySmResp(PDU):
    params_config = [
        ("message_id", StringParam, {"max_len": 65}),
        ("final_date", StringParam, {"max_len": 17}),
        # message_state is also an optional TLV, so force it as non-optional
        ("message_state", IntegerParam, {"size": 1, "is_optional": False}),
        ("error_code", IntegerParam, {"size": 1})]


class ReplaceSm(PDU):
    need_sequence = True

    params_config = [
        ("message_id", StringParam, {"max_len": 65}),
        ("source_addr_ton", IntegerParam, {"size": 1}),
        ("source_addr_npi", IntegerParam, {"size": 1}),
        ("source_addr", StringParam, {"max_len": 21}),
        ("schedule_delivery_time", StringParam, {"max_len": 17}),
        ("validity_period", StringParam, {"max_len": 17}),
        ("registered_delivery", IntegerParam, {"size": 1}),
        ("sm_default_msg_id", IntegerParam, {"size": 1}),
        ("sm_length", IntegerParam, {"size": 1}),
        ("short_message", OctetStringParam, {"max_len": 254, "len_param": "sm_length"})]

    def _prepare_body(self):
        self.sm_length = 0
        if self.short_message:
            self.sm_length = len(self.short_message)


class ReplaceSmResp(PDU):
    params_config = []


class SubmitMulti(PDU):
    need_sequence = True

    params_config = [
        ("service_type", StringParam, {"max_len": 6}),
        ("source_addr_ton", IntegerParam, {"size": 1}),
        ("source_addr_npi", IntegerParam, {"size": 1}),
        ("source_addr", StringParam, {"max_len": 21}),
        ("number_of_dests", IntegerParam, {"size": 1}),
        ("dest_address", DestAddressList, [
            ("dest_flag", IntegerParam, {"size": 1}),
            ("dl_name", StringParam, {"max_len": 21}),
            ("dest_addr_ton", IntegerParam, {"size": 1}),
            ("dest_addr_npi", IntegerParam, {"size": 1}),
            ("destination_addr", StringParam, {"max_len": 21})
        ]),
        ("esm_class", IntegerParam, {"size": 1}),
        ("protocol_id", IntegerParam, {"size": 1}),
        ("priority_flag", IntegerParam, {"size": 1}),
        ("schedule_delivery_time", StringParam, {"max_len": 17}),
        ("validity_period", StringParam, {"max_len": 17}),
        ("registered_delivery", IntegerParam, {"size": 1}),
        ("replace_if_present_flag", IntegerParam, {"size": 1}),
        ("data_coding", IntegerParam, {"size": 1}),
        ("sm_default_msg_id", IntegerParam, {"size": 1}),
        ("sm_length", IntegerParam, {"size": 1}),
        ("short_message", OctetStringParam, {"max_len": 254, "len_param": "sm_length"}),

        ("user_message_reference", IntegerParam, {"size": 1}),
        ("source_port", IntegerParam, {"size": 2}),
        ("source_addr_subunit", IntegerParam, {"size": 1}),
        ("destination_port", IntegerParam, {"size": 2}),
        ("dest_addr_subunit", IntegerParam, {"size": 1}),
        ("sar_msg_ref_num", IntegerParam, {"size": 2}),
        ("sar_total_segments", IntegerParam, {"size": 1}),
        ("sar_segment_seqnum", IntegerParam, {"size": 1}),
        ("more_messages_to_send", IntegerParam, {"size": 1}),
        ("payload_type", IntegerParam, {"size": 1}),
        ("message_payload", OctetStringParam, {"max_len": 260}),
        ("privacy_indicator", IntegerParam, {"size": 1}),
        ("callback_num", OctetStringParam, {"min_len": 4, "max_len": 19}),
        ("callback_num_pres_ind", IntegerParam, {"size": 1}),
        ("callback_num_atag", StringParam, {"max_len": 65}),
        ("source_subaddress", StringParam, {"min_len": 2, "max_len": 23}),
        ("dest_subaddress", StringParam, {"min_len": 2, "max_len": 23}),
        ("user_response_code", IntegerParam, {"size": 1}),
        ("display_time", IntegerParam, {"size": 1}),
        ("sms_signal", IntegerParam, {"size": 2}),
        ("ms_validity", IntegerParam, {"size": 1}),
        ("ms_msg_wait_facilities", IntegerParam, {"size": 1}),
        ("alert_on_message_delivery", IntegerParam, {"size": 1}),
        ("language_indicator", IntegerParam, {"size": 1})]

    def _prepare_body(self):
        if self.short_message:
            if self.message_payload is not None:
                raise PduParseError("message_payload and short_message cannot "
                                    "coexist")
            self.sm_length = len(self.short_message)
        else:
            self.sm_length = 0

        self.number_of_dests = len(self.dest_address)


class SubmitMultiResp(PDU):
    params_config = [
        ("message_id", StringParam, {"max_len": 65}),
        ("no_unsuccess", IntegerParam, {"size": 1}),
        ("unsuccess_sme", UnsuccessSmeList, [
            ("dest_addr_ton", IntegerParam, {"size": 1}),
            ("dest_addr_npi", IntegerParam, {"size": 1}),
            ("destination_addr", StringParam, {"max_len": 21}),
            ("error_status_code", IntegerParam, {"size": 1})
        ])]


class SubmitSm(PDU):
    need_sequence = True

    params_config = [
        ("service_type", StringParam, {"max_len": 6}),
        ("source_addr_ton", IntegerParam, {"size": 1}),
        ("source_addr_npi", IntegerParam, {"size": 1}),
        ("source_addr", StringParam, {"max_len": 21}),
        ("dest_addr_ton", IntegerParam, {"size": 1}),
        ("dest_addr_npi", IntegerParam, {"size": 1}),
        ("destination_addr", StringParam, {"max_len": 21}),
        ("esm_class", IntegerParam, {"size": 1}),
        ("protocol_id", IntegerParam, {"size": 1}),
        ("priority_flag", IntegerParam, {"size": 1}),
        ("schedule_delivery_time", StringParam, {"max_len": 17}),
        ("validity_period", StringParam, {"max_len": 17}),
        ("registered_delivery", IntegerParam, {"size": 1}),
        ("replace_if_present_flag", IntegerParam, {"size": 1}),
        ("data_coding", IntegerParam, {"size": 1}),
        ("sm_default_msg_id", IntegerParam, {"size": 1}),
        ("sm_length", IntegerParam, {"size": 1}),
        ("short_message", OctetStringParam, {"max_len": 254, "len_param": "sm_length"}),

        ("user_message_reference", IntegerParam, {"size": 1}),
        ("source_port", IntegerParam, {"size": 2}),
        ("source_addr_subunit", IntegerParam, {"size": 1}),
        ("destination_port", IntegerParam, {"size": 2}),
        ("dest_addr_subunit", IntegerParam, {"size": 1}),
        ("sar_msg_ref_num", IntegerParam, {"size": 2}),
        ("sar_total_segments", IntegerParam, {"size": 1}),
        ("sar_segment_seqnum", IntegerParam, {"size": 1}),
        ("more_messages_to_send", IntegerParam, {"size": 1}),
        ("payload_type", IntegerParam, {"size": 1}),
        ("message_payload", OctetStringParam, {"max_len": 260}),
        ("privacy_indicator", IntegerParam, {"size": 1}),
        ("callback_num", OctetStringParam, {"min_len": 4, "max_len": 19}),
        ("callback_num_pres_ind", IntegerParam, {"size": 1}),
        ("source_subaddress", StringParam, {"min_len": 2, "max_len": 23}),
        ("dest_subaddress", StringParam, {"min_len": 2, "max_len": 23}),
        ("user_response_code", IntegerParam, {"size": 1}),
        ("display_time", IntegerParam, {"size": 1}),
        ("sms_signal", IntegerParam, {"size": 2}),
        ("ms_validity", IntegerParam, {"size": 1}),
        ("ms_msg_wait_facilities", IntegerParam, {"size": 1}),
        ("number_of_messages", IntegerParam, {"size": 1}),
        ("alert_on_message_delivery", IntegerParam, {"size": 1}),
        ("language_indicator", IntegerParam, {"size": 1}),
        ("its_reply_type", IntegerParam, {"size": 1}),
        ("its_session_info", IntegerParam, {"size": 2}),
        ("ussd_service_op", IntegerParam, {"size": 1})]

    def _prepare_body(self):
        if self.short_message:
            if self.message_payload is not None:
                raise PduParseError("message_payload and short_message cannot "
                                    "coexist")
            self.sm_length = len(self.short_message)
        else:
            self.sm_length = 0


class SubmitSmResp(PDU):
    params_config = [
        ("message_id", StringParam, {"max_len": 65})]


class Unbind(PDU):
    need_sequence = True
    params_config = []


class UnbindResp(PDU):
    params_config = []


def define_optional_param(cmd: Type[PDU], param_type: Type[Param], tag: int,
                          tag_name: str, size: int = None, min_len: int = None,
                          max_len: int = None, len_param: str = None,
                          initial: Any = None):
    """Define a custom optional parameter.

    Defines a custom parameter (TLV) tag name/value and configures it. If a
    custom parameter is used by multiple different SMPP commands, the parameter
    needs to be defined once for each.

    Note that parameter definitions are global; they need to be done only once
    in the application and the changes affect every client within.

    Args:
        cmd: One of PDU sub classes to add the parameter to
        param_type: One of parameter type classes
        tag: The integer tag value, should be in the reserved range of
            0x4000 - 0xffff, in order to avoid overwriting any values defined
            by the SMPP 3.4 spec
        tag_name: Name of the tag. The tag will be accessible as an attribute of
            the SMPP command using this name, will not have any other relevance
            to the actual PDU being sent
        size: Optional fixed size in bytes for the parameter value. For string
            parameters is mandatory if `max_len` is not set. For integer
            parameters is mandatary and has to be one of 1, 2 or 4
        min_len: Optional and relevant only for string parameters. If value is
            less than the given length, the value will be left padded to match
        max_len: Optional and relevant only for strint parameters. If value is
            larger than the maximum length, the value will be truncated to
            match
        len_param: Optional a name of another command parameter that stores the
            length of this parameter
        initial: Any optional initial value to assign

    >>> # adds support for an optional parameter 0x1401 with an Octet String
    >>> # value that is two bytes in size
    >>> define_optional_param(DataSm, OctetStringParam, 0x1401, "vendor_tag", size=2)
    >>> # 'vendor_tag' is now available as an attribute for the data_sm command:
    >>> p = PDU.new(constants.CMD_DATA_SM, vendor_tag=b"\xf4\xe0")
    """
    if tag_name not in OPTIONAL_PARAM_TAGS:
        OPTIONAL_PARAM_TAGS[tag_name] = tag

    for param_name, _, _ in cmd.params_config:
        if param_name == tag_name:
            logger.warning(f"ignoring an already defined parameter definition "
                           f"for tag {tag_name}")
            return

    cmd.params_config.append((
        tag_name, param_type, {
            "size": size, "min_len": min_len, "max_len": max_len,
            "len_param": len_param, "initial": initial}))
