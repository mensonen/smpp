"""
Short message parsing helper methods.
"""
import random
from typing import List, Tuple, Union

from . import constants
from .encoding import gsm0338


def encode_short_message(short_message: Union[str, bytes],
                         encoding: int = constants.DATA_CODING_DEFAULT) -> Tuple[bytes, int]:
    """Encode short message in given encoding.

    Converts short message string to bytes using one of SMPP standard encodings.
    If conversion fails, a fallback conversion to UCS2 (UTF-16-BE) is done.

    Args:
        short_message: Message to encode. If message is already in bytes, no
            conversions are made
        encoding: One of the `constants.DATA_CODING_*` values. Not all encodings
            are supported. Using `DATA_CODING_DEFAULT` will produce GSM 03.38
            encoded text

    Returns:
        Encoded text and final used encoding.

    """
    if isinstance(short_message, bytes):
        return short_message, encoding

    encoded = False
    try:
        if encoding == constants.DATA_CODING_DEFAULT:
            data = short_message.encode("gsm0338")
        elif encoding == constants.DATA_CODING_ISO88591:
            data = short_message.encode("iso-8859-1")
        elif encoding == constants.DATA_CODING_ISO88595:
            data = short_message.encode("iso-8859-5")
        elif encoding == constants.DATA_CODING_ISO88598:
            data = short_message.encode("iso-8859-8")

        encoded = True
    except UnicodeError:
        # falling back on UCS2
        encoding = constants.DATA_CODING_ISO10646

    if encoding == constants.DATA_CODING_ISO10646:
        data = short_message.encode("utf-16-be")
    elif encoding in (constants.DATA_CODING_BINARY, constants.DATA_CODING_BINARY2):
        if not isinstance(data, bytes):
            raise ValueError("Binary data coding requires bytes input")
        data = short_message
    elif not encoded:
        raise ValueError(f"Unhandled encoding {hex(encoding)}")

    return data, encoding


def split_short_message(data: Union[str, bytes],
                        encoding: int) -> Tuple[int, int, List[bytes]]:
    """Encode message and split into multiple parts if necessary.

    Takes short message data and converts it into bytes using one of the
    given encodings (passed through `encode_short_message`), and then splits it
    into multiple parts, if the encoded text length is too long. A UDH is
    added to each message segment automatically and the resulting message parts
    should all be submitted individually to the SMSC.

    Args:
        data: Message data to send
        encoding: One of the `constants.DATA_CODING_*` values. Not all encodings
            are supported. Using `DATA_CODING_DEFAULT` will produce GSM 03.38
            encoded text

    Returns:
        Three values:
        * esm_class to use when submitting the message
        * encoding to use as the data_coding parameter
        * a list of message parts

    """
    data, encoding = encode_short_message(data, encoding)

    esm_class = 0x00

    if encoding == constants.DATA_CODING_DEFAULT:
        max_len = 160
        chunk_size = 153
    elif encoding in (constants.DATA_CODING_BINARY, constants.DATA_CODING_BINARY2):
        max_len = 70
        chunk_size = 67
    else:
        max_len = 140
        chunk_size = 134

    if len(data) > max_len:
        esm_class = 0x40

        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        uid = random.randint(0, 255).to_bytes(1, "big")
        udh = b"\x05\x00\x03" + uid + len(chunks).to_bytes(1, "big")

        parts = [b"".join((udh, count.to_bytes(1, "big"), chunk))
                 for count, chunk in enumerate(chunks, start=1)]

        return esm_class, encoding, parts

    else:
        return esm_class, encoding, [data]
