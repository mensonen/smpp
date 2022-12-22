from . import constants


class SequenceGenerator:
    """A sequence generator base class.

    By default is just a non-persistent counter that loops back to 1 when
    max sequence is reached. Should be overwritten by implementing parties, if
    any kind of persistence is required.

    >>> from smpp import SequenceGenerator, client
    >>>
    >>> class PersistentSequence(SequenceGenerator):
    >>>     def next_sequence(self) -> int:
    >>>          self._sequence += 1
    >>>          # store somewhere
    >>>          return self._sequence
    >>>
    >>> esme = client.Client("smsc_host", 2776,
    >>>                      sequence_generator=PersistentSequence)

    It is not necessary to provide instances of the default sequence generator
    when creating new clients, as the clients default to `SequenceGenerator`
    automatically.
    """
    MIN_SEQUENCE = 0x00000001
    MAX_SEQUENCE = 0x7FFFFFFF

    def __init__(self):
        self._sequence = self.MIN_SEQUENCE

    @property
    def sequence(self) -> int:
        """Current sequence number."""
        return self._sequence

    def next_sequence(self) -> int:
        """Increase and return current sequence."""
        if self._sequence == self.MAX_SEQUENCE:
            self._sequence = self.MIN_SEQUENCE
        else:
            self._sequence += 1
        return self._sequence


class SmppError(Exception):
    """Base class for all exceptions."""
    def __init__(self, msg: str, code: int = 0):
        self.msg = msg
        """Human-readable error message."""
        self.code = code
        """One of `constants.ESME_*` error codes."""

    def __str__(self):
        if self.code > 0 and self.code in constants.SMPP_ERROR_CODES:
            return f"{self.msg} ({hex(self.code)}: {constants.SMPP_ERROR_CODES[self.code]})"
        elif self.code > 0:
            return f"{self.msg} ({hex(self.code)}: Unknown)"
        return f"{self.msg}"


class CommandError(SmppError):
    """Exceptions raised when PDU command status is not ESME_ROK."""
    pass


class PduParseError(SmppError):
    """Exceptions raised when response PDU could not be parsed."""
    pass


class SmppConnectionError(SmppError):
    """Exceptions raised when underlying socket failed."""
    pass


def cmd_name_to_id(command_name: str) -> int:
    """Translate a command name to an command ID.

    Takes a command name argument, e.g "submit_sm" and returns its integer ID
    value, e.g 0X00000004.
    """
    for value, name in constants.COMMAND_IDS.items():
        if command_name == name:
            return value


def pack_7bit(byte_string: bytes, padding: int = 0) -> bytes:
    """Pack 8bit data into a 7bit byte string.

    Compresses 8bit data into a 7bit structure by limiting each byte to the
    lowest 127 chars, hence gaining 1 char for every 8 characters, allowing more
    data to fit in the same length of bytes.

    Example:
    >>> # Without packing:
    >>> "7bit".encode("gsm0338").hex()
    '37626974'
    >>> # With packing:
    >>> pack_7bit("7bit".encode("gsm0338")).hex()
    '37719a0e'

    See `unpack_7bit` for the reverse operation.

    Args:
        byte_string: Bytes to pack. As only chars up to 127 are allowed, should
            be encoded as ASCII, or GSM 03.38 if more characters are required
        padding: Integer length to pad the results with
    """
    byte_string = reversed(byte_string)
    binary_string = []
    for b in byte_string:
        s = ""
        for i in range(8):
            s = ("%1d" % (b & 1)) + s
            b >>= 1
        binary_string.append(s[1:])
    binary_string = "".join(binary_string)

    for i in range(padding):
        binary_string += "0"

    # zero extend last octet if needed
    extra = len(binary_string) % 8
    if extra > 0:
        for i in range(8 - extra):
            binary_string = "0" + binary_string

    # convert back to bytes
    packed_bytes = []
    for i in range(0, len(binary_string), 8):
        packed_bytes.append(int(binary_string[i:i + 8], 2))

    return bytes(reversed(packed_bytes))


def unpack_7bit(byte_string: bytes, padding: int = 0) -> bytes:
    """Unpack 7bit packed byte string into 8bit data.

    Uncompresses 8bit data that has been packed into a 7bit structure. See
    `pack_7bit` for the reverse.

    Example:

    >>> # Without packing:
    >>> "7bit".encode("gsm0338").hex()
    '37626974'
    >>> # With packing
    >>> pack_7bit("7bit".encode("gsm0338")).hex()
    '37719a0e'
    >>> unpack_7bit(bytes.fromhex("37719a0e")).decode()
    "7bit"

    Args:
         byte_string: Bytes to unpack
         padding: A length of padding to remove
    """
    byte_string = reversed(byte_string)
    binary_string = []
    for b in byte_string:
        s = ""
        for i in range(8):
            s = ("%1d" % (b & 1)) + s
            b >>= 1
        binary_string.append(s)
    binary_string = "".join(binary_string)

    if padding != 0:
        binary_string = binary_string[:-padding]

    unpacked_bytes = []
    while len(binary_string) >= 7:
        unpacked_bytes.append(int(binary_string[-7:], 2))
        binary_string = binary_string[:-7]

    return bytes(unpacked_bytes)


from . import client
from . import pdu
