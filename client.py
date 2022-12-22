"""
# An SMPP client ("ESME") implementation

This module provides an ESME implementation that covers the network data
transmission part of the SMPP client duties; it can connect to an SMSC, perform
bind operations, transmit any ESME-issued commands and optionally provides a
busy-loop that will indefinitely listen and wait for incoming PDUs from the
SMSC.

## Basic usage

Create a new client and bind to SMSC:

>>> from smpp import client
>>> esme = client.Client("smsc.host.or.ip", 2776)
>>> esme.connect()  # establish a link
>>> esme.bind_transmitter(system_id="username", password="pass")  # authenticate

ESME-originating commands are accessible as methods of the client, and take
PDU parameter names as keyword arguments. A list of mandatory and optional
parameters are as listed in the SMPP 3.4 specification, but are also visible
in the definition of each `smpp.pdu.PDU` subclass.

>>> # in reality, submit_sm and data_sm would require more parameters than this
>>> esme.submit_sm(destination_addr="4178481818", short_message=b"test sms")
>>> esme.data_sm(message_payload=b"msg data", source_addr="sender")

A response PDU can be read using `Client.read_one_pdu`, which blocks until
data is received.

>>> esme.submit_sm(destination_addr="4178481818", short_message=b"test sms")
>>> esme.read_one_pdu()

`read_one_pdu` does not return the read PDU, instead it will call a callback
function (if defined, see below) and automatically respond to the PDU, if the
incoming PDU requires a response. It will return a boolean `True` if it is safe
to continue to read more PDUs and `False` if the client should exit.

When done, the client can be disconnected:

>>> esme.disconnect()

Note that this is a rather violent procedure and will simply force the
underlying network socket to shut down. A cleaner approach would be to have the
client run its "listen" loop and then perform a clean unbind, as demonstrated
below.

## Listening for messages and reacting to callbacks

The SMPP client provides a `Client.listen` method which is a busy loop that
blocks until either an exception is raised or an UNBIND or UNBIND_RESP PDU is
received, in which case `Client.disconnect` is automatically called and the loop
exits. The listen loop can be run from a separate thread:

>>> import threading
>>> import time
>>>
>>> esme = client.Client("smsc.host.or.ip", 2776)
>>> esme.connect()  # establish a link
>>> esme.bind_transmitter(system_id="username", password="pass")  # authenticate
>>> try:
>>>     esme_thread = threading.Thread(target=esme.listen)
>>>     esme_thread.start()
>>>     while True:
>>>         time.sleep(1)  # some application logic can happen here, until it is
>>>                        # time to exit, in which case:
>>>         esme.unbind()  # sends UNBIND command, when UNBIND_RESP arrives,
>>>                        # the `listen` loop exits
>>>         break
>>> except (KeyboardInterrupt, SystemExit, EOFError):
>>>     esme.disconnect()
>>> finally:
>>>     esme_thread.join(5)

The `listen` loop consists of just calling `Client.read_one_pdu` repeatedly
until it returns a non-True value. Custom busy loops can be constructed as well,
using the same logic, if more complex connect/disconnect/error handling is
wanted:

>>> import threading
>>> def busy_loop(esme):
>>>     try:
>>>         while esme.read_one_pdu():
>>>             print("waiting for PDU")
>>>     except client.SmppConnectionError:
>>>         # special logic for network errors
>>>     except client.CommandError:
>>>         # special logic for faulty PDUs
>>>     finally:
>>>         esme.disconnect()
>>>
>>> esme = client.Client("smsc.host.or.ip", 2776)
>>> esme.connect()  # establish a link
>>> esme.bind_transmitter(system_id="username", password="pass")  # authenticate
>>> esme_thread = threading.Thread(target=busy_loop, args=(esme,))
>>> esme_thread.start()

Interaction with the implementing party is provided via callbacks. When creating
a client, callback functions can be provided for each individual SMPP PDU type
using `Client.set_callbacks`; the client will call the callback either right
after receiving a PDU, or right before sending out a PDU:

>>> def deliver_sm(pdu):
>>>     print(f"Got a DLR: {pdu.short_message.decode()}")
>>> def submit_sm_resp(pdu):
>>>     if pdu.ok:
>>>         print("SMS was sent successfully")
>>> esme = client.Client("smsc.host.or.ip", 2776)
>>> esme.set_callbacks(deliver_sm=deliver_sm,
>>>                    submit_sm_resp=submit_sm_resp)

Alternatively, one callback can be set for every single command at once:

>>> def log_pdu(pdu):
>>>     logging.getLogger("pdu_dump").debug(f"Got {pdu.command}")
>>> esme.set_callbacks(all_commands=log_pdu)

The callback function can return an integer value that matches one of the
`constants.ESME_*` status codes. If a status is returned, it is used for the
automatic response, instead of `constants.ESME_ROK`.

## Sequence generation

The SMPP client defaults to generating sequence numbers on its own, for every
single outgoing PDU, starting from 0 and rolling over after 2147483647. The
client also sets the response sequence automatically, whenever a response PDU
requires one.

The automatically generated sequence can be overwritten for each command:

>>> # does not auto-generate a sequence
>>> esme.data_sm(sequence_number=12354678)

The default sequence generator does not persist in any way and resets back to
zero at every application restart. A custom sequence generator that provides
persistence can be used instead:

>>> from smpp import SequenceGenerator, client
>>>
>>> class PersistentSequence(SequenceGenerator):
>>>     def next_sequence(self) -> int:
>>>          self._sequence += 1
>>>          # store somewhere?
>>>          return self._sequence
>>>
>>> esme = client.Client("smsc_host", 2776,
>>>                      sequence_generator=PersistentSequence)

## Custom TLV parameters

The `pdu.py` module supports defining custom parameters, which, when defined,
can be accessed as PDU arguments directly and will also be parsed correctly in
the incoming PDUs. If not defined, custom parameters are ignored in both
sending and receiving PDUs, as per SMPP 3.4 spec.

To define a custom parameter:

>>> from smpp import client, pdu
>>> # adds support for an optional parameter 0x1401 with an Octet String
>>> # value that is two bytes in size, for every data_sm command
>>> pdu.define_optional_param(pdu.DataSm, pdu.OctetStringParam,
>>>                           0x1401, "vendor_tag", size=2)
>>> esme = client.Client("smsc_host", 2776)
>>> # 'vendor_tag' is now available
>>> esme.data_sm(vendor_tag=b"\\xa8\\xec")

Custom parameters can and should be defined only once during the lifetime of
the application; the definitions are global and it is not possible to define
one tag multiple times with a different name or definition.

"""
import logging
import socket
import struct
import time

from typing import Callable, Dict, Tuple

from . import constants
from . import cmd_name_to_id
from . import CommandError, PduParseError, SequenceGenerator, SmppConnectionError
from .pdu import PDU

logger = logging.getLogger("smpp.client")

# list of command responses that trigger a change in session state
SESSION_STATE_CHANGE_COMMANDS = {
    constants.CMD_BIND_TRANSMITTER_RESP: constants.SESSION_STATE_BOUND_TX,
    constants.CMD_BIND_RECEIVER_RESP: constants.SESSION_STATE_BOUND_RX,
    constants.CMD_BIND_TRANSCEIVER_RESP: constants.SESSION_STATE_BOUND_TRX,
    constants.CMD_UNBIND_RESP: constants.SESSION_STATE_OPEN}


class ClientLogAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: dict):
        return f"[{self.extra['clientname']}] {msg}", kwargs


class Client:
    """An SMPP client.

    This client handles ESME network data transmission duties; it can connect
    to an SMSC, perform a bind, transmit any ESME-issued commands and optionally
    wait indefinitely for incoming PDUs from the SMSC.
    """
    _socket = None

    state = constants.SESSION_STATE_CLOSED

    host = None
    port = None
    sequence_generator = None

    def __init__(self, host: str, port: int, timeout: int = 5,
                 sequence_generator: SequenceGenerator = None,
                 logging_identifier: str = None,
                 enquire_link_timeout: int = 30):
        self.host = host
        self.port = port
        self.enquire_link_timeout = enquire_link_timeout

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(timeout)
        self._inactivity_timer = time.time()

        if sequence_generator is None:
            sequence_generator = SequenceGenerator()
        self.sequence_generator = sequence_generator

        if logging_identifier is None:
            self.logger = logger
        else:
            self.logger = ClientLogAdapter(
                logger, extra={"clientname": logging_identifier})

        self.cb: Dict[int, Callable] = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._socket is not None:
            try:
                self.unbind()
            except (CommandError, SmppConnectionError) as e:
                self.logger.warning(f"{e}. Ignored")
            self.disconnect()

    def __del__(self):
        if self._socket is not None:
            self.logger.warning(
                f"{self} was removed without closing, socket left open!")

    @property
    def inactivity_time(self) -> int:
        """Time elapsed since last received PDU."""
        return int(time.time() - self._inactivity_timer)

    def next_sequence(self) -> int:
        return self.sequence_generator.next_sequence()

    @property
    def sequence(self) -> int:
        return self.sequence_generator.sequence

    def set_callbacks(self, all_commands: Callable = None, **kwargs: Callable):
        """Set callback functions to be called on PDU send and receive.

        A callback is called either just after reading and parsing a new PDU
        from the incoming socket stream, before it is processed by the SMPP
        client, or right before a PDU is sent out.

        The callbacks may return an integer value, which should indicate the
        status of the response PDU, if any, that will be sent out. E.g when a
        deliver_sm is read, a deliver_sm_resp is automatically triggered, with
        the command status set based on the return value of the callback
        function.

        Keyword Arguments:
            all_commands: Set callback for every single command, be it sent or
                received, to the same value
            **kwargs: Set a callback for an individual command, with function
                argument name being same as the command name to set

        >>> esme = Client()
        >>> # prints PDU to stdout on every send and receive
        >>> esme.set_callbacks(all_commands=lambda pdu: print(f"Got pdu {pdu}"))
        >>> # handle deliver_sm and submit_sm_resp only
        >>> def deliver_sm(pdu):
        >>>     print(f"Got delivery report PDU {pdu}")
        >>>     # doing something with the SMS
        >>>     return constants.ESME_ROK
        >>>
        >>> esme.set_callbacks(deliver_sm=deliver_sm,
        >>>                    submit_sm_resp=lambda pdu: print(f"Got submit_sm_resp"))
        """
        if all_commands:
            for command_id in constants.COMMAND_IDS.keys():
                self.cb[command_id] = all_commands

        for command_name, callback in kwargs.items():
            command_id = cmd_name_to_id(command_name)
            if command_id:
                self.cb[command_id] = callback

    def _bind(self, command_id: int, **kwargs) -> PDU:
        pdu = PDU.new(command_id, sequence_generator=self.sequence_generator,
                      **kwargs)
        self._send_pdu(pdu)
        try:
            result_pdu, _ = self._read_pdu()
        except socket.timeout:
            raise SmppConnectionError("Socket timeout")
        if not result_pdu.ok:
            raise CommandError("Bind request rejected", result_pdu.command_status)
        return result_pdu

    def _send_pdu(self, pdu: PDU):
        if self.state not in constants.COMMAND_SESSION_STATES[pdu.command_id]:
            raise CommandError(
                f"{pdu.command} command could not be sent",
                constants.ESME_RINVBNDSTS)

        self.logger.info(f"sending {pdu.command} PDU")

        raw_data = pdu.header + pdu.body
        raw_data_length = len(raw_data)

        if pdu.command_id in self.cb:
            self.cb[pdu.command_id](pdu)

        total_sent = 0
        while total_sent < raw_data_length:
            try:
                sent = self._socket.send(raw_data[total_sent:])
                if sent == 0:
                    raise SmppConnectionError(f"broken socket")
                total_sent += sent
            except socket.error as e:
                raise SmppConnectionError(
                    f"failed to write to socket at {total_sent} bytes sent: {e}")

        self.logger.debug(f"sent {raw_data_length} bytes")

    def _read_pdu(self) -> Tuple[PDU, int]:
        self.logger.debug("waiting for PDU")

        try:
            raw_length = self._socket.recv(4)
        except socket.timeout:
            # raising this separately so that action can be taken on timeout
            raise
        except socket.error as e:
            raise SmppConnectionError(f"failed to read from socket: {e}")
        if not raw_length:
            raise SmppConnectionError(f"broken socket")

        try:
            read_length = struct.unpack(">L", raw_length)[0]
        except struct.error:
            raise PduParseError(f"Invalid command length: {repr(raw_length)}")

        raw_body = self._socket.recv(read_length - 4)
        raw_data = raw_length + raw_body

        self.logger.debug(f"read {len(raw_data)} bytes")
        self._inactivity_timer = time.time()

        pdu = PDU.new_from_raw(raw_data)
        self.logger.debug(f"parsed a {pdu.command} command PDU")

        if pdu.ok and pdu.command_id in SESSION_STATE_CHANGE_COMMANDS:
            self.state = SESSION_STATE_CHANGE_COMMANDS[pdu.command_id]
            self.logger.debug(
                f"session state changing to {constants.SESSION_STATE_NAMES[self.state]}")

        return_status = constants.ESME_ROK

        if pdu.command_id in self.cb:
            cb_status = self.cb[pdu.command_id](pdu)
            if cb_status is not None:
                return_status = cb_status

        return pdu, return_status

    def connect(self):
        self.logger.info(f"connecting to SMSC {self.host} at port {self.port}")

        try:
            if self._socket is None:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((self.host, self.port))
            self.state = constants.SESSION_STATE_OPEN
        except socket.error as e:
            raise SmppConnectionError(f"Connection failed: {e}")

    def disconnect(self):
        self.logger.info(f"disconnecting from SMSC {self.host}")

        if self.state == constants.SESSION_STATE_CLOSED:
            self.logger.warning(f"{self} is already in closed state")
        elif self.state != constants.SESSION_STATE_OPEN:
            self.logger.warning(f"{self} is being disconnected while bound")
        if self._socket is not None:
            self._socket.close()
            self._socket = None

        self.state = constants.SESSION_STATE_CLOSED

    def listen(self):
        """Blocks and reads incoming PDUs.

        Does a busy blocking loop that reads incoming PDUs from the network
        socket, until either an UNBIND or UNBIND_RESP PDU is received, in which
        case it exits the loop gracefully and shuts down the socket (calls
        `disconnect`).

        In cases of an exception being thrown during reading a PDU, the
        exception is left uncaught and the network socket is left open. After
        an exception is handled by the implementing party, the busy loop can
        be resumed by calling `listen` again, without the need to reconnect.
        """
        while self.read_one_pdu():
            self.logger.debug("waiting for PDU")

        self.logger.info("client exiting, shutting down socket")
        self.disconnect()

    def read_one_pdu(self):
        try:
            pdu, return_status = self._read_pdu()
        except socket.timeout:
            if self.inactivity_time > self.enquire_link_timeout:
                self.logger.debug("socket timed out, sending enquire link")
                pdu = PDU.new(constants.CMD_ENQUIRE_LINK,
                              sequence_generator=self.sequence_generator)
                self._send_pdu(pdu)
            return True

        if not pdu.ok:
            self.logger.warning(f"received {pdu.command} with a NOK "
                                f"status {hex(pdu.command_status)}")

        if pdu.command_id == constants.CMD_ALERT_NOTIFICATION:
            self.logger.info("received alert_notification command")

        elif pdu.command_id == constants.CMD_CANCEL_SM_RESP:
            self.logger.info("received cancel_sm_resp command")

        elif pdu.command_id == constants.CMD_DATA_SM_RESP:
            self.logger.info("received data_sm_resp command")

        elif pdu.command_id == constants.CMD_DELIVER_SM:
            self.logger.info("received deliver_sm command")

            response_pdu = PDU.new(
                constants.CMD_DELIVER_SM_RESP,
                command_status=return_status,
                sequence_number=pdu.sequence_number)

            self._send_pdu(response_pdu)
            self.logger.debug("responded with deliver_sm_resp")

        elif pdu.command_id == constants.CMD_ENQUIRE_LINK:
            self.logger.info("received enquire_link command")

            response_pdu = PDU.new(
                constants.CMD_ENQUIRE_LINK_RESP,
                sequence_number=pdu.sequence_number)

            self._send_pdu(response_pdu)
            self.logger.debug("responded with enquire_link_resp")

        elif pdu.command_id == constants.CMD_ENQUIRE_LINK_RESP:
            self.logger.info("received enquire_link_resp command")

        elif pdu.command_id == constants.CMD_QUERY_SM_RESP:
            self.logger.info("received query_sm_resp command")

        elif pdu.command_id == constants.CMD_REPLACE_SM_RESP:
            self.logger.info("received replace_sm_resp command")

        elif pdu.command_id == constants.CMD_SUBMIT_MULTI_RESP:
            self.logger.info("received submit_multi_resp command")

        elif pdu.command_id == constants.CMD_SUBMIT_SM_RESP:
            self.logger.info("received submit_sm_resp command")

        elif pdu.command_id == constants.CMD_UNBIND:
            self.logger.info("received unbind command")

            response_pdu = PDU.new(
                constants.CMD_UNBIND_RESP,
                sequence_number=pdu.sequence_number)

            self._send_pdu(response_pdu)
            self.logger.debug("responded with unbind_resp, exiting")

            return False

        elif pdu.command_id == constants.CMD_UNBIND_RESP:
            self.logger.info("received unbind_resp command, exiting")
            return False

        else:
            self.logger.warning(
                f"received an unnhandled SMPP command {pdu.command}")

        return True

    # shortcuts for ESME issued SMPP PDU commands follow

    def bind_transmitter(self, **kwargs):
        self.logger.debug("binding as transmitter")
        return self._bind(constants.CMD_BIND_TRANSMITTER, **kwargs)

    def bind_receiver(self, **kwargs):
        self.logger.debug("binding as receiver")
        return self._bind(constants.CMD_BIND_RECEIVER, **kwargs)

    def bind_transceiver(self, **kwargs):
        self.logger.debug("binding as transceiver")
        return self._bind(constants.CMD_BIND_TRANSCEIVER, **kwargs)

    def cancel_sm(self, **kwargs) -> PDU:
        pdu = PDU.new(constants.CMD_CANCEL_SM,
                      sequence_generator=self.sequence_generator,
                      **kwargs)
        self._send_pdu(pdu)
        return pdu

    def data_sm(self, **kwargs) -> PDU:
        pdu = PDU.new(constants.CMD_DATA_SM,
                      sequence_generator=self.sequence_generator,
                      **kwargs)
        self._send_pdu(pdu)
        return pdu

    def query_sm(self, **kwargs) -> PDU:
        pdu = PDU.new(constants.CMD_QUERY_SM,
                      sequence_generator=self.sequence_generator,
                      **kwargs)
        self._send_pdu(pdu)
        return pdu

    def unbind(self) -> PDU:
        pdu = PDU.new(constants.CMD_UNBIND,
                      sequence_generator=self.sequence_generator)
        self._send_pdu(pdu)
        return pdu

    def replace_sm(self, **kwargs) -> PDU:
        pdu = PDU.new(constants.CMD_REPLACE_SM,
                      sequence_generator=self.sequence_generator,
                      **kwargs)
        self._send_pdu(pdu)
        return pdu

    def submit_sm(self, **kwargs) -> PDU:
        pdu = PDU.new(constants.CMD_SUBMIT_SM,
                      sequence_generator=self.sequence_generator,
                      **kwargs)
        self._send_pdu(pdu)
        return pdu

    def submit_sm_multi(self, **kwargs) -> PDU:
        pdu = PDU.new(constants.CMD_SUBMIT_MULTI,
                      sequence_generator=self.sequence_generator,
                      **kwargs)
        self._send_pdu(pdu)
        return pdu
