SMPP client library
===================

This is a basic SMPP client (i.e. "ESME") library that provides support for 
generating and parsing PDUs, for connecting to an SMSC in order to submit or
receive PDUs, as well as basic SMS content related helper methods, such as
encoding, message splitting and UDH generation.

The library consists of three main modules:

`pdu.py`
--------

 * Generate any command, as specified in the SMPP 3.4 spec
 * Automatic incrementing of sequence numbers
 * Encodes PDU parameters, as specified in the SMPP 3.4 spec
 * Decodes raw, network-received bytes into PDU instances
 * Possibility to define custom parameters as TLVs

#### Basic usage:

```python
from smpp import constants
from smpp.pdu import PDU

# command parameters can be set during creation
p = PDU.new(constants.CMD_DATA_SM, 
            sequence_number=1,
            source_addr="sender")
# or later as attributes of a command instance
p.destination_addr = "147897987"

# raw PDU data in bytes, header is the command header containing status,
# length and command id, body is the parameters encoded in proper order
raw_pdu = p.header + p.body

# new PDUs can also be parsed from raw network bytes:
p = PDU.new_from_raw(raw_pdu)
print(p.destination_addr)  # produces 147897987
```

`client.py`
-----------

 * Connectivity to SMSC
 * All ESME-issued commands available as instance methods
 * A basic busy loop to listen for incoming PDUs and maintain connectivity to
   the SMSC
 * A callback interface for the implementing party to react to every sent or 
   received PDU

#### Basic usage, connect and bind to SMSC, send one SMS:

```python
from smpp.client import Client

esme = Client("smsch.host.address", 2776)
esme.connect()
esme.bind_transceiver(system_id="username", password="secret")
esme.submit_sm(destination_addr="4178481818", short_message=b"test sms")
esme.unbind()
esme.disconnect()
```

#### Listening to messages:

The SMPP client provides a `Client.listen` method which is a busy loop that
blocks until either an exception is raised or an UNBIND or UNBIND_RESP PDU is
received, in which case `Client.disconnect` is automatically called and the loop
exits. The listen loop can be run from a separate thread:

```python
import threading
import time
from smpp.client import Client

esme = Client("smsc.host.or.ip", 2776)
esme.connect()  # establish a link
esme.bind_transmitter(system_id="username", password="pass")  # authenticate
try:
    esme_thread = threading.Thread(target=esme.listen)
    esme_thread.start()
    while True:
        time.sleep(1)  # some application logic can happen here, until it is
                       # time to exit, in which case:
        esme.unbind()  # sends UNBIND command, when UNBIND_RESP arrives,
                       # the `listen` loop exits
        break
except (KeyboardInterrupt, SystemExit, EOFError):
    esme.disconnect()
finally:
    esme_thread.join(5)
```

The `listen` loop consists of just calling `Client.read_one_pdu` repeatedly
until it returns a non-True value. Custom busy loops can be constructed as well,
using the same logic, if more complex connect/disconnect/error handling is
wanted:

```python
import threading
from smpp.client import Client, SmppConnectionError, CommandError

def busy_loop(esme):
    try:
        while esme.read_one_pdu():
            print("waiting for PDU")
    except SmppConnectionError:
        # special logic for network errors
    except CommandError:
        # special logic for faulty PDUs
    finally:
        esme.disconnect()

esme = Client("smsc.host.or.ip", 2776)
esme.connect()  # establish a link
esme.bind_transmitter(system_id="username", password="pass")  # authenticate
esme_thread = threading.Thread(target=busy_loop, args=(esme,))
esme_thread.start()
```

Interaction with the implementing party is provided via callbacks. When creating
a client, callback functions can be provided for each individual SMPP PDU type
using `Client.set_callbacks`; the client will call the callback either right
after receiving a PDU, or right before sending out a PDU:

```python
from smpp.client import Client

def deliver_sm(pdu):
    print(f"Got a DLR: {pdu.short_message.decode()}")
    
def submit_sm_resp(pdu):
    if pdu.ok:
        print("SMS was sent successfully")
        
esme = Client("smsc.host.or.ip", 2776)
esme.set_callbacks(deliver_sm=deliver_sm,
                   submit_sm_resp=submit_sm_resp)
```

Alternatively, one callback can be set for every single command at once:

```python
import logging

def log_pdu(pdu):
    logging.getLogger("pdu_dump").debug(f"Got {pdu.command}")
    
esme.set_callbacks(all_commands=log_pdu)
```

The callback function can return an integer value that matches one of the
`constants.ESME_*` status codes. If a status is returned, it is used for the
automatic response, instead of `constants.ESME_ROK`.

#### Sequence generation

The SMPP client defaults to generating sequence numbers on its own, for every
single outgoing PDU, starting from 0 and rolling over after 2147483647. The
client also sets the response sequence automatically, whenever a response PDU
requires one.

The automatically generated sequence can be overwritten for each command:

```python
# does not auto-generate a sequence
esme.data_sm(sequence_number=12354678)
```

The default sequence generator does not persist in any way and resets back to
zero at every application restart. A custom sequence generator that provides
persistence can be used instead:

```python
from smpp import SequenceGenerator, client

class PersistentSequence(SequenceGenerator):
    def next_sequence(self) -> int:
         self._sequence += 1
         # store somewhere?
         return self._sequence

esme = client.Client("smsc_host", 2776,
                     sequence_generator=PersistentSequence)
```

#### Custom TLV parameters

The `pdu.py` module supports defining custom parameters, which, when defined,
can be accessed as PDU arguments directly and will also be parsed correctly in
the incoming PDUs. If not defined, custom parameters are ignored in both
sending and receiving PDUs, as per SMPP 3.4 spec.

To define a custom parameter:

```python
from smpp import client, pdu
# adds support for an optional parameter 0x1401 with an Octet String
# value that is two bytes in size, for every data_sm command
pdu.define_optional_param(pdu.DataSm, pdu.OctetStringParam,
                          0x1401, "vendor_tag", size=2)
esme = client.Client("smsc_host", 2776)
# 'vendor_tag' is now available
esme.data_sm(vendor_tag=b"\xa8\xec")
```

Custom parameters can and should be defined only once during the lifetime of
the application; the definitions are global and it is not possible to define
one tag multiple times with a different name or definition.


`sm.py`
-------

 * Encode short messages in common formats (GSM 03.38, latin-1, UCS2)
 * Split long messages into multipart concatenated parts, with UDH set correctly

#### Basic usage

Split text into concatenated parts, using a specific encoding:

```python
from smpp import constants, sm

# produces GSM03.38 encoded text
esm_class, data_coding, msg_parts = sm.split_short_message(
   "One SMS", constants.DATA_CODING_DEFAULT)

for part in msg_parts:
    esme.submit_sm(esm_class=esm_class,
                   data_coding=data_coding,
                   short_message=part,
                   dest_addr_ton=1,
                   dest_addr_npi=1,
                   destination_addr="4479379546546")
```

Both `sm.split_short_message` and `sm.encode_short_message` fall back to UCS2
encoding, if the input text contains characters that cannot be encoded using the
GSM03.38 default alphabet:

```python
from smpp import constants, sm

esm_class, data_coding, msg_parts = sm.split_short_message(
   "可輸入英文單字", constants.DATA_CODING_DEFAULT)

# data coding is now UCS2 (0x08) instead of GSM03.39 (0x00)
data_coding == constants.DATA_CODING_UCS2
```

Helper methods to pack GSM03.38 encoded text into a 7-bit structure also exist,
in case a custom SMSC requires such:

```python
from smpp import pack_7bit, sm

orig_message = "Pack this into 7bit!"
short_message = pack_7bit(orig_message.encode("gsm0338"))

# as the short message is already encoded bytes, split_short_message will not 
# try to encode it again
esm_class, data_coding, msg_parts = sm.split_short_message(
   short_message, constants.DATA_CODING_DEFAULT)
```

7-bit packing works by compressing 8-bit data into a 7-bit structure, by 
limiting each byte to the lowest 127 chars. Therefore the input text must contain
only chars up to 127, i.e ASCII, or GSM03.38.


```python
from smpp import pack_7bit, unpack_7bit

# Without packing:
"7bit".encode("gsm0338").hex() == "37626974"

# With packing:
pack_7bit("7bit".encode("gsm0338")).hex() == "37719a0e"

# And reverse:
unpack_7bit(bytes.fromhex("37719a0e")).decode() == "7bit"
```
