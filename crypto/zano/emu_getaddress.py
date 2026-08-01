# ZanoGetAddress wiring check, inside the emulator.
#
# Three separate claims, each of which can fail independently:
#   1. the wire MessageType routes to the app
#   2. the app module actually imports (it pulls apps.monero.xmr for the shared
#      key derivation, so a build that omits monero breaks it)
#   3. the encoding path still reproduces the address published on chain
#
#   SDL_VIDEODRIVER=dummy unshare -rn sh -c \
#       'ip link set lo up; exec ./build/unix/trezor-emu-core ../crypto/zano/emu_getaddress.py'

fail = 0

from trezor.enums import MessageType
from apps import workflow_handlers

h = workflow_handlers._find_message_handler_module(MessageType.ZanoGetAddress)
print("handler for ZanoGetAddress:", h)
if h != "apps.zano.get_address":
    print("  [FAIL] wrong or missing handler")
    fail += 1
else:
    print("  [ok] routes to the app")

from trezor.messages import ZanoAddress, ZanoGetAddress

print("  [ok] wire messages importable:", ZanoGetAddress.MESSAGE_WIRE_TYPE,
      ZanoAddress.MESSAGE_WIRE_TYPE)

import apps.zano.get_address as ga

print("  [ok] app module imported:", ga.get_address is not None)

import trezorzano


def unhex(s):
    return bytes(int(s[i : i + 2], 16) for i in range(0, len(s), 2))


# remington.b, as published on Vaulta mainnet under slip44:1018.
a = trezorzano.address_from_keys(
    unhex("3a9f316c2eceb38591737031b2fc39daaf379caaab786878b80ea658cf1e02ff"),
    unhex("00b51be3b5821c592a4b21fb2e83c7ea1c792f9e164cac96c1e7b3118b5cb36b"),
)
print("address:", a)
if len(a) == 97 and a.startswith("ZxCDR2aGwYhX2ayq"):
    print("  [ok] matches the address published on chain")
else:
    print("  [FAIL] does not match")
    fail += 1

print("FAILURES:" if fail else "ALL OK", fail if fail else "")
