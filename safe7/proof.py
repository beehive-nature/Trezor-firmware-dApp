"""Safe 7 end-to-end proof: seed a running debug emulator with the repo's test
mnemonic, fetch the EOS public key, and assert it against the repo's own
device-test vector (tests/device_tests/eos/test_get_public_key.py, MNEMONIC12).

Uses the same harness the device tests use (TrezorTestContext + debuglink), so
THP pairing and the on-device pairing dialog are auto-confirmed via the debug
transport. Plain `trezorctl` cannot do this non-interactively for T3W1.
Requires a DEBUG emulator build (xtask ... --pyopt=false); emulator must be
running on udp:127.0.0.1:21324 (debug link on 21325).

The EOS test vector carries a t2t1 coverage marker, but key derivation is a
pure function of the BIP-39 seed, so T3W1 must yield the identical key.

Exits 0 and prints "PROOF OK" only on an exact key match.
"""

import sys
import time

from trezorlib import debuglink, eos
from trezorlib.tools import parse_path
from trezorlib.transport import get_transport

# Defensive tuning only: cap trezorlib's unbounded read/busy-retry waits so a
# wedged channel fails an attempt instead of outliving the outer timeout.
try:
    from trezorlib import client as _client_mod
    from trezorlib.thp import channel as _thp_channel

    _client_mod._DEFAULT_READ_TIMEOUT = 30
    _thp_channel.Channel.BUSY_RETRIES = 8
    _thp_channel.Channel.BUSY_BACKOFF_TIME = 0.1
except Exception:
    pass

EMULATOR = "udp:127.0.0.1:21324"
# tests/common.py MNEMONIC12 — the seed the EOS test vector belongs to.
MNEMONIC12 = "alcohol woman abuse must during monitor noble actual mixed trade anger aisle"
PATH = "m/44h/194h/0h/0/0"
EXPECTED_WIF = "EOS4u6Sfnzj4Sh2pEQnkXyZQJqH3PkKjGByDCbsqqmyq6PttM9KyB"
EXPECTED_RAW = "02015fabe197c955036bab25f4e7c16558f9f672f9f625314ab1ec8f64f7b1198e"

DEADLINE = time.monotonic() + 240
FATAL_ERRORS = (AttributeError, TypeError, NameError, ImportError, AssertionError)

result = None
last_err: "Exception | None" = None
while time.monotonic() < DEADLINE:
    try:
        ctx = debuglink.TrezorTestContext(get_transport(EMULATOR), force_wipe=True)
        if ctx.client.features.initialized:
            # left-running emulator from a previous run: start from clean state
            ctx.client.wipe_device()
        debuglink.load_device(
            ctx.client.get_session(passphrase=None),
            MNEMONIC12,
            pin=None,
            passphrase_protection=False,
            label="safe7",
        )
        session = ctx.client.get_session()
        result = eos.get_public_key(session, parse_path(PATH), False)
        break
    except FATAL_ERRORS:
        raise
    except Exception as e:
        last_err = e
        print(f"waiting for emulator: {type(e).__name__}: {e}", flush=True)
        time.sleep(3)

if result is None:
    print(f"PROOF FAILED: emulator never became ready: {last_err}")
    sys.exit(1)

print(f"path: {PATH}")
print(f"WIF:  {result.wif_public_key}")
print(f"raw:  {result.raw_public_key.hex()}")
if (
    result.wif_public_key == EXPECTED_WIF
    and result.raw_public_key.hex() == EXPECTED_RAW
):
    print("PROOF OK — exact match with tests/device_tests/eos/test_get_public_key.py")
    sys.exit(0)

print("PROOF FAILED: key does not match the repo test vector (wrong seed or wrong tree?)")
sys.exit(1)
