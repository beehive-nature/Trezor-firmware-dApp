# Runtime smoke test for the trezorzano MicroPython module.
#
# Run inside the emulator. Note the network namespace: the emulator binds UDP 21324
# unconditionally and there is no port override, so a second emulator on the machine
# will die at sock.c:27 with a bare "Fatal:". Isolating avoids disturbing whatever is
# already running rather than killing it.
#
#   make -f Makefile.scons build_unix TREZOR_MODEL=T3W1 DISABLE_TROPIC=1 DISABLE_OPTIGA=1
#   SDL_VIDEODRIVER=dummy unshare -rn sh -c \
#       'ip link set lo up; exec ./build/unix/trezor-emu-core crypto/zano/emu_smoke.py'
#
# DISABLE_TROPIC/DISABLE_OPTIGA are required on T3W1: the emulator cannot model the
# secure elements and aborts at main_main.c:104 without them.

import trezorzano

print("IMPORT OK")
print("  attrs:", sorted(a for a in dir(trezorzano) if not a.startswith("_")))

trezorzano.generators_init()
print("GENERATORS_INIT OK")

_RING = dict(
    ring_stealth_addresses=[b"\x01" * 32],
    ring_amount_commitments=[b"\x02" * 32],
    ring_blinded_asset_ids=[b"\x03" * 32],
    pseudo_out_amount_commitment=b"\x04" * 32,
    pseudo_out_asset_id=b"\x05" * 32,
    key_image=b"\x06" * 32,
    secret_spend=b"\x07" * 32,
    secret_amount_blind=b"\x08" * 32,
    secret_asset=b"\x09" * 32,
    secret_index=0,
)

# A short buffer must be refused, not read past. The C behind this indexes a fixed 32
# bytes, so a 31-byte input that reached it would read one byte of adjacent memory.
try:
    trezorzano.sign(message_hash=b"\x00" * 31, **_RING)
    print("FAIL: 31-byte message_hash was accepted")
except Exception as e:
    print("SHORT BUFFER REJECTED:", type(e).__name__, e)

# Ring lists of unequal length would otherwise pair a stealth address with another
# member's commitment, which verifies as a valid signature over the wrong ring.
_bad = dict(_RING)
_bad["ring_stealth_addresses"] = [b"\x01" * 32, b"\x01" * 32]
try:
    trezorzano.sign(message_hash=b"\x00" * 32, **_bad)
    print("FAIL: mismatched ring lengths accepted")
except Exception as e:
    print("RING MISMATCH REJECTED:", type(e).__name__, e)
