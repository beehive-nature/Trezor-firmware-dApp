# Address encoding, exercised inside the emulator.
#
# The vectors are the ones crypto/zano/emit_address_vectors.c emitted and
# hyle-team/zano's own base58::encode_addr confirmed byte-for-byte (12/12). If the
# device produces a different string for the same keys, the firmware path differs from
# the proven C path and that is the bug this catches.
#
#   SDL_VIDEODRIVER=dummy unshare -rn sh -c \
#       'ip link set lo up; exec ./build/unix/trezor-emu-core crypto/zano/emu_address.py'

import trezorzano


def unhex(s):
    # MicroPython has no bytes.fromhex; keep this dependency-free so the test does
    # not fail for a reason unrelated to what it is testing.
    return bytes(int(s[i : i + 2], 16) for i in range(0, len(s), 2))


# remington.b, published on Vaulta mainnet under slip44:1018. Its keys were recovered
# by decoding the live address; re-encoding them must reproduce it exactly.
FOUNDER_SPEND = unhex(
    "3a9f316c2eceb38591737031b2fc39daaf379caaab786878b80ea658cf1e02ff"
)
FOUNDER_VIEW = unhex(
    "00b51be3b5821c592a4b21fb2e83c7ea1c792f9e164cac96c1e7b3118b5cb36b"
)
FOUNDER_ADDR = (
    "ZxCDR2aGwYhX2ayqCxrp2oAgFzoRaGZodJUWHmPZk7Ho1W4puz6D"
    "JDP5k1pDbZqTjQaSRRPg5ZBDDVsL42pVyQ7d2YM4Vy3Gu"
)

fail = 0

addr = trezorzano.address_from_keys(FOUNDER_SPEND, FOUNDER_VIEW)
print("device produced:", addr)
print("  length:", len(addr))
if addr == FOUNDER_ADDR:
    print("  [ok] matches the address published on chain")
else:
    print("  [FAIL] differs from the on-chain address")
    print("         want", FOUNDER_ADDR)
    fail += 1

if len(addr) == 97 and addr.startswith("Zx"):
    print("  [ok] 97 chars, 'Zx' prefix")
else:
    print("  [FAIL] wrong shape")
    fail += 1

# A short key must be refused rather than read past.
try:
    trezorzano.address_from_keys(FOUNDER_SPEND[:31], FOUNDER_VIEW)
    print("  [FAIL] 31-byte spend key accepted")
    fail += 1
except Exception as e:
    print("  [ok] short key rejected:", type(e).__name__, e)

print("FAILURES:" if fail else "ALL OK", fail if fail else "")
