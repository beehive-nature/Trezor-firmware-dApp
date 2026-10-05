# bpq: the device's own post-quantum identity (docs/bpq-device.md).
#
# Derivation v1, written down before the code: SLIP-21 node ["BZPQ-DEVICE", "v1"]
# of the device seed gives a 32-byte PRK, which takes the place of masterPrk in
# beehive-nature SPEC-BPQ-1 §2. Every key below the PRK is derived in C
# (trezorcrypto.bpq) and only public keys and signatures come back.

SLIP21_NAMESPACE = [b"BZPQ-DEVICE"]
SLIP21_PATH = [b"BZPQ-DEVICE", b"v1"]
