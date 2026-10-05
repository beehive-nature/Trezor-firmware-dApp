#!/bin/sh
# Build + run the Schnorr conformance test, then emit our own signatures for
# the reference-side cross-check.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
CRYPTO=$(cd "$HERE/.." && pwd)
VECTORS=${VECTORS:-/mnt/c/Users/travi/zano-port/schnorr_vectors.json}
OURSIGS=${OURSIGS:-/mnt/c/Users/travi/zano-port/our_schnorr_sigs.json}
OUT=${OUT:-/tmp/zano_schnorr_test}

rm -f "$OUT"

echo "=== embedding reference vectors ==="
python3 "$HERE/schnorr_vectors_to_header.py" "$VECTORS" > "$HERE/zano_schnorr_vectors.h"
echo "  $(grep -c '\.name =' "$HERE/zano_schnorr_vectors.h") vectors"

cd "$CRYPTO"
echo
echo "=== building (-Wall -Wextra) ==="
gcc -o "$OUT" \
    zano/test_schnorr.c zano/schnorr.c zano/zano_generators.c \
    ed25519-donna/ed25519-donna-impl-base.c \
    ed25519-donna/ed25519-donna-32bit-tables.c \
    ed25519-donna/ed25519-donna-basepoint-table.c \
    ed25519-donna/modm-donna-32bit.c \
    ed25519-donna/curve25519-donna-32bit.c \
    ed25519-donna/curve25519-donna-helpers.c \
    ed25519-donna/curve25519-donna-scalarmult-base.c \
    ed25519-donna/ed25519-keccak.c ed25519-donna/ed25519.c \
    sha3.c hasher.c blake256.c blake2b.c groestl.c sha2.c ripemd160.c \
    memzero.c consteq.c \
    -I. -Ied25519-donna -Izano \
    -DED25519_CUSTOMRANDOM -DED25519_CUSTOMHASH -DED25519_NO_INLINE_ASM \
    -DED25519_FORCE_32BIT=1 -DUSE_KECCAK=1 -DUSE_MONERO=1 \
    -Wall -Wextra -Wno-unused-function -O1
echo "  built (zero warnings expected above)"

echo
"$OUT" "$OURSIGS"
