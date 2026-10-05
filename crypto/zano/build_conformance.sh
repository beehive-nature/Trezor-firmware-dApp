#!/bin/sh
# Build + run the differential conformance test against real Zano vectors.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
CRYPTO=$(cd "$HERE/.." && pwd)
VECTORS=${VECTORS:-/mnt/c/Users/travi/zano-port/clsag_ggx_vectors.json}
OUT=${OUT:-/tmp/zano_conformance}

rm -f "$OUT"

echo "=== generating zano_vectors.h from reference vectors ==="
python3 "$HERE/vectors_to_header.py" "$VECTORS" > "$HERE/zano_vectors.h"
echo "  $(grep -c '\.name =' "$HERE/zano_vectors.h") vectors embedded"

cd "$CRYPTO"
echo
echo "=== building ==="
gcc -o "$OUT" \
    zano/test_conformance.c zano/zano_generators.c \
    ed25519-donna/ed25519-donna-impl-base.c \
    ed25519-donna/ed25519-donna-32bit-tables.c \
    ed25519-donna/ed25519-donna-basepoint-table.c \
    ed25519-donna/modm-donna-32bit.c \
    ed25519-donna/curve25519-donna-32bit.c \
    ed25519-donna/curve25519-donna-helpers.c \
    ed25519-donna/curve25519-donna-scalarmult-base.c \
    ed25519-donna/ed25519-keccak.c ed25519-donna/ed25519.c \
    sha3.c hasher.c blake256.c blake2b.c groestl.c sha2.c ripemd160.c \
    memzero.c consteq.c monero/xmr.c monero/serialize.c \
    -I. -Ied25519-donna -Imonero -Izano \
    -DED25519_CUSTOMRANDOM -DED25519_CUSTOMHASH -DED25519_NO_INLINE_ASM \
    -DED25519_FORCE_32BIT=1 -DUSE_KECCAK=1 -DUSE_MONERO=1 \
    -Wall -Wno-unused-function -O1
echo "  built: $OUT"

echo
"$OUT"
