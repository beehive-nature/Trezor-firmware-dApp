#!/bin/sh
# Host test for crypto/bpq: builds test_bpq against the vendored libraries
# and runs it. Run from the repository root. Regenerate the vectors first with
#   python3 crypto/bpq/vectors_to_header.py <beehive-nature checkout>
set -eu
out="${TMPDIR:-/tmp}/bpq-host-test"
mkdir -p "$out"
CFLAGS="-std=gnu11 -O1 -Wall -Wextra -Werror -Icrypto -Ivendor/mldsa-native/mldsa -Ivendor/mlkem-native/mlkem"

# The bpq objects share a binary with the tree's own mldsa-native (ML-DSA-44)
# and SPHINCS+ (SHA2-128s) builds, so every symbol they export must be bpq's.
for f in bpq bpq_mldsa65 bpq_mlkem768 bpq_slh; do
  cc $CFLAGS -c "crypto/bpq/$f.c" -o "$out/$f.o"
done
foreign=$(nm -g --defined-only "$out"/bpq*.o | awk 'NF == 3 && $3 !~ /^bpq/ {print $3}')
if [ -n "$foreign" ]; then
  echo "FAIL: exported symbols outside the bpq namespace:"; echo "$foreign"; exit 1
fi
echo "symbols: every export of the four bpq objects starts with bpq"

cc $CFLAGS -Wno-unused-function \
  crypto/bpq/test_bpq.c "$out"/bpq*.o \
  crypto/hmac.c crypto/sha2.c crypto/sha3.c crypto/memzero.c \
  crypto/ed25519-donna/curve25519-donna-32bit.c \
  crypto/ed25519-donna/curve25519-donna-helpers.c \
  crypto/ed25519-donna/curve25519-donna-scalarmult-base.c \
  crypto/ed25519-donna/ed25519.c crypto/ed25519-donna/modm-donna-32bit.c \
  crypto/ed25519-donna/ed25519-donna-basepoint-table.c \
  crypto/ed25519-donna/ed25519-donna-32bit-tables.c \
  crypto/ed25519-donna/ed25519-donna-impl-base.c \
  -o "$out/test_bpq"
"$out/test_bpq"
