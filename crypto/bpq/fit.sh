#!/bin/sh
# Hardware fit of crypto/bpq on T3W1, measured without a device. Run from the
# repository root, in nix-shell, after a T3W1 HARDWARE build that includes bpq:
#   sh crypto/bpq/fit.sh core/build-xtask/artifacts/T3W1 [baseline artifacts dir]
# Reads the build; flashes nothing, talks to no device.
set -eu
art="$1"
base="${2:-}"
out="${TMPDIR:-/tmp}/bpq-fit"
rm -rf "$out"
mkdir -p "$out"
NM=arm-none-eabi-nm
SIZE=arm-none-eabi-size

echo "== 1 heap: bpq_alloc high-water mark (host build, fixed-width types)"
cc -std=gnu11 -O1 -Wall -Wextra -Werror -Wno-unused-function -Icrypto \
  -Ivendor/mldsa-native/mldsa -Ivendor/mlkem-native/mlkem \
  crypto/bpq/fit_heap.c crypto/bpq/bpq.c crypto/bpq/bpq_mldsa65.c \
  crypto/bpq/bpq_mlkem768.c crypto/bpq/bpq_slh.c \
  crypto/hmac.c crypto/sha2.c crypto/sha3.c crypto/memzero.c \
  crypto/ed25519-donna/curve25519-donna-32bit.c \
  crypto/ed25519-donna/curve25519-donna-helpers.c \
  crypto/ed25519-donna/curve25519-donna-scalarmult-base.c \
  crypto/ed25519-donna/ed25519.c crypto/ed25519-donna/modm-donna-32bit.c \
  crypto/ed25519-donna/ed25519-donna-basepoint-table.c \
  crypto/ed25519-donna/ed25519-donna-32bit-tables.c \
  crypto/ed25519-donna/ed25519-donna-impl-base.c \
  -o "$out/fit_heap"
"$out/fit_heap"

echo
echo "== 2 stack: worst static path, T3W1 compiler and flags from $art/firmware.cc.json"
python3 crypto/bpq/fit_compile.py "$art/firmware.cc.json" "$out/ci" \
  crypto/bpq/bpq.c crypto/bpq/bpq_mldsa65.c crypto/bpq/bpq_mlkem768.c \
  crypto/bpq/bpq_slh.c crypto/hmac.c crypto/sha2.c crypto/sha3.c \
  crypto/memzero.c crypto/ed25519-donna/curve25519-donna-32bit.c \
  crypto/ed25519-donna/curve25519-donna-scalarmult-base.c \
  crypto/ed25519-donna/curve25519-donna-helpers.c \
  crypto/ed25519-donna/ed25519.c crypto/ed25519-donna/modm-donna-32bit.c \
  crypto/ed25519-donna/ed25519-donna-impl-base.c \
  modtrezorcrypto/modtrezorcrypto.c
# SLH-DSA-SHAKE-256f keygen (n=32, w=16, tree height 68/17=4) has two VLAs and
# one function pointer, bounded from vendor/sphincsplus/ref:
#   thash_shake_simple.c:17  buf[SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N]; the
#     largest inblocks keygen reaches is SPX_WOTS_LEN = 67 (wotsx1.c:72):
#     32 + 32 + 67*32 = 2208 B
#   utilsx1.c:35  stack[tree_height*SPX_N] = 4*32 = 128 B
#   utilsx1.c:43  gen_leaf is wots_gen_leafx1, the only one merkle.c:41 passes
python3 crypto/bpq/fit_stack.py "$out/ci" \
  --vla bpq_spx256f_thash=2208 --vla bpq_spx256f_treehashx1=128 \
  --indirect bpq_spx256f_treehashx1=bpq_spx256f_wots_gen_leafx1 \
  mod_trezorcrypto_bpq_public_keys mod_trezorcrypto_bpq_sign \
  mod_trezorcrypto_bpq_verify bpq_public_keys bpq_sign bpq_verify || true
grep -h -E "_stack_section_size|\.stack " "$art/firmware.map" | head -3 || true

echo
echo "== 3 flash and RAM: the image"
$SIZE -A "$art/firmware.elf" | grep -E "^(\.flash|\.data|\.bss|\.stack|\.heap|\.tls) "
printf "firmware.bin %s B; FIRMWARE_MAXSIZE (models/T3W1/memory.h) %s B\n" \
  "$(wc -c < "$art/firmware.bin")" "$((417 * 8 * 1024))"
hs=$($NM "$art/firmware.elf" | awk '$3 == "_heap_start" {print $1}')
he=$($NM "$art/firmware.elf" | awk '$3 == "_heap_end" {print $1}')
printf "MicroPython GC heap _heap_start..._heap_end = %d B\n" "$((0x$he - 0x$hs))"
printf "symbols named bpq*: %d B (a floor: unprefixed static helpers are not counted; section 4 gives the whole delta)\n" \
  "$($NM -S --size-sort "$art/firmware.elf" | awk '$4 ~ /^(bpq|mod_trezorcrypto_bpq)/ {s += strtonum("0x" $2)} END {print s + 0}')"
if [ -n "$base" ]; then
  echo
  echo "== 4 against the baseline build $base (same commit, bpq gated out)"
  printf "firmware.bin %s B -> %s B\n" "$(wc -c < "$base/firmware.bin")" "$(wc -c < "$art/firmware.bin")"
  $SIZE "$base/firmware.elf" "$art/firmware.elf"
fi
