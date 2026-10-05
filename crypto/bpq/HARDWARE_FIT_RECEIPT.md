# bpq hardware fit on T3W1, measured without a device

2026-10-05, WSL with `nix-shell`. **No device, no flash, no bootloader unlock, no real
phrase.** Two T3W1 hardware images were built and read; neither was written anywhere but
the build directory. Public test vectors only.

- **base**: `27ba1ed51` (the rebase of `bpq-safe7` onto `beehive` `7a8709bdff`) with the
  build-regenerated `qstrdefsport.h`, i.e. the content of `1d21da9e4`. bpq is gated out of
  hardware, as committed: 0 `bpq` symbols in the image.
- **fit**: the same tree plus the measurement-only patch below, which lifts the
  emulator-only gate and lowers one diagnostic to a printed warning. Not committed. The
  image has 166 `bpq` symbols.

## Findings

1. **As committed, bpq does not compile for the hardware target.** The first fit build
   failed on one error, ARM-only: `vendor/sphincsplus/ref/merkle.c:29`
   `info.wots_steps = steps;` assigns `unsigned int *` to `uint32_t *`, and on
   `arm-none-eabi` `uint32_t` is `long unsigned int` (on x86-64 the two types are the
   same, so the emulator never saw it). `bpq_slh.c` includes `merkle.c` for
   `merkle_gen_root`, which calls `merkle_sign`. The measurement build lowered this one
   diagnostic to a warning (both types are 32 bits on Cortex-M33, so the code is
   unchanged). **The real fix is open and is not made here.**
2. **Flash fits.** `firmware.bin` 2,360,320 B → 2,396,672 B (+36,352 B; text +36,352,
   data and bss unchanged), against `FIRMWARE_MAXSIZE` 3,416,064 B: 70.2 % used.
3. **No static RAM added.** `.data` and `.bss` are identical in both images. AUX1_RAM
   reads 100 % in both because the MicroPython GC heap takes the remainder: 697,904 B.
4. **Heap (MicroPython GC, through `bpq_alloc` = `m_malloc_maybe`).** Peak live bytes:
   `bpq_sign` 86,160 B, `bpq_public_keys` 69,794 B, `bpq_verify` 62,400 B; the largest
   single block is 30,720 B. That is 12.3 % of the GC heap at peak. Measured on the host
   through the same allocator seam; every allocation is `sizeof(T) * N` of fixed-width
   types, so the byte counts do not depend on the word size. On allocation failure
   `m_malloc_maybe` returns NULL and bpq returns an error (no crash path).
   **Not measured:** whether a 30,720 B contiguous block is free on a fragmented device
   heap at the moment of a request.
5. **Stack (32 KiB firmware app stack, `.stack` 0x8000).** Worst-case static paths from
   the MicroPython binding down, compiled by `fit_compile.py` with the hardware build's
   own `arm-none-eabi-gcc` command lines plus `-fstack-usage -fcallgraph-info=su`:
   `BpqGetCard` path (`mod_trezorcrypto_bpq_public_keys`) **16,296 B**, of which one
   frame, `bpqmlk768_indcpa_keypair_derand` (ML-KEM-768 keygen, vendor/mlkem-native), is
   13,832 B; `BpqSign` path 6,600 B; verify 6,952 B. Complete for every reachable
   function, with three bounds named from the source in `fit.sh` (two SPHINCS+ VLAs and
   one function pointer). Not counted: libc leaves (`memcpy`, `memset`, ...), the
   MicroPython allocator and raise paths, and **the MicroPython VM frames above the
   binding**. So 16,296 B leaves about 16 KiB for everything above it, and how much of that the VM uses
   at that call depth is **UNVERIFIED** until it runs on the device.
6. **Not measured at all:** signing time on the Cortex-M33, behaviour on hardware, and the
   on-device display flow. Those need an image on a device, which needs the founder.

Reproduce: build a T3W1 hardware image that includes bpq, then from the repository root
in `nix-shell`: `sh crypto/bpq/fit.sh core/build-xtask/artifacts/T3W1 <base artifacts>`.

## The measurement patch (fit only, not committed)

```diff
diff --git a/core/embed/rtl/build.rs b/core/embed/rtl/build.rs
index 257d96ac7..c2402cbc2 100644
--- a/core/embed/rtl/build.rs
+++ b/core/embed/rtl/build.rs
@@ -317,7 +317,7 @@ fn add_crypto(lib: &mut xbuild::CLibrary) -> Result<()> {
     // bpq: the device's own post-quantum identity (docs/bpq-device.md). Built
     // into the universal emulator only; the hardware image is a separate,
     // reviewed step, so a device build has neither this C nor the app above it.
-    if cfg!(feature = "universal_fw") && cfg!(feature = "emulator") {
+    if cfg!(feature = "universal_fw") {
         lib.add_include("../../vendor/mldsa-native/mldsa");
         lib.add_include("../../vendor/mlkem-native/mlkem");
         lib.add_define("USE_BPQ", None);
diff --git a/core/embed/upymod/build.rs b/core/embed/upymod/build.rs
index b67a8646a..a1e690788 100644
--- a/core/embed/upymod/build.rs
+++ b/core/embed/upymod/build.rs
@@ -1189,7 +1189,7 @@ impl<'a> MpyBuilder<'a> {
             files.add(src, "trezor/enums/Cardano*.py")?;
 
             // bpq: emulator only, with the C in rtl/build.rs (docs/bpq-device.md)
-            if cfg!(feature = "emulator") {
+            if true {
                 files.add(src, "apps/bpq/*.py")?;
             }
 
diff --git a/core/src/apps/workflow_handlers.py b/core/src/apps/workflow_handlers.py
index b0389675f..f823fff1c 100644
--- a/core/src/apps/workflow_handlers.py
+++ b/core/src/apps/workflow_handlers.py
@@ -178,9 +178,9 @@ def _find_message_handler_module(msg_type: int) -> str:
         # bpq: built into the emulator only (SConscript.unix); a hardware image
         # has neither the app nor trezorcrypto.bpq, so it answers as for any
         # unknown message.
-        if utils.EMULATOR and msg_type == MessageType.BpqGetCard:
+        if msg_type == MessageType.BpqGetCard:
             return "apps.bpq.get_card"
-        if utils.EMULATOR and msg_type == MessageType.BpqSign:
+        if msg_type == MessageType.BpqSign:
             return "apps.bpq.sign"
 
         # monero
diff --git a/crypto/bpq/bpq_slh.c b/crypto/bpq/bpq_slh.c
index 9225c5148..a3f6d45d0 100644
--- a/crypto/bpq/bpq_slh.c
+++ b/crypto/bpq/bpq_slh.c
@@ -57,6 +57,7 @@
 #include "../../vendor/sphincsplus/ref/address.c"
 #include "../../vendor/sphincsplus/ref/fips202.c"
 #include "../../vendor/sphincsplus/ref/hash_shake.c"
+#pragma GCC diagnostic warning "-Wincompatible-pointer-types"
 #include "../../vendor/sphincsplus/ref/merkle.c"
 #include "../../vendor/sphincsplus/ref/thash_shake_simple.c"
 #include "../../vendor/sphincsplus/ref/utils.c"
```

## base build

```
$ (cd core && uv run --frozen xtask build firmware --model T3W1)  [in nix-shell]  # base
Region                   Used        Total    Usage
FLASH               2305.0 KB    3336.0 KB   69.09%
AUX1_RAM             800.0 KB     800.0 KB  100.00%
rc=0
f0f158390302ee845d656bbf408950a0b14dc8f54bfe952c848eba29fcba8c9a  base/firmware.bin
```

## fit build 1: the ARM-only error

```
$ (cd core && uv run --frozen xtask build firmware --model T3W1)  [in nix-shell]  # fit, before the warning line
     1: Failed to compile /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/bpq/bpq_slh.c
     2: In file included from /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/bpq/bpq_slh.c:60:
        /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/bpq/../../vendor/sphincsplus/ref/merkle.c: In function 'bpq_spx256f_merkle_sign':
        /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/bpq/../../vendor/sphincsplus/ref/merkle.c:29:21: error: assignment to 'uint32_t *' {aka 'long unsigned int *'} from incompatible pointer type 'unsigned int *' [-Werror=incompatible-pointer-types]
           29 |     info.wots_steps = steps;
              |                     ^
        cc1: all warnings being treated as errors

Error: `cargo build` failed with status: exit status: 101
```

## fit build 2

```
$ (cd core && uv run --frozen xtask build firmware --model T3W1)  [in nix-shell]  # fit
Region                   Used        Total    Usage
FLASH               2340.5 KB    3336.0 KB   70.16%
AUX1_RAM             800.0 KB     800.0 KB  100.00%
rc=0
e15fc619f446d5fbbff01a76cef46c1dd5090f9258c974d52323048c9d0a0565  core/build-xtask/artifacts/T3W1/firmware.bin
```

## fit report

```
$ sh crypto/bpq/fit.sh core/build-xtask/artifacts/T3W1 /home/travi/bpq-hwfit-20261005/base  [in nix-shell, fit tree]
== 1 heap: bpq_alloc high-water mark (host build, fixed-width types)
bpq_public_keys root A     peak  69794 B  largest block  30720 B  allocations  12  ok
bpq_sign root A rnd 0      peak  86160 B  largest block  30720 B  allocations  66  ok
bpq_sign root A rnd 1      peak  86160 B  largest block  30720 B  allocations  73  ok
bpq_sign root A rnd 2      peak  86160 B  largest block  30720 B  allocations  31  ok
bpq_sign root A rnd 3      peak  86160 B  largest block  30720 B  allocations 101  ok
bpq_verify root A          peak  62400 B  largest block  30720 B  allocations  11  ok
bpq_public_keys root B     peak  69794 B  largest block  30720 B  allocations  12  ok
bpq_sign root B rnd 0      peak  86160 B  largest block  30720 B  allocations  31  ok
bpq_sign root B rnd 1      peak  86160 B  largest block  30720 B  allocations  59  ok
bpq_sign root B rnd 2      peak  86160 B  largest block  30720 B  allocations 143  ok
bpq_sign root B rnd 3      peak  86160 B  largest block  30720 B  allocations  45  ok
bpq_verify root B          peak  62400 B  largest block  30720 B  allocations  11  ok
bpq_public_keys root C     peak  69794 B  largest block  30720 B  allocations  12  ok
bpq_sign root C rnd 0      peak  86160 B  largest block  30720 B  allocations  52  ok
bpq_sign root C rnd 1      peak  86160 B  largest block  30720 B  allocations  38  ok
bpq_sign root C rnd 2      peak  86160 B  largest block  30720 B  allocations  38  ok
bpq_sign root C rnd 3      peak  86160 B  largest block  30720 B  allocations  24  ok
bpq_verify root C          peak  62400 B  largest block  30720 B  allocations  11  ok
worst heap high-water mark: 86160 B

== 2 stack: worst static path, T3W1 compiler and flags from core/build-xtask/artifacts/T3W1/firmware.cc.json
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/ed25519-donna/curve25519-donna-32bit.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/ed25519-donna/curve25519-donna-helpers.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/ed25519-donna/curve25519-donna-scalarmult-base.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/ed25519-donna/ed25519-donna-impl-base.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/ed25519-donna/ed25519.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/ed25519-donna/modm-donna-32bit.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/hmac.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/memzero.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/sha2.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/sha3.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/bpq/bpq.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/bpq/bpq_mldsa65.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/bpq/bpq_mlkem768.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/vendor/trezor-crypto/bpq/bpq_slh.c  (arm-none-eabi-gcc)
ok  /home/travi/bpq-fit-clone/core/embed/upymod/modtrezorcrypto/modtrezorcrypto.c  (arm-none-eabi-gcc)
mod_trezorcrypto_bpq_public_keys: 16296 B worst-case stack (complete)
  path: mod_trezorcrypto_bpq_public_keys 112 > bpq_public_keys 696 > bpq_xwing_public_from_seed 120 > bpq_mlkem768_keypair 16 > bpqmlk768_keypair_derand 32 > bpqmlk768_indcpa_keypair_derand 13832 > bpqmlk768_poly_getnoise_eta1_4x.constprop.0 856 > bpqmlk768_shake256 288 > mlk_keccak_absorb_once 40 > mlk_keccakf1600_permute_c 304
  bounds used: --indirect bpq_spx256f_treehashx1=bpq_spx256f_wots_gen_leafx1, --vla bpq_spx256f_thash=2208, --vla bpq_spx256f_treehashx1=128
  not counted (no frame info): __fatal_error, __stack_chk_fail, abs, explicit_bzero, m_free, m_malloc_maybe, memcmp, memcpy, memset, mp_get_buffer_raise, mp_obj_new_str_from_vstr, mp_obj_new_tuple, mp_raise_ValueError, mp_raise_msg, strlen, vstr_clear, vstr_init_len
mod_trezorcrypto_bpq_sign: 6600 B worst-case stack (complete)
  path: mod_trezorcrypto_bpq_sign 128 > bpq_sign 104 > bpq_mldsa65_keypair 16 > bpqmld65_keypair_internal 112 > mld_compute_t0_t1_tr_from_sk_components 64 > bpqmld65_polyvec_matrix_expand 1416 > bpqmld65_poly_uniform_4x 4368 > mld_keccak_squeezeblocks_x4 72 > bpqmld65_keccakf1600x4_permute 16 > mld_keccakf1600_permute_c 304
  not counted (no frame info): __stack_chk_fail, explicit_bzero, m_free, m_malloc_maybe, memcmp, memcpy, memset, mp_get_buffer_raise, mp_obj_new_str_from_vstr, mp_raise_ValueError, mp_raise_msg, random_buffer, strlen, vstr_clear, vstr_init_len
mod_trezorcrypto_bpq_verify: 6952 B worst-case stack (complete)
  path: mod_trezorcrypto_bpq_verify 56 > bpq_verify 24 > bpq_mldsa65_verify 40 > bpqmld65_verify 432 > bpqmld65_verify_internal 224 > bpqmld65_polyvec_matrix_expand 1416 > bpqmld65_poly_uniform_4x 4368 > mld_keccak_squeezeblocks_x4 72 > bpqmld65_keccakf1600x4_permute 16 > mld_keccakf1600_permute_c 304
  not counted (no frame info): __stack_chk_fail, m_free, m_malloc_maybe, memcpy, memset, mp_get_buffer_raise
bpq_public_keys: 16184 B worst-case stack (complete)
  path: bpq_public_keys 696 > bpq_xwing_public_from_seed 120 > bpq_mlkem768_keypair 16 > bpqmlk768_keypair_derand 32 > bpqmlk768_indcpa_keypair_derand 13832 > bpqmlk768_poly_getnoise_eta1_4x.constprop.0 856 > bpqmlk768_shake256 288 > mlk_keccak_absorb_once 40 > mlk_keccakf1600_permute_c 304
  bounds used: --indirect bpq_spx256f_treehashx1=bpq_spx256f_wots_gen_leafx1, --vla bpq_spx256f_thash=2208, --vla bpq_spx256f_treehashx1=128
  not counted (no frame info): __fatal_error, __stack_chk_fail, abs, explicit_bzero, m_free, m_malloc_maybe, memcmp, memcpy, memset, strlen
bpq_sign: 6472 B worst-case stack (complete)
  path: bpq_sign 104 > bpq_mldsa65_keypair 16 > bpqmld65_keypair_internal 112 > mld_compute_t0_t1_tr_from_sk_components 64 > bpqmld65_polyvec_matrix_expand 1416 > bpqmld65_poly_uniform_4x 4368 > mld_keccak_squeezeblocks_x4 72 > bpqmld65_keccakf1600x4_permute 16 > mld_keccakf1600_permute_c 304
  not counted (no frame info): __stack_chk_fail, explicit_bzero, m_free, m_malloc_maybe, memcmp, memcpy, memset, strlen
bpq_verify: 6896 B worst-case stack (complete)
  path: bpq_verify 24 > bpq_mldsa65_verify 40 > bpqmld65_verify 432 > bpqmld65_verify_internal 224 > bpqmld65_polyvec_matrix_expand 1416 > bpqmld65_poly_uniform_4x 4368 > mld_keccak_squeezeblocks_x4 72 > bpqmld65_keccakf1600x4_permute 16 > mld_keccakf1600_permute_c 304
  not counted (no frame info): __stack_chk_fail, m_free, m_malloc_maybe, memcpy, memset
                0x00008000                        _stack_section_size = SIZEOF (.stack)
.stack          0x20198000     0x8000

== 3 flash and RAM: the image
.stack               32768   538542080
.data                  512   538574848
.bss                 30400   538575360
.tls                     0   538575360
.heap               697904   538663376
.flash             2394112   134604800
firmware.bin 2396672 B; FIRMWARE_MAXSIZE (models/T3W1/memory.h) 3416064 B
MicroPython GC heap _heap_start..._heap_end = 697904 B
symbols named bpq*: 16024 B (a floor: unprefixed static helpers are not counted; section 4 gives the whole delta)

== 4 against the baseline build /home/travi/bpq-hwfit-20261005/base (same commit, bpq gated out)
firmware.bin 2360320 B -> 2396672 B
   text	   data	    bss	    dec	    hex	filename
2358784	  89552	 730672	3179008	 308200	/home/travi/bpq-hwfit-20261005/base/firmware.elf
2395136	  89552	 730672	3215360	 311000	core/build-xtask/artifacts/T3W1/firmware.elf
```
