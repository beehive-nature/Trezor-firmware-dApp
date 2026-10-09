# bpq on arm-none-eabi: the compile fix for bpq_slh.c, with receipts

2026-10-09, Seat 3 (Claude Code), on `bpq-safe7-7a8709b` after `da2583079`. Scope: ONE
TRANSLATION UNIT compiled for the T3W1 hardware target with the hardware build's own
compile line, the host test, and an emulator rebuild with its unit tests. No hardware
image was built (bpq is still gated to the emulator; lifting that gate is the separate
reviewed change the handoff names), no device was touched, nothing was flashed. The
change was reviewed read-only before it was committed; the review's own receipts are
marked below.

## The defect, as committed at da2583079

`crypto/bpq/bpq_slh.c:60` includes `vendor/sphincsplus/ref/merkle.c` textually. Inside it,
`merkle.c:25` declares `unsigned steps[ SPX_WOTS_LEN ];` (the type `chain_lengths` takes,
`wots.h:23`) and `merkle.c:29` assigns it to `uint32_t *wots_steps` (`wotsx1.h:15`). On
arm-none-eabi-gcc `uint32_t` is `long unsigned int`, a distinct 32-bit type, so under the
firmware's `-Werror` the assignment is an error. On x86-64 (and i386) `uint32_t` is
`unsigned int`, the types coincide, and the emulator and the host test never see it. It
is the only instance of that diagnostic in the whole translation unit (review: the
unfixed unit under `-Wno-error` prints exactly one warning, this one).

```
$ echo | arm-none-eabi-gcc -dM -E -mcpu=cortex-m33 -mthumb - | grep -E '__UINT32_TYPE__|__SIZEOF_(INT|LONG)__'
#define __SIZEOF_INT__ 4
#define __SIZEOF_LONG__ 4
#define __UINT32_TYPE__ long unsigned int
$ echo | gcc -dM -E - | grep __UINT32_TYPE__          # WSL host, gcc 15.2.0
#define __UINT32_TYPE__ unsigned int
$ echo | gcc -m32 -dM -E - | grep __UINT32_TYPE__     # i386, also ILP32 (macro level only)
#define __UINT32_TYPE__ unsigned int
```

The vendored tree is the `vendor/sphincsplus` submodule at `129b72c80e122a22a61f71b5d2b042770890ccee`
(upstream `sphincs/sphincsplus`, branch `consistent-basew`, whose head is that same
commit); upstream `master` still carries the same two declarations today.

## The decision

The fix is a scoped diagnostic block around that one include in `bpq_slh.c` (inserted
lines 60-73 and 75; line 74 is the existing include):

```c
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
#include "../../vendor/sphincsplus/ref/merkle.c"
#pragma GCC diagnostic pop
```

with a comment beside it saying what is silenced and why. It silences
`-Wincompatible-pointer-types` for the merkle.c include only (that file and the headers
it is first to pull in: `utilsx1.h`, `wots.h`, `wotsx1.h`, `merkle.h`), changes no code,
and touches no vendored file. Why this shape and not another:

- The tree already treats this reference this way: `core/embed/rtl/build.rs` (feature
  `sphincsplus`) compiles its own eight sphincsplus units with
  `-Wno-incompatible-pointer-types`, and upstream Trezor scopes `#pragma GCC diagnostic`
  push/ignored/pop around vendored `printf.c` (`core/embed/rtl/printf.c:742` and
  `:1062`, commit `b1af51662`). This block is narrower than both.
- A flag on the bpq source list in `build.rs` would silence whole units and sit in the
  block the handoff reserves for the reviewed gate lift; a flag on `crypto_attrs` would
  cover all of trezor-crypto.
- Changing the vendored type means a forked submodule and a moved pin shared with the
  firmware's own SHA2-128s build: a reviewed change, not a seat's compile fix.
- Reimplementing `merkle_gen_root` locally would duplicate reference signing-tree code
  and make `bpq_slh.c:2-4` and `docs/bpq-device.md` untrue.
- The measurement's uncommitted `#pragma GCC diagnostic warning` line had no push/pop,
  governed the rest of the unit, and prints a warning on every build; it is not carried
  over, nor is the fit clone's opened gate.

The fix at the source is one line, `wotsx1.h:15` `uint32_t *wots_steps;` to
`unsigned int *wots_steps;` (changing `merkle.c:25` instead only moves the error to the
`chain_lengths` call at `:28`). Filed upstream 2026-10-09 as
https://github.com/sphincs/sphincsplus/issues/70 (open at the time of writing). Delete
the block once the pinned merkle.c builds for arm-none-eabi without it.

## Receipts

Compiler: `arm-none-eabi-gcc (Arm GNU Toolchain 13.3.Rel1 (Build arm-13.24)) 13.3.1 20240614`,
from the fork's nix shell. Compile line: the entry for `bpq_slh.c` in the compile database
of the 2026-10-05 fit build (`core/build-xtask/artifacts/T3W1/firmware.cc.json`, 98
arguments, `-std=gnu11 -Os -mcpu=cortex-m33`, `-Werror` present,
`-Wno-incompatible-pointer-types` absent), replayed from `core/embed/rtl` against this
checkout by `crypto/bpq/arm_probe.py` (no shell; only the compiler path, the source path
and `-o` substituted).

**Control, the unit as committed at da2583079:**

```
rc=1
In file included from /home/travi/bpq-rb-clone/core/vendor/trezor-crypto/bpq/bpq_slh.c:60:
/home/travi/bpq-rb-clone/core/vendor/trezor-crypto/bpq/../../vendor/sphincsplus/ref/merkle.c: In function 'bpq_spx256f_merkle_sign':
/home/travi/bpq-rb-clone/core/vendor/trezor-crypto/bpq/../../vendor/sphincsplus/ref/merkle.c:29:21: error: assignment to 'uint32_t *' {aka 'long unsigned int *'} from incompatible pointer type 'unsigned int *' [-Werror=incompatible-pointer-types]
   29 |     info.wots_steps = steps;
      |                     ^
cc1: all warnings being treated as errors
```

(identical, path aside, to `HARDWARE_FIT_RECEIPT.md` fit build 1.)

**The unit with the block, same compile line:**

```
rc=0
exported T symbols: 35; not prefixed bpq: none
00000000 T bpq_slh_shake256f_public_from_seed
00000000 T bpq_spx256f_merkle_gen_root
00000000 T bpq_spx256f_merkle_sign
d06a3ee28696852471596f56533103d17129328514e10a2fc10a91f31375de35  final_fixed.o
```

**The three other bpq units, unchanged, their own compile lines:** `bpq.c` rc=0,
`bpq_mldsa65.c` rc=0, `bpq_mlkem768.c` rc=0.

**Scope of the block (review, read-only, T3W1 flags, probes fed on stdin or through a
pipe copy, nothing written):** a deliberate `uint32_t *p = u;` with `unsigned u[1]`
placed right after the `pop`, at end of file, before the `push`, appended to a copy of
`wots.c`, and appended to a copy of `wotsx1.c` is rejected in every case
(`error: initialization of 'uint32_t *' ... [-Werror=incompatible-pointer-types]`,
rc=1); placed between the include and the `pop` it is suppressed (rc=0). These are the
only pragmas in the file. On host gcc 15, where this diagnostic is an error by default,
the same block turns rc=1 into rc=0, so the fix survives a toolchain move to GCC 14+.
clang 21 compiles the file with the host-test flags without a `__GNUC__` guard.

**Generated code (review):** x86-64 with the host-test flags, assembly of the file
before and after has the same md5 (2790 lines, 0-line diff); with the emulator
compile-database flags and `-g0`, 0-line diff over 3260 lines (with `-g`, the only
differences are `.loc`/DWARF line numbers shifted by the inserted lines); for ARM with
`-g0`, the file after equals the file before compiled with
`-Wno-incompatible-pointer-types` (0-line diff over 3652 lines).

**Host test, this tree:**

```
$ sh crypto/bpq/build_test.sh
... 25 [ok] lines ...
ALL OK
rc=0
```

**Emulator rebuilt from this tree, and its unit tests:**

```
$ nix-shell --run "cd core && uv run --frozen xtask build firmware --emulator --model T3W1 --pyopt false --debug-link true --disable-tropic"
xtask rc=0
firmware-emu before: 5c1f7332ea540140c521bd886d3a75a8e9aa0876e94ec90e1a8dedd9193638a3  (the 2026-10-05 receipt's binary)
firmware-emu after:  46815d00de6f59325ecf186aac48bfbf1b2da7db9aef43ae14676bde64652a90
$ nix-shell --run "cd core/tests && ./run_tests.sh test_trezor.crypto.bpq.py"
Ran 5 tests
OK: test_trezor.crypto.bpq.py
PASSED: 1/1 tests OK!
run_tests rc=0
```

A second rebuild after the comment text was revised on review (same line count)
produced the byte-identical `46815d00...` binary and the same five passing tests.

`crypto/bpq/bpq_slh.c` after the change: git blob `f383b99ae61960c87b4979b224d96e2ee0c5b9ff`,
sha256 `ceb3dea3fdc18045d99166b37727b585d1860bbef8ea9028cab47b4d0ef5a719`; 15 lines
inserted, none removed, include order unchanged, the `// clang-format off` guard at
`:26-29` untouched, longest line 79 columns, no CR bytes, file ends with a newline;
clang-format 21.1.8 with the repository's `.clang-format` proposes no change (review).

## Not claimed

- A hardware image containing bpq: none was built. That needs the gate lift
  (`core/embed/rtl/build.rs` `&& cfg!(feature = "emulator")`, `core/embed/upymod/build.rs`
  `if cfg!(feature = "emulator")`, `core/src/apps/workflow_handlers.py` `utils.EMULATOR and`,
  and the "emulator only" sentences in `docs/bpq-device.md:3-4` and the three comments
  beside those gates rewritten in the same commit), landed as a reviewed change, then two
  fresh pinned builds compared byte for byte (beehive-nature `tools/firmware/build-pinned.sh`
  and `compare-builds.py`; that recipe pins `--pyopt true`, no debuglink, and a
  non-production build embeds the `unsafe_signed_prod` vendor header). The fit build of
  2026-10-05 remains the only hardware-flag compile of these units, and it came from a
  dirty tree.
- The emulator cross-check (`crypto/bpq/emu_xcheck.py`) against `bpq.js` and `bsigner`
  was not re-run: the block changes no generated code (see above), the rebuilt emulator
  passes its unit tests, and the oracles in beehive-nature have moved since the
  2026-10-05 receipt (their hashes there no longer name the files at HEAD), so a re-run
  belongs with the reviewed hardware change and a pinned oracle revision.
- On-device stack headroom, heap fragmentation, signing time, the display flow: unmeasured
  until the gate-6 ceremony.
- The i386 statement rests on the compiler's macros only; this host has no i386 headers
  to compile against.

## Reproduce

```
cd core/embed/rtl   # from a checkout that has a hardware compile database
python3 ../../../crypto/bpq/arm_probe.py bpq_slh.c /tmp/bpq_slh.o \
    --db <firmware.cc.json of a hardware build> \
    --cc /nix/store/<gcc-arm-embedded-13.3.rel1>/bin/arm-none-eabi-gcc
```

The control is the same command on a checkout of `da2583079`. Without `--db`, the
script reads this checkout's own `core/build-xtask/artifacts/T3W1/firmware.cc.json` and
refuses when that build had no bpq (0 database entries), which is the case until the
gate is lifted.
