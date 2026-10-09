# bpq hardware-build candidate for T3W1: two pinned builds, compared, with fit and cross-check

2026-10-09, Seat 3 (Claude Code), step 2 of the Safe 7 lane by the founder's relayed order.
Candidate commit `967fddb3d77d96436bba53d18a21e4d23f30b2ea` on `bpq-safe7-7a8709b`
(`5e12b132f` → `7dab5f939` the gate → `967fddb3d` the oracle move). Scope: two fresh pinned
T3W1 hardware builds of the candidate at the fixed path, compared byte for byte; one pinned
build of the parent for the fit baseline; the fit re-run on build A in place; the emulator
cross-check at the candidate; negative checks. NO DEVICE, no USB enumeration, no flash, no
unlock, no wipe, no real phrase, no mainnet. Development keys: not production signing
authority. Build readiness authorizes nothing. Independent review by zCode is requested
(beehive-nature `docs/dispatches/2026-10-09-zcode-review-request-safe7-step2.md`).

## The change (commit 7dab5f939)

bpq is a model-scoped cargo feature of universal T3W1 firmware, hardware and emulator alike,
on this tree's `eos` precedent: declared by `core/embed/models/T3W1/model.toml`, used by
`core/embed/projects/firmware/project.toml`, declared in `rtl` and `upymod` (`upymod/bpq`
implies `rtl/bpq`), forwarded by the `firmware` and `unix` project crates. `rtl/build.rs` gates
the C on `universal_fw && bpq` and refuses any other model by name; `upymod/build.rs` freezes
`apps/bpq` under `bpq`, defines `USE_BPQ` under the same condition, folds `utils.USE_BPQ` to a
literal; `modtrezorutils` exports `USE_BPQ`; `workflow_handlers.py` routes on it. Negative
checks: `core/embed/xtask/tests/bpq_model_scope.rs` (3 passed, run by
`cd core/embed && cargo test -p xtask --test bpq_model_scope`); `cargo check -p rtl` and
`-p upymod` with `models/model_t3t1,universal_fw,emulator,bpq` both refuse ("bpq is
model-scoped to T3W1; refusing to build it for model T3T1", exit 101), the T3W1 control passes;
`build_mocks --check` rc 0; rustfmt, black, isort, flake8 clean. Behaviour change: the
universal emulators of the other models lose bpq (they had it since `f7dba43d2`); their unit
test is guarded with `if utils.USE_BPQ`.

## Recipe

beehive-nature `tools/firmware/build-pinned.sh CHECKOUT FULL_COMMIT` (refuses a wrong
revision, a dirty tree including untracked files, an unpinned submodule, an existing
`core/build-xtask`; `CFLAGS=-ffile-prefix-map=$PWD=/build/bsafe`; in the checkout's nix shell:
`uv sync --frozen && uv run --frozen xtask build firmware --model T3W1 --pyopt true`) and
`tools/firmware/compare-builds.py`, copied into the evidence directory and hashed there. Each
build: a fresh `git clone --no-hardlinks` of the local mirror `~/bpq-rb-clone` into
`/home/travi/bsafe-canonical-build`, origin set to the private fork url, detached at the
candidate, all 18 submodules fetched from their public upstreams (`git submodule status
--recursive`: every line begins with a space), tree clean (0 status lines) before and after.
Build A was read in place (fit, identities, controls), then moved to
`/home/travi/bsafe-candidate-run-1`; build B repeated the same steps into the same path and
moved to `-run-2`. Evidence directory `/home/travi/bsafe-candidate-20261009` (every log hashed
in `logs.sha256`).

## Two builds, byte-identical

```
build 1 exit 0  2026-10-09T23:23:55Z -> 2026-10-09T23:28:23Z   (tree status 0 before, 0 after)
build 2 exit 0  2026-10-09T23:38:33Z -> 2026-10-09T23:43:01Z   (tree status 0 before, 0 after)
features identical   (the three `cargo build --package …` lines of secmon, kernel, firmware)
$ python3 -I compare-builds.py bsafe-candidate-run-1 bsafe-candidate-run-2 --revision 967fddb3d… \
    --artifact core/build-xtask/artifacts/T3W1/firmware.bin \
    --artifact core/build-xtask/thumbv8m.main-none-eabihf/release/kernel.bin \
    --artifact core/build-xtask/thumbv8m.main-none-eabihf/release/secmon.bin
{"byte_identical": true, "error": null}        compare exit=0
firmware.bin  2396672 B  dfc5d2a435c78223115b191c076080981f280c8125873a08784d4a39ad6508aa
kernel.bin     330752 B  2bfc721406bd48e74fd805e4982a9d4ba7e7a137e0bedb1ba4e83a3a0f784f63
secmon.bin     186368 B  4c6d3c667aa2d9f4a53cf81ede1aab562b91cc54d236ef79c989e407c4866d32  (freshly built; see below)
```

Controls, each refused as it must be: the wrapper against a wrong revision (exit 1); the
wrapper against the already-built checkout (existing `core/build-xtask`, exit 1); the
comparison tool against the same checkout twice (`"Two distinct checkouts are required"`,
exit 1).

## Identities, read from build A's artifacts

```
== image ==
dfc5d2a435c78223115b191c076080981f280c8125873a08784d4a39ad6508aa  firmware.bin   2396672 B
== fingerprint ==
headertool (build log):      Fingerprint: 9643 e4be 1c1d 4e2e 58a1 5f97 2aaa a256 9e3b ef21 9fe2 8915 e848 e1ef ae80 0a9f
trezorctl firmware verify:   Vendor header from UNSAFE, DO NOT USE!, version 0.0
                             Firmware fingerprint: 9643e4be1c1d4e2e58a15f972aaaa2569e3bef219fe28915e848e1efae800a9f
== vendor header (first 1024 bytes) ==
6c80f1f17f1a352fbb3c5f63ab902f0142aea3f1c9205a0ec097ab2965229553   text "UNSAFE, DO NOT USE!"
equal to core/embed/models/T3W1/vendorheader/vendorheader_unsafe_signed_prod.bin
== secmon ==
embedded, the prebuilt core/embed/models/T3W1/secmon/secmon.bin (kernel/build.rs, no bootloader_devel):
f9cacf15ec3e126fa26d31790bc5038474f373f81f616163937c5beb277098d9   186368 B
freshly built core/build-xtask/thumbv8m.main-none-eabihf/release/secmon.bin (compared, not embedded):
4c6d3c667aa2d9f4a53cf81ede1aab562b91cc54d236ef79c989e407c4866d32
== bootloader (prebuilt) ==
44fc92abe00b88de59da861b1b929bba131762abe07740477f09441447b94326   bootloader_T3W1.bin
== resolved features (firmware package) ==
models/model_t3w1,pyopt,dev_keys,universal_fw,frozen,…,bpq   (debuglink 0, emulator 0, debug 0,
pyopt 1, dev_keys 1, bootloader_devel 0, bpq 1)
== bpq symbols in firmware.elf, names matching ' (bpq_|mod_trezorcrypto_bpq_)' ==
candidate 47     parent baseline (5e12b132f) 0
== FLASH ==
candidate         FLASH   2340.5 KB   3336.0 KB   70.16 %
parent baseline   FLASH   2305.0 KB   3336.0 KB   69.09 %
parent image 6945ee90ff2df43456b47fe12ef2da42aff34770bbeb5cc2fbfd9cd3931dd650   2360320 B
delta  2396672 - 2360320 = 36352 B  (the 2026-10-05 fit measurement's delta, now from a committed tree)
```

Toolchain inside the pinned nix shell (both builds): see `toolchain-1.txt` / `toolchain-2.txt`
in the evidence directory (Arm GNU Toolchain 13.3.Rel1; the Rust nightly and uv pinned by
`shell.nix`).

## Fit, re-run on build A in place against the parent baseline (`sh crypto/bpq/fit.sh`, rc 0)

```
heap (host, through the bpq_alloc seam, fixed-width types):
  bpq_public_keys  peak 69794 B   largest block 30720 B
  bpq_sign         peak 86160 B   largest block 30720 B   (all rounds, roots A, B, C)
  bpq_verify       peak 62400 B   largest block 30720 B
  worst heap high-water mark: 86160 B
stack (worst static path, T3W1 compiler and flags from build A's firmware.cc.json):
  mod_trezorcrypto_bpq_public_keys 16296 B   mod_trezorcrypto_bpq_sign 6600 B   mod_trezorcrypto_bpq_verify 6952 B
  .stack 0x8000 (32 KiB)
```

The same numbers as `HARDWARE_FIT_RECEIPT.md` (2026-10-05, a dirty measurement tree), now from
the committed candidate. Still not measured: the MicroPython VM frames above the binding,
heap fragmentation on a device, signing time; those exist only on a device.

## Emulator cross-check at the candidate (`crypto/bpq/emu_xcheck_receipt_967fddb3d.json`)

```
fork_revision 967fddb3d77d96436bba53d18a21e4d23f30b2ea   fork_dirty false
emulator 66bb00b4e0c8530a… (T3W1, --pyopt false --debug-link true --disable-tropic), 47 bpq symbols
unit test core/tests/test_trezor.crypto.bpq.py: Ran 5 tests, PASSED
oracle: beehive-nature d46a26c215a583e26f0f3bdf7631faeebc3d695a
  surfaces/bpq.js                       d2c42d58d7bf26714eae9bb20c1d1a988816940666d2e500ec9cf7068d83ecb5
  surfaces/onboarding/vendor/bpq-lib.js 510efda5929db4ffe2714d647dac9055d723d7e8d1ea1b91d0983b3b7ba62e66
  crates/bsigner/src/bpq.rs             1f3eb997c659fa473d570ba13d42494ddf2a4d2857c3621608b3b4fc93082eef
  (the Rust oracle crates/bpq-device-xcheck, cargo 1.98.1 --locked, prints that bpq.rs sha256)
js   keys_equal true  signatures_verify true  controls_refused true  ok true
rust keys_equal true  signatures_verify true  controls_refused true  ok true
second profile same card: true    device id bzpq1lws2ertcufjd8ehnr0qndqrz5krg3qqd4zltg7d5vrgncl8j8qjsr47lvv
PASS: device card equals bpq.js and bsigner; device binding and detached signature verify in both;
R4 binding both ways; refusals held; second profile gave the same card. EMULATOR ONLY.
```

## Not claimed

- Anything on a device. No image was installed anywhere; nothing here authorizes installing
  one. On-device stack headroom, heap fragmentation, signing time, the display flow: unmeasured.
- Hardware fit as a whole (the heap number is a host measurement through the seam; the stack
  number stops at the MicroPython binding).
- Independent reproducibility: this is a same-host, same-path repeat-build comparison under
  pinned nix inputs, not an independent-builder or hermetic claim.
- Security of the fork: the upstream security reconciliation (audit gate 1) has no receipt;
  the candidate is 23 ahead of and 825 behind upstream `c1dacf2f4` (merge-base `0cd72f033`).
- Transport (gate 2), recovery tests (gate 4), binding/replay/downgrade/rotation evidence
  (gate 5): no receipt.
- The cross-check is a cross-check between implementations, not an audit (SPEC-BPQ-1 §6).

## Pending

- zCode's independent review of `7dab5f939`, `967fddb3d`, the public oracle crate and this
  receipt.
- Gates 1, 2, 4 (firmware seat), gate 5 (PQ lane), the 13 `dev@beehive-nature` fork commits
  (founder acknowledgment).
- Gate 6: the founder's specific informed consent, asked only after the readiness receipts and
  the privacy-safe procedure exist (`docs/dispatches/2026-10-09-safe7-gate6-ceremony-plan.md`).
