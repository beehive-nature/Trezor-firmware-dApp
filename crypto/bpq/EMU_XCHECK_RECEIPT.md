# bpq emulator receipts

Produced at `db92c2566da8353e1f179c77f2bf3bd7ea32c5b8` (clean tree), 2026-10-05T03:03:27Z, in WSL with `nix-shell`.
Pasted unedited; ANSI colour codes and per-line emulator log lines (DBG/INF/WRN) were
filtered from the unit-test output, and Rust compiler warnings from the cross-check's
stderr. The full cross-check output is `emu_xcheck_receipt.json` beside this file.
Public BIP-39 test vector only (abandon x11, about). EMULATOR ONLY: no device, no flash.

## 0-tree

```
$ git rev-parse HEAD; git status --porcelain --untracked-files=all
db92c2566da8353e1f179c77f2bf3bd7ea32c5b8
(empty = clean)
```

## 1-build

```
$ (cd core && uv run --frozen xtask build firmware --emulator --model T3W1 --pyopt false --debug-link true --disable-tropic)  [in nix-shell]
   = note: `#[warn(unused_features)]` (part of `#[warn(unused)]`) on by default

warning: `trezor_lib` (lib) generated 1 warning
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 47.26s
rc=0
05b6912c3c8d85519ba5945b8cd4678df95297e18768e35a184758f3200c137d  core/build-xtask/artifacts/T3W1/firmware-emu
```

## 2-host-test

```
$ sh crypto/bpq/build_test.sh
symbols: every export of the four bpq objects starts with bpq
ML-DSA-65 keyGen, NIST ACVP
  [ok] pk byte-equal tcId 26
  [ok] pk byte-equal tcId 27
  [ok] pk byte-equal tcId 28
ML-KEM-768 keyGen, NIST ACVP
  [ok] ek byte-equal tcId 26
  [ok] ek byte-equal tcId 27
  [ok] ek byte-equal tcId 28
SPEC-BPQ-1 roots, bpq-vectors.json
  [ok] dsaPublicKey root A, context pq:vector
  [ok] kemPublicKey root A, context pq:vector
  [ok] successionCommit root A, context pq:vector
  [ok] signature verifies under the vector key root A, context pq:vector
  [ok] altered signature refused root A, context pq:vector
  [ok] dsaPublicKey root B, context pq:vector
  [ok] kemPublicKey root B, context pq:vector
  [ok] successionCommit root B, context pq:vector
  [ok] signature verifies under the vector key root B, context pq:vector
  [ok] altered signature refused root B, context pq:vector
  [ok] dsaPublicKey root C, context pq:vector
  [ok] kemPublicKey root C, context pq:vector
  [ok] successionCommit root C, context pq:vector
  [ok] signature verifies under the vector key root C, context pq:vector
  [ok] altered signature refused root C, context pq:vector
context rules
  [ok] "root" refused 
  [ok] empty refused 
  [ok] newline refused 
  [ok] no keys under "root" 
ALL OK
rc=0
```

## 3-unit-test

```
$ (cd core/tests && ./run_tests.sh test_trezor.crypto.bpq.py)  [in nix-shell]
class TestCryptoBpq
  test_mldsa65_keygen_acvp ... ok
  test_mlkem768_keygen_acvp ... ok
  test_spec_bpq_1_roots ... ok
  test_sign_verifies_under_vector_key ... ok
  test_context_refusals ... ok
class TestCaseWithContext
Ran 5 tests
Task #1 terminated cleanly
Summary:
-------------------
OK: test_trezor.crypto.bpq.py
PASSED: 1/1 tests OK!
```

## 4-xcheck

```
$ BEEHIVE_NATURE=<checkout> uv run --frozen python crypto/bpq/emu_xcheck.py  [in nix-shell]
rc=0
PASS: device card equals bpq.js and bsigner; device binding and detached signature verify in both; R4 binding both ways; refusals held; second profile gave the same card. EMULATOR ONLY.
```
