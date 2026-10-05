# bpq on the device: the Safe 7's own post-quantum identity

Status: EMULATOR ONLY. Built and tested on the T3W1 debug emulator. Nothing here has
run on hardware, and nothing here authorizes flashing a device.

Ruling: beehive-nature `docs/RULINGS-2026-10-04.md` R4 (option A). The device's
post-quantum identity is its own, derived from a versioned, domain-separated child of
the device's own seed. It is tied to the wallet's identity by a SPEC-BPQ-1 §3 binding
that both sign. The bzDiD phrase is never loaded onto a device, and nothing derived
here is ever imported into a browser.

Spec of record for every byte after the child seed: beehive-nature
`docs/specs/SPEC-BPQ-1.md` §2 (keys), §3 (card, binding), §3b (detached signature).

## 1 · The derivation, version 1

This section was written before the code that implements it.

1. `S` = the device's BIP-39 seed, mnemonic plus passphrase, exactly what
   `apps.common.seed.get_seed()` returns for every other app. A SLIP-39 backup gives
   its own seed through the same call, so both backup kinds work.
2. SLIP-21 (symmetric key derivation), path `["BZPQ-DEVICE", "v1"]`:
   - `N0 = HMAC-SHA512(key = "Symmetric key seed", S)`
   - `N1 = HMAC-SHA512(key = N0[0:32], 0x00 ‖ "BZPQ-DEVICE")`
   - `N2 = HMAC-SHA512(key = N1[0:32], 0x00 ‖ "v1")`
   - `PRK = N2[32:64]` (32 bytes)
3. `PRK` takes the place of `masterPrk` in SPEC-BPQ-1 §2, with a context string the
   host names. Every key below it uses the frozen SPEC-BPQ-1 labels:

   | key | label | bytes |
   |---|---|---|
   | ML-DSA-65 seed ξ | `BDID-v1/ml-dsa-65-record-key` | 32 |
   | X-Wing seed | `BDID-v1/x-wing-kem-key` | 32 |
   | SLH-DSA-SHAKE-256f seed | `BDID-v1/slh-dsa-shake-256f-succession` | 96 |

   `expand(label, L) = HKDF-Expand(SHA-256, PRK, label ‖ context, L)`.
4. `id = bech32m("bzpq", SHA3-256("bpq1/id" ‖ dsaPk ‖ SHA3-256("bpq1/succession" ‖ slhPk)))`.

The same PRK and context give the same card in `surfaces/bpq.js` and
`crates/bsigner/src/bpq.rs`; that equality is what the emulator cross-check proves.

**Kept apart from everything else.**
- SLIP-21's master key string ("Symmetric key seed") differs from every BIP-32 and
  SLIP-10 curve seed string, so no coin path reaches this tree.
- No other app uses the label `BZPQ-DEVICE`. Existing SLIP-21 labels in this tree:
  `SLIP-0019`, `SLIP-0024`, the WebAuthn and Evolu nodes, and THP credentials.
- The MCU attestation key (`secret_key_mcu_device_auth`, ML-DSA-44) is a factory key
  from the secret store, not from the seed. It is never used here and never a user key.
- The app gets the 32-byte child, through the keychain's SLIP-21 namespace check. The
  C code under it gets only that child and wipes every seed and secret key it derives.

**Versioning.** A change to any byte of this derivation is a new version: the path
becomes `["BZPQ-DEVICE", "v2"]` and gives a new id. Version 1 is never rewritten.

**Context.** The host names it. The device refuses an empty context, the reserved
`root` (SPEC-BPQ-1 R2: no signing key exists under it), anything over 64 bytes, and
any byte outside printable ASCII, so what the screen shows is what was used.

## 2 · Messages

`common/protob/messages-bpq.proto`, wire ids 1300 to 1303.

- `BpqGetCard(context, show_display)` → `BpqCard(id, dsa_public_key,
  kem_public_key, succession_commit, signature)`. The signature is the card's own
  ML-DSA-65 signature over `"bpq1/card" ‖ dsa ‖ kem ‖ succ`. With `show_display`,
  the device shows the id before answering.
- `BpqSign(context, binding | detached)` → `BpqSignature(id, signature)`.
  The host sends structured fields, never message bytes. The device checks them
  against SPEC-BPQ-1 §3 (the `at` shape, claim kinds and values), builds the signed
  bytes itself, shows the id and every field, and signs only after the user confirms:
  - binding: `"bpq1/bind" ‖ SHA3-256(id ‖ "\n" ‖ at ‖ "\n" ‖ lines)`
  - detached: `"bpq1/detached" ‖ fileSha3 ‖ SHA3-256(id ‖ "\n" ‖ at ‖ "\n" ‖ size)`

No message carries a seed, a PRK or a secret key, in either direction.

## 3 · Code

| path | what |
|---|---|
| `crypto/bpq/bpq.c`, `bpq.h` | SPEC-BPQ-1 §2 key derivation from a PRK, ML-DSA-65 sign and verify |
| `crypto/bpq/bpq_mldsa65.c` | `vendor/mldsa-native` built once more at parameter set 65, namespace `bpqmld65_` |
| `crypto/bpq/bpq_mlkem768.c` | `vendor/mlkem-native` (v2.0.0) at ML-KEM-768, namespace `bpqmlk768_`, for the X-Wing public key |
| `crypto/bpq/bpq_slh.c` | `vendor/sphincsplus` ref at SLH-DSA-SHAKE-256f, namespace `bpq_spx256f_`, key generation only |

`build_test.sh` refuses any exported symbol of these objects that does not start
with `bpq`, so none can collide with the tree's own ML-DSA-44 or SHA2-128s builds.
| `core/embed/upymod/modtrezorcrypto/modtrezorcrypto-bpq.h` | `trezorcrypto.bpq` |
| `core/src/apps/bpq/` | the two handlers |
| `core/tests/test_trezor.crypto.bpq.py` | key generation against public vectors |
| `crypto/bpq/emu_xcheck.py` | the emulator cross-check against `bpq.js` and `bsigner` |

## 4 · What is not claimed

- **Hardware.** ML-DSA-65 working memory goes to the MicroPython heap through
  mldsa-native's `MLD_CONFIG_CUSTOM_ALLOC_FREE`, wiped before it is freed. Whether
  that, plus the stack mldsa-native still uses, fits the T3W1 firmware (32 KiB app
  stack) is UNVERIFIED. The hardware firmware build does not include this app.
- **Channel.** A post-quantum signature from the device is not post-quantum channel
  confidentiality (THP is Noise_XX, classical) and not device attestation.
- **Audit.** mldsa-native, mlkem-native and the SPHINCS+ reference are third-party
  code; agreement with `@noble/post-quantum` and RustCrypto on public vectors is a
  cross-check between implementations, not an audit.
