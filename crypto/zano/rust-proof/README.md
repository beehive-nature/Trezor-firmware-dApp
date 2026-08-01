# zano.rs compile-and-run proof

The firmware's own `cargo check` cannot run standalone: `generate_trezorhal_bindings()`
needs SCons-generated model headers, and it runs before the crypto bindings. That is the
HAL, not this module. This crate proves exactly the thing in question and nothing more:

  - bindgen really parses `crypto/zano/clsag_ggx.h` and `zano_generators.h`
  - the generated types match the C layout (bindgen emits size/offset assertions;
    `zano_ring_member` is 224 bytes, fields at 0 / 160 / 192)
  - `core/embed/rust/src/crypto/zano.rs` compiles — the REAL file, mounted with
    `#[path]`, never a copy that could drift
  - it links against the real C and the tests EXECUTE

The headline test feeds a CLSAG_GGX signature that the **Zano reference implementation
already accepted** (from the 8/8 outbound conformance run) through the Rust wrapper. If
the wrapper mis-orders a field, mishandles the asymmetric 1/8 convention, or walks the
ring wrong, it fails.

    cargo test -- --test-threads=1

`--test-threads=1` is required: `zano_generators_init` writes the `zano_point_X` global
without a guard, so parallel first-calls race and one observes a failed unpack. Harmless
on-device, where this is single-threaded.

## What writing this caught

Three real defects the compiler found that review had not:

  - `zano_generators_init` was never in the bindings — it is declared in
    `zano_generators.h`, and only `clsag_ggx.h` had been wired into `crypto.h`.
  - `ge25519_unpack_vartime` returns `int` and returns **1 on success**. The wrapper had
    `if !ffi::ge25519_unpack_vartime(...)`, inverting the check — the same defect class
    that once sat in `clsag_ggx.c` and let malformed points through.
  - bindgen derives no `Default` for `zano_ring_member`, so the scratch arrays had to be
    zeroed explicitly.

And one wrong assumption in the tests themselves: `0xff * 32` **decodes fine** in donna,
so it never reached the `InvalidEncoding` branch it was written to exercise. A probe
found `y = 0x02` followed by zeros, which is genuinely rejected. Assumptions about what
a curve implementation rejects are worth probing rather than asserting.
