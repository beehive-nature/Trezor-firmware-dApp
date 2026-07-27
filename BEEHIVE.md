# Trezor-firmware-dApp

On-device **Zano (Zarcanum)** signing for [beehive-nature](https://github.com/beehive-nature/beehive-nature) — the firmware side of a Trezor-co-signed Zano escrow. A fork of [`trezor/trezor-firmware`](https://github.com/trezor/trezor-firmware). **Not a Cargo crate** (C + MicroPython + Rust xbuild); deliberately separate from the beehive-nature workspace.

> **The one rule:** the Zano spend secret `s` is derived and used *only* inside this firmware; it never exists in host RAM. The host (`dro-signer` / `chain-zano` in beehive-nature) is an untrusted coordinator that supplies public ring data and receives public signature outputs.

## What this repo carries

Two beehive change-sets on top of upstream trezor-firmware:

1. **EOS → Vaulta promotion** *(done)* — removes the `# Legacy coin support` gate so the EOS app ships on the Safe 7 (T3W1). 7 sites / 5 files. Also serves the EOS rail (`chain-eos`). **Upstream-PR-able.**
2. **Zano app** *(specced, unstarted)* — on-device `CLSAG_GGX` / Zarcanum signing. See [`docs/crypto-delta-spec.md`](docs/crypto-delta-spec.md). v1 scope: native ZANO transfers only.

## Relationship to beehive-nature

| | beehive-nature (host) | this repo (device) |
|---|---|---|
| Holds | chain-zano spec, dro-signer seam, escrow, atmirror | crypto/zano, apps/zano, signing state machine |
| Trust | untrusted coordinator | holds `s` |
| Meets at | `proto/messages-zano.proto` (frozen v0.3, **authoritative**) | `common/protob/messages-zano.proto` (build copy) |

The proto is the **only** contract between the two repos. CI checksum-checks the two copies so they cannot silently drift.

## Fork model & upstream sync

Forked from `trezor/trezor-firmware`; base pinned at `0cd72f0`.

```sh
git remote add upstream https://github.com/trezor/trezor-firmware.git
git fetch upstream && git rebase upstream/main
```

Beehive changes are kept in two deliberately-separated shapes so rebases stay predictable:

- **Additive** (new paths — ~zero upstream conflict): `crypto/zano/`, `core/src/apps/zano/`, `core/tests/test_apps.zano.*`, the vector harness.
- **Overlay** (modifications to upstream files — the only conflict surface): the Vaulta 7 sites + the Zano wiring (`SConscript.*` gates, `models/*/model.toml` features, Cargo `zano` feature). A small, named commit set.

## Build (WSL / Ubuntu)

```sh
sudo apt-get install -y scons libsdl2-dev libsdl2-image-dev llvm-dev libclang-dev clang protobuf-compiler
rustup default nightly          # no rust-toolchain.toml pins it; nightly is required
git submodule update --init --recursive
uv sync && source .venv/bin/activate
xtask build firmware --emulator -m t3w1   # Safe 7 emulator, EOS promoted
./emu.py                                  # then drive trezorlib against it
```

Device firmware (cross-compile) additionally needs `gcc-arm-none-eabi` + `rustup target add thumbv8m.main-none-eabihf`.

## Zano port — start here

[`docs/crypto-delta-spec.md`](docs/crypto-delta-spec.md) is the implementation plan. Four bounded new-work categories, in order:

1. **Generators** (X, U, H2) — fixed constants lifted verbatim from `hyle-team/zano`, vector-checked.
2. **CLSAG_GGX** — the known dv-CLSAG algorithm; highest risk is byte-identical Fiat–Shamir transcript / domain-sep tags.
3. **bppe** — Bulletproofs+ extended (two-mask); adapts Monero's BP+ offload pattern.
4. **Balance proof** — small double-Schnorr over G/X.

Reuses trezor's `ed25519-donna` + `crypto/monero/` toolkit; **does not** vendor a second Ed25519. The bidirectional differential vector harness (Zano-crypto-linked vectors ↔ host-built device-code oracle, byte-exact at every intermediate) is specified in the spec and is what de-risks the byte-exact port.

## First artifacts

- `beehive-vaulta-promotion.patch` — EOS→Vaulta promotion, LF-clean, applies at `0cd72f0`.
- `docs/crypto-delta-spec.md` — the Zano port plan (copy from beehive-nature).

## License

Upstream trezor-firmware is **MIT**. Beehive's Zano additions: *decision pending* — AGPL-3.0 (matching beehive-nature) vs MIT; note the interaction with the MIT base and any upstream-PR intent.
