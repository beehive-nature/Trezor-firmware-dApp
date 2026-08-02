# T3W1 BUILD INVENTORY — measure three times, cut once

Repo: `C:\Users\travi\source\trezor-firmware` (WSL: `/mnt/c/Users/travi/source/trezor-firmware`), HEAD `e4bad3e6a5`. Suite build examined: `C:\Users\travi\AppData\Local\Programs\Trezor Suite\resources\app.asar`, 26.7.3.

**Read this first:** the tree does not currently produce a T3W1 image. It does not fail at runtime — it fails to link. Section 3, item 1. Nothing else in this document matters until that is fixed.

---

## 1. The matrix

`EVERYTHING` is not a per-coin knob. `core/SConscript.firmware:13` defines it as `BITCOIN_ONLY != '1'`. One switch carries Cardano, Ethereum, Monero, EOS, Solana, Stellar, Tezos, Tron, Zcash. There is no configuration that keeps EOS and drops Zcash.

| Chain key | Stock T3W1 | This fork | What is missing | Cost to add |
|---|---|---|---|---|
| `slip44:0` Bitcoin | Yes. `support.json` T3W1 `bitcoin:BTC` | Same | Nothing | — |
| `slip44:145` Bitcoin Cash | Yes. `support.json:~648` block, `bitcoin:BCH: 2.6.1`. Routes to `bitcoinlike.Bitcoinlike` (`bcash.json` decred:false, overwintered:false) | Same | Nothing | — |
| `slip44:133` Zcash | Yes, **transparent only**. `bitcoin:ZEC: 2.6.1` in the T3W1 supported block. v5 (ZIP-225/244) and v4 (ZIP-243, Sapling-era) both ship; v3 Overwinter is rejected by test. Decodes ZIP-316 Rev-0 `u1…` and pays the transparent receiver | Identical — zero fork commits touch `core/src/apps/zcash/` or `zcash_v4.py` | Shielded spend/receive (no Jubjub, no BLS12-381, no Groth16, no Pallas, no zip32 shielded — `grep -ril "zip32\|sapling\|orchard\|jubjub\|pallas" crypto/ core/embed/rust/src` returns only the BIP-39 wordlist). UA *encode* is dead code. ZIP-316 Rev-2 HRPs (`zu…`/`tu…`) unrecognised | Rev-2 HRP: ~10 lines, `unified_addresses.py:21-24,102-103` + the `address[0]=="u"` dispatch at `signer.py:133`. Shielded: see §2 |
| `eip155:1` Ethereum | Yes. `networks.json` chain_id 1, slip44 60, symbol ETH | Same | Nothing | — |
| `eip155:42161` Arbitrum | Yes, but **built-in slip44 is 9001, not 60** (`common/defs/ethereum/networks.json:71-77`, verified). Built-ins beat host definitions (`definitions.py:39-48`) | Same | Nothing in firmware. See open question Q3 | — |
| `eip155:7200` exSat | **Absent.** `networks.json` holds exactly 10 chain_ids: 1, 10, 56, 61, 137, 8453, 17000, 42161, 560048, 11155111. `grep -rn "exsat\|XSAT"` = 0 hits. Signs fine (`sign_tx.py` rejects only chain_id 0 and >MAX), keychain falls back to slip44 (60,1), but displays "Unknown network" / "UNKN" and **silently drops all token definitions** (`definitions.py:50-52`) | Same | Built-in network entry | Zero code if the host fetches the already-signed blob (verified live: `data.trezor.io/firmware/definitions/eth/chain-id/7200/network.dat`, 575 B, magic `trzd1`, decodes to chain_id 7200 / symbol "BTC" / slip44 60 / name "exSat", data version 1784116430 > MIN_DATA_VERSION 1780391762, so it passes the freshness gate). To bake in: 1 entry in `networks.json`, 1 line in `support.json`, `make templates` |
| `slip44:501` Solana | Yes. Three accepted path patterns (`m/44'/501'`, `…/0'`, `…/0'/0'`), all three gated identically on get_address, get_public_key and sign_tx — no publish-then-cannot-sign hole | Same | Nothing | — |
| `slip44:144` XRP | Yes, incl. AccountDelete (TransactionType 21, `serialize.py:53-63`, `layout.py:108-138`) | Same | Cosmetic: `sign_tx.py:51-52` says "10 to 10,000 drops"; `helpers.py:15` enforces `MAX_FEE = 1_000_000` | 1 line + `tests/device_tests/ripple/test_sign_tx.py:118` regex |
| `slip44:148` Stellar | Yes, incl. `StellarCreateAccountOp` (op 0, fully serialized and confirmed) | Same | CAP-33 sponsorship ops: `messages.proto:234-236` `reserved 226,227,228` with `// omitted:` comments. Not in `consts.py` op_codes → whole envelope unsignable, not just the op | Begin+End are the minimum sandwich; End's XDR body is literally `void`. ~150 lines across proto/consts/serialize/layout. But see §4 — there is a zero-code workaround |
| `slip44:194` Vaulta (EOS) | **Compiled and routed, capability withheld.** `SConscript.firmware:794,803-805` globs `apps/eos/*.py` under EVERYTHING with no model gate; `workflow_handlers.py:233-236` routes `EosGetPublicKey`/`EosSignTx`; `support.json:717` says `"misc:EOS": "not for T3W1 (#2793)"` | Announces it — `base.py:159-162` adds `Capability.EOS` for T3W1. **This change is uncommitted working-tree, and its comment cites `SConscript.unix` (the emulator file) for what ships on hardware** | **All 39 `eos__*` UI strings are empty for the Eckhart layout.** Verified: `en.json:583` `eos__buy_ram` = Bolt "Buy RAM", Eckhart ""; `:709` `eos__receiver` Eckhart ""; `:751` `eos__transfer` Eckhart "". T3W1 is Eckhart (`config.mk:3`). Baked into the blob at `translated_string.rs:32305-32311` as seven consecutive `""`. Also: `support.json` unchanged; Suite deleted EOS from connect entirely | Translations: pure data, 39 strings + `make templates`. `support.json`: 1 line move. Suite: not fixable from here — trezorctl only |
| `slip44:1018` Zano | **Not in `support.json` at all** | Address encode + CLSAG_GGX primitive + `ZanoGetAddress` — **emulator only.** `grep -i zano core/SConscript.firmware` returns nothing (re-verified). No `features.append('zano')` at `:932-943`; no `zano/*.c` in the crypto block at `:208-213`; no `apps/zano/*.py` freeze. Everything lives in `SConscript.unix` | Firmware build wiring (see §3.1), and signing (device-side tx construction + BGE one-out-of-many proof) | Wiring: 3 edits, ~1 hour. Signing: a protocol, not a patch. See §4 |

---

## 2. Zcash, answered plainly

**Transparent works, completely, today, with no fork changes.** v5 (ZIP-225/ZIP-244, NU5-era) and v4 (ZIP-243, Sapling-era) both sign; v3 is refused; the ZIP-244 hasher is implemented per-field with spec anchors. The published `t1VY72kp…` is a P2PKH transparent address (`zcash.json` address_type 7352 = 0x1CB8 = `t1`) and it is exactly what the device can produce and spend from. Operational note: the v4 path streams and re-txids previous transactions with pre-NU5 serialization, so it **cannot spend an output of a v5 transaction**. Since NU5 (May 2022) essentially every new Zcash tx is v5, so v4 is legacy-UTXO-only. Use the v5 lane.

**Shielded: two different answers, and conflating them is the trap.**

**Sapling is out of reach.** Not hard — absent. There is no Jubjub, no BLS12-381, no Groth16 anywhere in `crypto/` or `core/embed/rust/src/`. There is no upstream branch that ever implemented it: on `upstream/zcash-orchard`, `git grep -i` for `jubjub|bls12|groth16` returns zero hits including `Cargo.lock`. The `ZcashSignatureType` enum was born with the Sapling variants commented out. What exists is *structural* Sapling — `SaplingHasher` (an empty-bundle hasher returning `blake2b(personal=b"ZTxIdSaplingHash")` over no data), the `nSpendsSapling`/`nOutputsSapling` counts, and 43-byte Sapling receiver parsing in the UA decoder. Those are load-bearing for a correct v5 txid. They are not a spend path.

**Orchard is hard-but-possible, and the number that settles it is not a proving time.** The number is that **the device never proves.** `upstream/zcash-orchard` (tip `d562254c21`, 2022-12-27, Tomas Krnak, ZF-grant-funded, PR #2472 — still open, still draft, maintainer Hannsek on 2025-10-23: not on the priority list) splits the work: the device holds `ask`, derives all action-shielding randomness deterministically from a seed (`BundleShieldingRng`, blake2b personalizations `ActionShieldSeed`/`Inps_Permutation`/`Outs_Permutation`), computes the nullifier, `rk`, `cmx`, `cv_net` and the note encryption, and signs the ZIP-244 sighash with a randomized `rsk`. The host regenerates the same randomness and builds the halo2 proof. This is cryptographically sound: `zcash/orchard`'s `src/circuit.rs` witnesses `ak` (the *validating* key), never `ask`. It demonstrably worked — five Zcash testnet txids in `tests/device_tests/zcash/test_sign_shielded_tx.py` are marked accepted by the network, four with real Orchard spend-auth signatures.

**On-device proving is genuinely impossible on this silicon, and here is the number.** T3W1 is STM32U5G9. The production build takes `secmon_layout`, so the app heap is `AUX1_RAM` in `memory_secmon.ld:64` = `0xc8000` = **800 KiB**. A Sapling spend circuit is ~10⁵ constraints; the QAP needs FFTs over a 2¹⁷-element BLS12-381 scalar domain = 131,072 × 32 B = **4 MiB for one polynomial**, with several live simultaneously. That is 15×+ over the entire heap before a single curve operation. There is no escape hatch: `HAL_XSPI_MODULE_ENABLED` is commented out in `stm32u5xx_hal_conf.h:97` and there is no PSRAM/OCTOSPI driver anywhere under `core/embed` — no memory-mapped external RAM exists. (The often-quoted `sapling-spend.params` = 47,958,396 B vs a 3.42 MB firmware partition proves *impracticality* of key residency, not impossibility — a streaming design defeats that argument. The working-set number is the one that closes it.)

**So: shielded Zcash is a porting problem, not a cryptography problem — and it is not going in this firmware.** The honest cost:

- `layout.py` on the branch imports `trezor.ui.components.common.confirm`, `trezor.ui.components.tt.*`, `trezor.ui.layouts.tt` — the retired T2T1 Python UI framework. HEAD ships `layouts/{bolt,caesar,delizia,eckhart}`. Every confirmation screen is a rewrite.
- The wire API dropped `ctx`; the branch's `keychain.for_coin(cls, ctx, coin)` no longer matches.
- ~2,850 lines of Rust to re-add (`zcash_primitives/pallas`, `poseidon` incl. a 1,350-line constant table) plus `modtrezorzcashprimitives.c`, plus `messages-zcash.proto`.
- 11,458 commits of rebase (`git rev-list --left-right --count upstream/main...upstream/zcash-orchard` = 1 / 11458).
- The branch is itself incomplete: no simultaneous transparent+Orchard spend, no replacement transactions, `root_fingerprint` NotImplementedError.
- **The privacy price nobody states:** because `ak` and `nk` are circuit witnesses, the host cannot prove without the Orchard **Full Viewing Key**. That is why the branch ships `ZcashGetViewingKey` with `full` defaulting to true. The FVK leaves the chip permanently and hands the host complete visibility of the account's Orchard balance and history. "Device holds keys" is true only of `ask`.
- Protobuf is fine (proto2 `required` still used at HEAD), and the branch is self-contained against today's main (`zcash-v5` and `zcash-unified-addresses` already landed).

And the registry consequence: Orchard needs a unified address. The published `t1VY72kp…` is not reachable by any of it. Shielded Zcash means publishing a new `u1…` receiver, which the firmware also cannot currently generate (`unified_addresses.encode()` is dead code, and even wired up it could only echo host-supplied receiver bytes since no shielded key material exists).

**Correct marketing string:** *"Zcash (transparent). Sends and receives t1/t3. Accepts a ZIP-316 Revision-0 unified address as a destination and pays its transparent receiver. Cannot produce, receive to, or spend from any shielded address."* Do not write "unified address support" without the qualifier.

---

## 3. What goes in the one firmware

Ordered by value per unit of effort. **[BLOCKER] / [FLAG] / [DATA] / [CODE]** marks the kind of work.

### 3.1 [BLOCKER] [CODE] Fix the Zano link failure — 3 edits, nothing builds without it

`core/embed/upymod/rustmods.c:43-45` (re-verified this session):

```c
#ifdef USE_MONERO
MP_REGISTER_MODULE(MP_QSTR_trezorzano, mp_module_trezorzano);
#endif
```

`SConscript.firmware:138` emits `('USE_MONERO', '1' if EVERYTHING else '0')` — so `-DUSE_MONERO=0` in bitcoin-only builds, and `#ifdef` is satisfied by *either* value. The rest of the tree correctly uses `#if` (`crypto/monero/monero.h:8`, `crypto/options.h:91`). The registration therefore fires in **every** firmware build. The QSTR collector preprocesses `rustmods.c` and greps `^MP_REGISTER_MODULE`, so `moduledefs.h` gets an unconditional `extern const struct _mp_obj_module_t mp_module_trezorzano;` plus a table entry that takes the symbol's address — a hard link dependency. The symbol is defined only under `#[cfg(all(feature = "zano", feature = "micropython"))]`. `SConscript.firmware:932-943` never appends `'zano'` (re-verified). **Every T3W1 image, including bitcoin-only, fails to link.** The reason it has not been observed is that `core/build/` contains only `unix/` — this tree has never been built for hardware. The fork's own commit `15cdad2b71` records the hazard and says the fix "is not done."

Three edits, all in `core/SConscript.firmware`:

1. `features.append('zano')` alongside `universal_fw` at :937.
2. Add `vendor/trezor-crypto/zano/{clsag_ggx,zano_address,zano_generators}.c` to the `SOURCE_MOD_CRYPTO` EVERYTHING block at :208-213, after `monero/xmr.c` (`zano_hp()` calls `xmr_hash_to_ec`).
3. Add `Glob(SOURCE_PY_DIR + 'apps/zano/*.py')` to the EVERYTHING block at :794/:810-812, after monero. `workflow_handlers.py:175-176` already routes `ZanoGetAddress` → `"apps.zano.get_address"`, and `find_registered_handler` catches only `ValueError`, so a missing frozen module raises an uncaught `ImportError`.

Doing only #1 moves the failure from `mp_module_trezorzano` to `zano_generate_clsag_ggx`. Do all three.

Separately, change `rustmods.c:43` from `#ifdef` to `#if` (and `core/embed/rust/librust.h:16`, harmless but same defect) so a future bitcoin-only build does not re-break. `SConscript.firmware:731,848`'s `trezor/enums/Zano*.py` and `Zcash*.py` globs match zero files — vestigial, leave them.

**Unverified and worth knowing before you trust the build:** the Zano Rust/C has never been compiled for thumb or run on ARM. `zano_micropython.rs` allocates a 1,120-byte stack buffer for signature bytes and `zano.rs:171,201-202` holds three more `MAX_RING_SIZE=16` arrays. None of it is reachable from `ZanoGetAddress` (`get_address.py:35` calls only `address_from_keys`), so it should not block the address path, but the compile is untested.

### 3.2 [DATA] Fill in 39 Eckhart EOS strings — Vaulta is unusable without it

Verified this session: `en.json:583,709,751` show Bolt populated, Caesar/Delizia/**Eckhart** empty. `translated_string.rs` is a positional concat table selected by `cfg`; at ordinals 232-238 the Bolt table holds "Action Name"…"Code" (lines 1905-1911) and the Eckhart table holds seven `""` (32305-32311). T3W1 is Eckhart.

Consequence: `actions/layout.py:53-61` passes `TR.eos__buy_ram` as the screen *title* and `TR.eos__payer`/`TR.eos__receiver` as *property labels*. `layout.py:18` passes `TR.eos__about_to_sign_template` as the confirm description. On T3W1 all resolve to `""`. The signature is cryptographically correct; the user sees an untitled screen with bare account names and amounts and no labels. That is the gap between "reachable" and "signable in good conscience."

Pure data work. 39 keys in `core/translations/en.json` + `make templates`. Highest value-per-effort item in the whole list after the blocker.

### 3.3 [DATA] Commit the capability announcement, and fix its comment

`base.py:159-162` is uncommitted working-tree (verified: `git status --porcelain -- core/src/apps/base.py` → ` M`). Commit it. Its comment cites `SConscript.unix:820-826` and `:837` — the **emulator** build file, and both citations are additionally stale in line number (the Zano block added at `:837-841` shifted the NEM gate by five lines; `:820-822` is inside the Cardano block). The hardware truth is `SConscript.firmware:141/803-805`, plus `SConscript.kernel:114` and `SConscript.secmon:106` (commit `c4521b8177` correctly touched all four), plus `core/embed/models/T3W1/model.toml:32` for the xtask/cargo path. Rewrite the comment to cite those.

**Set expectations correctly:** announcing `Capability_EOS` buys you nothing in Suite. Suite 26.7.3 dropped EOS as a coin entirely — `eosGetPublicKey`/`eosSignTransaction` are gone (upstream commit `16da7214cc`, 2026-01-06, "feat(connect): remove EOS support"), and there is no `"eos"` string anywhere in `app.asar`. The protobuf schema survives (`EosGetPublicKeySchema` etc. at `app.asar@55695917`, registry at `@56660414`) and `Capability_EOS=6` decodes cleanly, so announcing it is harmless — it just will not light up an account. The capability matters for trezorlib, where `eos.py:321,331` already carry `@workflow(capability=messages.Capability.EOS)`. That gate is currently inert (the decorator stores `self.capabilities` at `tools.py:389` and never reads it) but is one upstream line from becoming enforced. Announce it.

### 3.4 [DATA] Move `misc:EOS` in `support.json`

`common/defs/support.json:717` still reads `"misc:EOS": "not for T3W1 (#2793)"`. Move it into the T3W1 supported dict. This file drives Suite/Connect metadata generation via `common/tools/coin_info.py` and `support.py` — it does not gate the build (trezorlib has zero references to it; `grep -rn "support.json" python/` = 0 hits), so this is cosmetic today and correct tomorrow. One line. (`:839` and `:961` carry the same string but are the D001/D002 dev-model blocks, not T3W1.)

### 3.5 [CODE] Bake in exSat, or decide not to

Verified this session: `networks.json` holds 10 chain_ids and 7200 is not one of them. Two options, both valid:

- **Zero firmware work:** have the host pass `encoded_network` from `data.trezor.io/firmware/definitions/eth/chain-id/7200/network.dat`. Confirmed to exist and to pass this fork's freshness gate. `definitions.py:53-54` raises `DataError("Network definition mismatch")` on a chain_id disagreement, so a wrong blob fails closed. trezorlib does this natively (`definitions.py:38,117`).
- **Bake it in:** add the entry to `common/defs/ethereum/networks.json`, add `"eth:XSAT:7200"` under the T3W1 block of `support.json`, `make templates`. `networks.py.mako:64` iterates `supported_on(model, eth)` so it lands in the T3W1 branch.

Bake it in if you expect to sign exSat from anything other than trezorlib. Without a definition the device shows "UNKN" on an unknown network *and* discards every token definition (`definitions.py:50-52`, `# ignore tokens if we don't have a network`), forcing `require_confirm_unknown_token` on every ERC-20. That is blind signing.

### 3.6 [CODE] The XRP fee string — 1 line

`sign_tx.py:52` says "10 to 10,000 drops"; the enforced ceiling is 1,000,000. This sits directly on the AccountDelete recovery path, which needs a 200,000-drop fee — 20× the number the error names. Fix the string to "10 drops to 1 XRP" **and** the `match=` pattern in `tests/device_tests/ripple/test_sign_tx.py:118` in the same change or `test_ripple_sign_invalid_fee` breaks. Inherited verbatim from upstream; not a fork regression.

### 3.7 [CODE] Host: Zano CLI stub + version marker

There is no `zano.py` in `src/trezorlib/` or `src/trezorlib/cli/`. The wire types are registered (`messages.py:830-831,9978-10008`; auto-registered via `mapping.py:108`), so the direct call works today:

```python
session.call(messages.ZanoGetAddress(address_n=tools.parse_path("m/44h/1018h/0h/0/0"),
                                     show_display=True),
             expect=messages.ZanoAddress).address
```

Use `Session.call()`, **not** `call_raw()` — `call_raw` does no processing, so with `show_display=True` it returns a `ButtonRequest` and you would hand-drive the button protocol. `call()` runs the interactive loop (`client.py:488-511`).

A ~20-line `cli/zano.py` mirroring `cli/eos.py` is worth it. **More urgent:** `pyproject.toml` declares `name="trezor", version="0.20.2"` — the same distribution name and a real published upstream version. Any non-editable install, lockfile refresh, fresh venv, or transitive `trezor` dependency silently swaps in upstream 0.20.2 and the code above dies with `AttributeError: module 'trezorlib.messages' has no attribute 'ZanoGetAddress'`. Install editable from the fork and set a local version marker (`0.20.2+zano1`) so the divergence is visible to pip.

### 3.8 [CODE] Optional: ZIP-316 Revision-2 HRPs

`PREFIXES` is hardcoded to `{"Zcash": "u", "Zcash Testnet": "utest"}` at `unified_addresses.py:21-24`, enforced at `:102-103`. Worse, the signer dispatches on `txo.address[0] == "u"` (`signer.py:133`), so a Rev-2 `tu1…` — the form that *would* carry a payable transparent receiver — never reaches `decode()` at all, falls through to base58, and dies as `DataError("Invalid address")`. Ten lines. **Q5 below: are wallets emitting Rev-2 HRPs yet?** I confirmed the spec, not deployment.

---

## 4. What CANNOT go in — and the fallback for each

**Zcash shielded (Sapling).** Absent, not withheld. → *Fallback:* transparent t1, which is what the registry publishes. No loss relative to the current registry state.

**Zcash shielded (Orchard).** Possible but a multi-week port of a 3.5-year-dead branch across 11,458 commits, with a full UI rewrite, plus permanent FVK export to the host, plus a new unified address to publish. → *Fallback:* transparent t1. If shielded is ever wanted, the gap list is a UI port and a Rust rebase — **not** cryptography, and **not** on-device proving.

**On-device zk proving (either system).** 800 KiB heap vs ~4 MiB per FFT polynomial with several live. No external RAM exists on the board. → *Fallback:* host proving. This is not a compromise; it is the architecture the ZF grantee designed and it produced network-accepted transactions.

**Zano signing.** Needs the device to construct the entire transaction (the last input's `f'` is a residual over output masks, so the device must own `r`), plus a BGE one-out-of-many proof, across 10-12 round trips / 8 message pairs. `docs/zano-signing-design.md` is the fork's own analysis and its conclusion is that the device must be the transaction constructor, not a co-signer. The only occurrence of the string `ZanoSignTx` in the tree is `:118` of that design note. → *Fallback, and this matters:* Zano funds are **not** cryptographically stranded. The keys are a deterministic function of the recovery seed — `apps/zano/__init__.py:3-5` sets ed25519 / SLIP44 1018 / `m/44'/1018'/account'`, `bip32.c:51-52` is standard SLIP-0010, `get_address.py:33` → `monero.generate_monero_keys` → spend = IL mod ℓ, view = keccak(spend) mod ℓ, which is exactly Zano's own `dependent_key` (`src/crypto/crypto.cpp:119-124`). Twenty lines of offline Python reproduce both secrets. Watch-only needs no export message: Zano's tracking seed is `address:view_secret_hex:timestamp` (`account.cpp:124-129,310-315`) — paste it into stock Zano. Spending works too: the wallet keys file stores `account_keys{address, spend_secret, view_secret}`, not the mnemonic, and load-time validation is only `verify_keys` on both pairs (`wallet2.cpp:3230-3236`) with `m_keys_seed_binary` unchecked and legitimately empty after a tracking-seed restore. What is genuinely closed is the *mnemonic* route: Zano's `keys_from_default` uses `sc_reduce64(seed32 || cn_fast_hash(seed32))`, not `sc_reduce32(seed32)`, so no word encoding lines up. **So the deliverable is a ~100-line offline derive-and-write-keys-file utility, kept and specified alongside the seed.** This is exactly how a Trezor Monero account recovers — via `--generate-from-keys`, not a Monero mnemonic. Write it before you publish the `Zx…` address as fundable. *(Note: `BEEHIVE.md` describes the Zano app as "specced, unstarted." Reconcile that with reality.)*

**Stellar CAP-33 sponsored reserves.** Ops 226/227/228 are `reserved` with `// omitted:` comments, absent from `consts.py` op_codes, so `get_op_code` raises and the entire envelope becomes unsignable — not just that op. → *Fallback, zero firmware work:* pre-authorized transaction signers. `SetOptions` (op 5) with `StellarSignerType.PRE_AUTH = 1` is fully supported (`serialize.py:194-204`, `layout.py:373-375`, rendered as `TR.stellar__preauth_transaction`). Tx1 — signed by the device, high threshold — installs the hash of Tx2 as a weight-N signer; Tx2, the Begin/…/End sandwich, is built entirely off-device and authorized on the sponsored side with no device involvement. The pre-auth signer is single-use, bound to one tx hash, and auto-removes when applied — a materially better security posture than a standing ed25519 co-signer, which at medium threshold would also inherit Payment authority. **Unverified: I did not run this end-to-end on testnet.** The mechanism is confirmed on both sides.

**Vaulta resource management via trezorctl.** `eos.py:263-291`'s `if action["account"] == "eosio":` branch is a 12-name if/elif chain with **no else**, so the outer `else: tx_action.unknown = parse_unknown(...)` is unreachable for eosio actions. An unlisted eosio action emits an `EosTxActionAck` with `common` and no payload; the device then hard-rejects it (`actions/__init__.py:123-146` → `:17-18` `ValueError("Invalid action")`). That kills `powerup` and the whole REX set (`rentcpu`, `rentnet`, `deposit`, `buyrex`, `sellrex`) plus `ramtransfer` — the actual EOS/Vaulta resource model since 2021. → *Fallback:* plain `eosio.token::transfer` of the A token works fine (`parse_asset` handles the 1-char "A" symbol). Manage resources from a separate hot account, or patch both sides (trezorlib action table + firmware `_check_action` allowlist + eckhart strings). Custom non-eosio contract actions need pre-serialized hex from an external `abi_json_to_bin`.

**EOS in Trezor Suite.** Deleted upstream, coin table and methods both. → *Fallback:* trezorctl. `cli/trezorctl.py:436` registers it unconditionally. Note trezorctl is an **offline signer only** — `cli/eos.py:58-66` wants a hand-built wrapper JSON with `chain_id` + `transaction`, requiring expiration / ref_block_num / ref_block_prefix / max_net_usage_words / max_cpu_usage_ms / delay_sec. No chain-head fetch, no broadcast. cleos or a Vaulta node client is mandatory. Also note `helpers.py:58` emits only the legacy `EOS`-prefixed key format (trezorlib accepts both `EOS` and `PUB_K1_` host-side) — see Q6.

**The 1-hour watchdog.** `vendor_unsafe.json` sets `limit_runtime: true`, clearing `VTRUST_ALLOW_UNLIMITED_RUN` (0x400, `image.h:85`). Confirmed on the compiled artifact, not just the JSON: `vendorheader_unsafe_signed_prod.bin` byte 16 reads `8e 00` = 0x008E (bit clear); `vendorheader_trezor_signed_prod.bin` reads `7f 05` = 0x057F (bit set). `bootloader/main.c:535-541` then arms `iwdg_start(60*60)`, which with prescaler 1024 and LSI 250 Hz is a reload of 877 → real period **3596.3 s = 59 min 56 s**. There is no escape: (a) `SConscript.firmware:965-978` forces `vendor = "unsafe_signed_prod"` for any non-PRODUCTION build, and every prod-signed header with `limit_runtime:false` carries SatoshiLabs vendor pubkeys; (b) there is no `iwdg_reload` anywhere in the tree — `sec/iwdg` exposes only `iwdg_start`; (c) the IWDG is marked secure+privileged in `tz_init.c:261-263` and the T3W1 kernel runs non-secure, so only secmon can touch the registers, and secmon needs 2-of-3 `MODEL_SECMON_KEYS` signatures you do not have; (d) `option_bytes.c:78-84` pins `IWDG_STOP`/`IWDG_STDBY`, so the counter runs through sleep and standby — it is wall clock, not active use. → *Fallback:* design for it. Every host flow must be resumable across an unannounced full reset, and must not hold device state (passphrase session, multi-step signing) longer than ~55 minutes. Also expect a red background, a required user click, and a 1-second delay on every single boot.

**Device authenticity attestation.** `vendor_unsafe.json` sets `allow_run_with_secret: false`, so `bootloader/main.c:488-496` clears `secret_run_access` — the firmware never gets the Optiga/Tropic pairing secret. Compounding it, unlocking the bootloader erases secret slot 0 (`stm32u5/secret.c:533-541` walks slots and erases the non-public ones; T3W1 declares 3 slots with only slot 0 private). → *Fallback: none. Accept it.* Suite's device-authenticity failure screen (`qye`, ctaSection `Kye`) has a support link and **no dismiss button**. See Q4 — this is the sharpest unresolved risk in the whole plan.

---

## 5. The $10 onboarding, itemised

**It is not $10. It is between $2.03 and $4.41, and roughly $1.33 of that is a refundable deposit rather than a cost.** Prices as gathered (BTC $62,546, ETH-denominated fees at then-current gas, ZEC $462.69, XRP $1.08, XLM $0.1739, SOL $73.13, A $0.0637). Q7 flags the price vector.

### Activation, per chain

| Chain | Activation required | Cost | Recoverable? | Who acts |
|---|---|---|---|---|
| `slip44:144` XRP | 1 XRP base reserve. Verified live off-chain-state, not docs: FeeSettings object at validated ledger 106,024,792 gives `ReserveBaseDrops = 1000000`, `ReserveIncrementDrops = 200000`. The 10→1 XRP change is pinned to ledger **92,508,417, closed 2024-12-02 22:45:51 UTC** (ledger 92,508,416 still reads 10000000) | **$1.08** | Mostly. `AccountDelete` returns the balance minus a burned 0.2 XRP special fee. **The device can sign it** — `MAX_FEE = 1_000_000` drops covers the 200,000-drop cost | Sponsor sends a plain Payment. Destination signs nothing |
| `slip44:148` XLM | 1 XLM = 2 × 0.5 base reserve. Verified live: Horizon ledger 63,767,521, `base_reserve_in_stroops = 5000000` | **$0.174** | Via account merge | Sponsor signs `CreateAccount`. Destination signs nothing. **A plain Payment fails with `PAYMENT_NO_DESTINATION`** — different op type, not just a bigger amount |
| `slip44:501` SOL | 890,880 lamports rent exemption for a 0-data System account. Verified live: `getMinimumBalanceForRentExemption(0)` = 890880 | **$0.065** + 5,000 lamport fee ($0.00037) | **Fully.** Rent-exempt accounts never have rent collected; draining to zero leaves `RentState::Uninitialized`, which `transition_allowed()` permits. The only burn is the 5,000-lamport fee | Sponsor sends one transfer. **Hard cliff:** 890,879 lamports fails the *entire* transaction with `InsufficientFundsForRent`. Query the RPC, don't hardcode |
| `slip44:194` Vaulta | **Already done — $0.** `remington.gm` exists on mainnet: created 2022-08-14T05:47:34.500, 7.2933 EOS liquid, 370,553 bytes RAM, last activity 2026-08-01 | **$0** | n/a | Nobody. *If it did not exist:* 2,996 bytes RAM (`eosio_contract.cpp:117-120`: 2048 overhead + 2 permission objects + both authorities' billable size) plus a `user_resources` row, ~$0.0001, and **only `gm` or `eosio` could create it** — `eosio.system.cpp:633` `check( creator == suffix, "only gm may create remington.gm" )`. The suffix gate lives inside `if( has_dot )`, so it is a consequence of choosing a dotted name, not a Vaulta property |
| BTC, BCH, ZEC-t, ETH, ARB, exSat, Zano | **None.** Address is pure key derivation | $0 | — | — |

**Hard protocol floor: $1.33 in locked/deposited value, of which ~$1.13 is recoverable.** The rest is discretionary delivery.

### Delivery fees, if you choose to push a dust payment to every chain

BTC 140 vB × 5–20 sat/vB = **$0.44–1.75** · ETH **$0.20–1.18** · ZEC ZIP-317 floor 10,000 zat = **$0.046** · Arbitrum **~$0.02** · BCH **~$0.001–0.01** · Zano flat 0.01 ZANO, 100% burned · SOL 5,000 lamports = **$0.0004** · XRP 10 drops = **$0.00001** · XLM 100 stroops = **$0.0000018** · Vaulta ~$0.

**BTC + ETH are 90–97% of the fee total.** Everything else is noise.

**Grand total: $2.03 – $4.41.**

### What a sponsor can batch

Nothing is atomic across chains — this is 10 separately signed, separately broadcast transactions. But **every one of them is sponsor-only.** The device signs nothing, the user does nothing, on any chain. That includes Stellar (`CreateAccount` is signed by the funder; `operations/layout.py:111` fires only when the *device* signs one) and includes Vaulta (already created). There is no privileged actor requirement anywhere in the set.

Two things the sponsor cannot do:
- **exSat** cannot be funded by sending to the registry's `bc1q…` address, and cannot be funded with ETH. Gas on chain 7200 is 18-decimal *bridged* BTC (nativeCurrency decimals 18 per ethereum-lists/chains). It requires exSat's bridge. A user who reads "same EVM key" and sends BTC on-chain to the 0x address, or to bc1q expecting it on 7200, loses funds.
- **Zano** is receivable but not spendable by the device. Do not fund it beyond a test amount until the offline recovery utility from §4 exists and has been round-tripped.

### Silent versus loud failures

**Loud — but none of them are atomic except Vaulta.** Three of the four leave a permanent failed-transaction record and burn the fee:

- **XRP:** `tec`-class codes are *applied to a ledger to apply the transaction cost*. Fee destroyed, sequence number consumed. Not an atomic rejection.
- **Stellar:** `op_no_destination` is an apply-time operation failure. Sequence incremented, fee collected. Only submission-time invalidity escapes free.
- **Solana:** `InsufficientFundsForRent { account_index }` is post-execution. `verify_changes()` compares pre/post rent states after `process_message`; a function taking a `post_rent_state` cannot be a pre-commit check. Fee charged, transaction in the block, only `RollbackAccounts` written back. Index 0 = the fee payer; index 1 = the recipient — the user-visible string names index 1.
- **Vaulta:** the only genuine atomic reject. `check( is_account( to ), "to account does not exist" )` — present in *both* `eosio.token` and `core.vaulta`, so the A token is protected on both paths post-rebrand.

**Genuinely silent, in order of how much they will cost you:**

1. **Paying a `u1…` unified address.** The device extracts and pays the transparent receiver; the recipient's shielded balance never moves and nothing warns. If you demo this, the caption is "pays the transparent receiver inside a unified address," not "supports unified addresses." (Note the accepted set is narrow both ways: shielded-only dies at `signer.py:143`; transparent-only dies at `unified_addresses.py:145`. Rev-0 requires at least one shielded receiver, so this is conformant, not a bug.)
2. **exSat native-layer deposits.** exSat is two-layer; per exSat's own bridge docs the EVM address goes in the **memo** of a Vaulta-side transfer. The registry publishing only a 0x under `eip155:7200` gives a payer on the native layer no memo hint. **Q8: the docs specify no error handling for a missing memo.**
3. **Below-dust BTC/BCH/ZEC.** `grep -i dust core/src/apps` returns zero matches. `dust_limit` is coin-definition registry metadata only — `coininfo.py`, the generated set of fields actually compiled into flash, has `maxfee_kb` and no `dust_limit`. The device signs a 500-sat output cleanly; you learn at broadcast. (And even that is relay policy, not consensus — `policy.cpp` is explicitly "intended to be customised by the end user." A below-dust output is minable by direct submission.) Solana is the exception and does better: `transaction/__init__.py:250-258` computes `calculate_rent()` and shows it as a distinct `rent` component in the fee before you sign.
4. **Suite's MCP `trezor_get_public_key`.** Unconditionally sends `getPublicKey`, and the class re-resolves coinInfo from the path's SLIP-44 index when the coin name misses. So `coin:"sol"` + a 145 path yields coin_name "Bcash", and every ed25519 chain gets a Bitcoin-magic xpub over the wrong curve. Affects 4 of 11 (SOL 501, XLM 148, Cardano 1815, Zano 1018); the secp256k1 chains — ETH, ARB, exSat, XRP, Vaulta — get *correct key material* with only wrong version bytes. Don't use the MCP surface for key export.

---

## 6. The order of work

The ordering constraint the founder named — Vaulta is a capability flag, Zano signing is a protocol — is right but incomplete. The real gating item is neither: it is that **the tree does not link**, and behind that, that **flashing this firmware permanently and irreversibly downgrades the device.** Do the destructive step last and once.

### Phase 0 — before touching the device (hours)

1. Apply §3.1. Build the T3W1 firmware image in WSL. This is the first time this tree has ever been built for hardware (`core/build/` contains only `unix/`); expect to find things.
2. Apply §3.2 and §3.3 and rebuild. Run the T3W1 **emulator** and drive an EOS `transfer` end to end — confirm the screens have titles and labels now. Drive `ZanoGetAddress` and confirm it still returns the `Zx…` you published.
3. Apply §3.6 and §3.4 (one line each) while you are in there.
4. **Non-destructive device check, and do this before anything else:** put the Safe 7 in bootloader mode and read `Features.bootloader_locked` (reported by `bootloader/protob/protob.c:99-102`). This answers Q1 and determines whether Phase 3 is even necessary.
5. Write the Zano offline recovery utility (§4) and round-trip it: derive from the seed, write a Zano keys file, load it in stock Zano, confirm the address matches `Zx…`. **Do this before any Zano funds exist.** It is 100 lines and it converts "receive-only" from a hazard into a documented custody procedure.

### Phase 1 — signing on the emulator, host recipes proven (days)

6. Prove every host path against the emulator: `trezorctl eos get-public-key` and a hand-built `sign-transaction` JSON; the direct `session.call(ZanoGetAddress(...))` from §3.7; Suite for the eight chains it supports. Install trezorlib editable from the fork with a `+zano1` version marker first.
7. Decide exSat (§3.5). If you bake it in, do it now — it costs one `make templates`.
8. Resolve Q2 and Q3 (below) against the emulator, because they are questions about *published registry entries* and are cheap to answer before the device is irreversible.

### Phase 2 — signing (minutes, once Phase 0 step 4 answers)

9. Sign the image. `models.py:507` maps `Model.T3W1` to `TREZOR_CORE_DEV` and the dev private keys are published in-repo (`testing/common.py:13`, `PRIVATE_KEYS_DEV`). trezorctl accepts a dev-key-signed image with a warning and **no flags** — `firmware.py:159-166` catches `FirmwareIntegrityError`, retries `verify(dev_keys=True)`, prints "WARNING: Firmware for development kit only," and returns. It does not `sys.exit`. Only genuinely unsigned images need `--skip-check` or `--raw`.

### Phase 3 — the irreversible step (do it once, deliberately)

10. `trezorctl device unlock-bootloader`. Its own docstring says "Irreversible." It wipes storage, regenerates the BHK, and erases secret slot 0 — the Optiga/Tropic pairing secret. **Device authenticity attestation is dead from this moment forward and cannot be restored.** Have the seed backed up and verified before you run it.

    *Why this is required:* the rejection is at **install**, not boot. `wf_firmware_update.c:378-385` — if the bootloader is locked and the vendor header lacks `VTRUST_SECRET_ALLOW`, it returns `Failure_ProcessError "Install restricted"` to the host and never writes flash. Signature is not the obstacle; `vendorheader_unsafe_signed_prod.bin` ships in-tree with real production signatures. Only the lock bit stands in the way.

11. Flash. Either host works — Suite 26.7.3 has a first-class **Settings → Install custom firmware** route (`firmware-custom`, a `.bin` dropzone, and its validator `cae()` checks only the 4-byte magic and model compatibility, with **no signature verification at all**, and whitelists T3W1), or trezorctl per step 9.
12. Accept the permanent conditions: red background, required click and 1-second delay on every boot, hard reset at 59m56s of wall clock.

### Phase 4 — make Suite usable

13. **Turn the firmware revision check OFF in Settings. Do not just dismiss the interstitial.** Two reasons. (a) Dismissal is not persisted — `dismissedSecurityChecks` is written by the reducer and read by the selector but never stored to IndexedDB, while the *failure* IS persisted with the remembered device, so the interstitial returns on every launch. (b) Dismissal does not restore function: a second, dismissal-independent selector (`kJ`) recomputes hardModal severity with no dismissal lookup and drives `isReceiveDisabled`, which disables `@wallet/receive/reveal-address-button`, used-address rows, and `@wallets/details/show-xpub-button`. You would have a Suite shell that cannot reveal a single address — on a device whose entire purpose is an 11-chain address registry.
14. No version value helps. A version bump does not evade the check; it makes things worse asymmetrically — an unrecognised version sets the strong firmware-**hash** check to `{type:"skipped"}` while the revision check still hard-modals.

### Phase 5 — living with it

15. Vaulta and Zano run through trezorctl/trezorlib, permanently. Suite will never show an EOS account.
16. Every host flow resumable across an unannounced reboot; no device state held past ~55 minutes.
17. Optional, low priority: §3.8 (Rev-2 HRPs), a `cli/zano.py` stub, Stellar pre-auth sponsorship if you ever need it.

### Not scheduled

Orchard shielded Zcash. Zano signing. Both are projects, not tasks, and neither is needed for anything the registry currently publishes.

---

## Open questions — genuinely unknown, stated as questions

**Q1. Is the Safe 7 in hand bootloader-locked?** `secret_bootloader_locked()` on U5 is `secret_keys_present_any()`, true only after factory provisioning wrote slot 0. Overwhelmingly likely for a retail unit, not assertable from the repo. **Answerable non-destructively in five minutes by reading `Features.bootloader_locked` in bootloader mode. Do it first.** If it is somehow unlocked, Phase 3 disappears and the device keeps its attestation.

**Q2. Which of the three Solana derivation patterns produced `FRniwme…`?** Not determinable from the repo — it depends on how the address was generated. All three sign, so there is no publish-then-cannot-spend hole, but pattern 1 (`m/44'/501'`) is awkward: Suite has no account type that discovers it, so it would be device-controlled but invisible in Suite, reachable only via trezorctl with an explicit `-n`. The de-facto canonical is `m/44'/501'/0'/0'` (trezorlib's own `DEFAULT_PATH`, Suite's primary `bip43Path`, Phantom/Backpack). Check before treating the registry entry as final.

**Q3. Was the published Arbitrum address derived at `m/44'/60'` or `m/44'/9001'`?** Verified this session: `networks.json:71-77` assigns chain 42161 slip44 **9001** (SLIP-0044 registers 9001 as ARB1), and built-ins take precedence over the signed definition, which says 60. The device therefore reports 9001 for Arbitrum by default. Byte-identical addresses across `eip155:1` and `eip155:42161` hold only if the host explicitly requests `m/44'/60'` for Arbitrum — permitted (`keychain.py:116-118`) but not the built-in default. If any tool derived at 9001, the published address is not the one the device shows for its Arbitrum account. Quieter and worse than a shared address.

**Q4. After bootloader unlock erases the pairing secret, does Suite's device-authenticity failure have any escape?** The revision check has a settings toggle. The authenticity failure screen's CTA section is a support link with no dismiss button, and the entropy and device-ID checks are likewise non-dismissible (their branches use support-link-only CTAs and short-circuit before the dismissal lookup). If authenticity is also a hardModal feeding `isReceiveDisabled`, Suite may be permanently receive-disabled for this device regardless of Phase 4. **This is the sharpest unresolved risk and it is only fully answerable after the irreversible step.** If it lands badly, the fallback is trezorctl/Connect for everything — which works, but is not the workflow anyone wants.

**Q5. Have Zcash wallets begun emitting ZIP-316 Revision-2 HRPs (`zu…`/`tu…`) by default?** Spec confirmed; deployment not. Determines whether §3.8 is forward-compatibility hygiene or a live breakage.

**Q6. Does Vaulta mainnet still accept legacy `EOS`-prefixed K1 keys post-rebrand?** `helpers.py:58` emits only that form; trezorlib accepts both `EOS` and `PUB_K1_` host-side. This is the single highest-value item to verify before flashing, because it is the difference between the Vaulta lane working and the Vaulta lane being the reason you reflash.

**Q7. Are the price inputs current?** BTC $62,546 alongside ZEC $462.69 is an unusual pairing. It does not change the conclusion — the $2–4 total is an internal-consistency result, and no plausible price vector reaches $10 — but re-price before you size a sponsor float across many users.

**Q8. Does exSat's native→EVM bridge recover a memo-less deposit?** The docs specify the memo as routing data and say nothing about error handling. If the answer is no, this is the one unrecoverable silent failure in the whole registry and the `eip155:7200` entry needs a published warning.

**Q9. Have the upstream Rust dependencies for the Orchard branch landed?** PR #2472's body lists open blockers in `zcash/orchard` (#344, #346, #348, #349, #351), `pasta_curves` (#47), `reddsa` (#28), plus companion firmware PR #2510. Only matters if Orchard is ever scheduled, but check before estimating it.