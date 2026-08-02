<!--
Produced by a 58-agent research pass over hyle-team/zano, every claim attacked by an
independent verifier before it reached this note. It supersedes the assumption the
MicroPython signing surface was built on: see "What this invalidates" below.
-->

# WHAT THIS INVALIDATES

`trezorzano.sign()` as currently shipped takes `secret_spend`, `secret_amount_blind`
and `secret_asset` as arguments from Python. Section 1 shows that is wrong for real
use, and not by a little:

  K1 = f * Hp(P_real)   and   K2 = t * Hp(P_real)   are PUBLISHED in the signature
  (src/crypto/clsag.cpp:208-214).

So anyone who learns f or t can test `K2 == t*Hp(P_i)` across the ring and identify
the real signer. Passing those secrets across the Python boundary does not leak funds
— section 2 shows free f and t cannot move value — it leaks the one thing a ring
signature exists to hide. The current API is fine as an internal test surface and
must not become the wire protocol.

The device has to generate f and t itself, which means owning the transaction
one-time key r and constructing every output, because the last input's f' is a
residual over the sum of output masks. The device is the transaction constructor, not
a co-signer of a host-built prefix.

# Zano CLSAG_GGX hardware signing — design note

Reference: hyle-team/zano @ `9b9c15b`, checked out **inside WSL** at `/tmp/zano-full` (`\\wsl.localhost\Ubuntu\tmp\zano-full` from Windows; Git Bash's `/tmp` is not it). All `src/...` line numbers below are from that tree.

---

## 1. Where f and t come from

### The call site, verbatim

`src/currency_core/currency_format_utils.cpp:2519-2521`, inside `generate_ZC_sig`:

```
generate_CLSAG_GGX(tx_hash_for_signature, ring, pseudo_out_amount_commitment, pseudo_out_blinded_asset_id,
  in.k_image, in_context.in_ephemeral.sec,                              // secret_0_xp
  se.real_out_amount_blinding_mask - pseudo_out_amount_blinding_mask,   // secret_1_f
  -pseudo_out_asset_id_blinding_mask,                                   // secret_2_t
  in_context.real_out_index, sig.clsags_ggx);
```

### t is not derived — it is chosen

`:2464` `pseudo_out_asset_id_blinding_mask = crypto::scalar_t::random();` — unconditional, no branch on asset, no branch on last-input, no balance constraint. `:2486` publishes `T^p_i = T_i + r'_i * X`.

**The device generates r′ locally and signs with t = −r′.** There is nothing to check and nothing the host may supply. Do not build a wire field for `t`. Do not shortcut `t = 0` for native coin: `T^p` would be byte-equal to the real ring member's `blinded_asset_id`, and separately `K2 = t·Hp(P_real)` is published (`src/crypto/clsag.cpp:213-214`), so a known `t` lets anyone test `K2 == t·Hp(P_i)` across the ring and identify the real index. Same applies to `f` via `K1` (`clsag.cpp:208-209`). **Neither f nor t may ever leave the device.**

### f is fully device-derivable, in two halves

*Minuend* — `se.real_out_amount_blinding_mask`, the blinding factor of the output being spent. Deterministic from the ECDH secret, `:3690-3724` (`decode_output_data`):

```
h  = derivation_to_scalar(8 * v * R_src, out_index_in_src_tx)     :3698
y  = Hs(CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK, h)                   :3704
check: a * (8·T_real) + y*G == 8·A_real   → else reject           :3707-3709
```
Domain string is `"ZANO_HDS_OUT_AMOUNT_BLIND_MASK_"` (31 chars + NUL = 32 bytes), `src/currency_core/crypto_config.h:15`. The device has `v`; the host supplies `R_src` and the index; line 3707 is what makes a lying host detectable.

*Subtrahend* — `pseudo_out_amount_blinding_mask` (f′). For every ZC input except the last: `:2472` `make_random()`, device's own choice. For the last ZC input: `:2465-2468`

```
f'_last = ogc.amount_blinding_masks_sum - ogc.pseudo_out_amount_blinding_masks_sum
          ± ogc.ao_amount_blinding_mask
```

`amount_blinding_masks_sum` is the sum of the **output** masks `y_j`, accumulated at `:1514`, each derived at `:1486` as `Hs(CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK, h_j)` with `h_j = Hs(8·r·V_j, j)` (`:1469-1471`).

**Therefore f is device-derivable if and only if the device owns the transaction one-time key r and constructs every output itself.** That is the load-bearing conclusion: the device must be the transaction *constructor*, not a co-signer of a host-built prefix. If the host builds outputs or supplies r, the last input's f′ is unpinnable and the whole exercise fails.

`r` is `keypair::generate()` at `:2954` — plain randomness, not consensus-constrained beyond `R = r·G` appearing in `extra`. A device-generated `r` is fully compatible. (`deterministic_generate_tx_onetime_key` at `:1617-1629` exists but is dead — its only caller is its own overload at `:1648`. Don't chase it; and note its comparator at `:1619` returns `memcmp`'s int as bool, so it isn't even a valid ordering.)

### The edge cases that break naive re-derivation

- `s_j` (output asset blinding mask) is **0** when `tdef_explicit_native_asset_id` is set (`:1482`), and `construct_tx` sets that flag automatically at `:3037-3038` when `all_inputs_are_obviously_native_coins`. That predicate is computed over **ring decoys** (`:2928-2939`): one non-native `blinded_asset_id` anywhere in any ring flips it. The device must evaluate the same predicate from the rings it already holds.
- Burn destinations (both address keys null, `:1441`) use `h = Hs(r, i)`, not ECDH, and honour `tdef_zero_amount_blinding_mask` at `:1460`. The normal branch at `:1486` ignores that flag.
- `tx_out_gateway` (`:1520-1547`) has no commitment and never touches the `tgc` accumulators — index desync hazard.

---

## 2. Minimum the device must verify

**Strictly required.**

1. **Build `tx.vout` yourself** from `(address, amount, asset_id, payment_id, flags)` you displayed, per `:1466-1507`. Never accept an output blob. All seven serialized fields of `tx_out_zarcanum` (`src/currency_core/currency_basic.h:416-424`) are yours to compute — including `encrypted_payment_id` and `mix_attr` (force `CURRENCY_TO_KEY_OUT_FORCED_NO_MIX` for auditable addresses, `:1500-1501`). Note `concealing_point`, `amount_commitment`, `blinded_asset_id` are stored **premultiplied by 1/8** (`:1474`, `:1484`, `:1488`).
2. **Build the prefix and hash it yourself.** `transaction_prefix` = `{version, hardfork_id, vin, extra, vout}` but serializes in the order `version, vin, extra, vout, hardfork_id` (`currency_basic.h:1201-1211`); `hardfork_id` is emitted only for `version >= TRANSACTION_VERSION_POST_HF5`. `result.tx_id = get_transaction_prefix_hash(tx)` (`:3119`) is the CLSAG message in the normal path (`prepare_prefix_hash_for_sign` returns `tx_id` unchanged unless `TX_FLAG_SIGNATURE_MODE_SEPARATE`, `:4906`/`:4971`). Never accept a host-supplied message hash.
3. **Per input, three checks against the ring member you were given:**
   - `x_p·G == ring[real].stealth_address` (mirrors `:2890`), with `x_p = Hs(8·v·R_src, i) + spend_sec` (`:916-925`).
   - `H_asset + r_i·X == 8·ring[real].blinded_asset_id` (`:2452-2453`) — pins the asset id.
   - `a·T_i + y_i·G == 8·ring[real].amount_commitment` (`:2458-2459`, `#ifndef NDEBUG` in the reference; **make it unconditional on device**) — pins the amount.
   These three together are what stop a host lying about what is being spent. They are self-consistency checks against host-supplied ring data; their force comes from the fact that consensus rebuilds the ring from chain data (`src/currency_core/blockchain_storage.cpp:6491-6496`), so a fabricated ring member yields a tx that simply fails to verify. That is DoS, not theft.
4. **Integer balance on device.** `sum(input amounts) == sum(output amounts) + fee`, per asset, native fee only. This is the residual check; `fee_to_declare = native_coins_input_sum - native_coins_output_sum` at `:3078`.
5. **Refuse `TX_FLAG_SIGNATURE_MODE_SEPARATE`** and refuse `version != CURRENT_TRANSACTION_VERSION` (4, `currency_config.h:39`). Separate mode crops the signed prefix (`:4949-4967`) and — worse — reads the flag from the *uncropped* `extra` at `:4907`, so a device that merely "checks the flag byte" can be walked into signing a cropped prefix. Refuse by pinning version and by being the sole author of `extra`.
6. **Display** every non-change destination (address, amount, asset), the fee, and any burn (`spend_pub == view_pub == null`) as a burn. Verify the change destination by re-deriving your own address rather than displaying it.

**Defence in depth (do later).** Verifying the host's range proof; checking that ring `key_offsets` are strictly ascending after relative encoding (`:4288-4304`); asserting the CLSAG relations `f·G == 8A_real − A^p` and `t·X == 8T_real − T^p` inside the signer (free, catches your own bugs — these are exactly `clsag.cpp:204-205`); withholding decryptability of the signatures behind a final-message opening key.

**Not worth device budget.** Pseudo-out inflation. Layer 1 is with respect to `G` only, and `A^p_i = a_i·T_i + f'_i·G` reuses the **real ring member's** `T_i` (`:2492`), not `T^p`. So for any `f`, `A^p` is forced to `a_i·T_i + (y_i − f)·G` — same amount, same asset. Free `f`/`t` cannot move value.

---

## 3. Message flow

Streaming is mandatory. Three hard barriers:

- Key images require the spend secret, so the host cannot know the vin order until the device has processed every input; vin is sorted by key image before the prefix hash (`:3066-3075`, ascending `memcmp`, enforced at consensus via `validate_inputs_sorting`, `currency_format_utils_transactions.cpp:846-861`).
- The prefix hash covers `vout`, so **no** input can be signed until every output is final — not just the last one.
- The last ZC input's `f′` needs `sum(y_j)` over all outputs (`:2468`).

Proposed messages (mirroring the Monero app's shape, which is eight pairs, not ten — `core/src/apps/monero/signing/` has steps 01,02,04,05,06,07,09,10):

| # | Request → Ack | Device does / retains |
|---|---|---|
| 1 | `ZanoSignTx{version, input_count, output_count, unlock_time, fee, tx_flags, account}` → `Ack{}` | Derives session HMAC/enc keys; generates `r`, returns nothing. Retains `r`, counts, fee. |
| 2×N | `ZanoTxSource{ring[], real_index, real_out_tx_key, real_out_index_in_tx, amount, asset_id, real_out_amount_blinding_mask, real_out_asset_id_blinding_mask}` → `Ack{key_image, source_hmac}` | Runs the three §2.3 checks; **re-derives** `y_i`, `r_i` and compares to the supplied values (accept only as a hint). Retains per input: `key_image`, `y_i`, `a_i`, `asset_id`, 32-byte digest of the source entry. |
| 3 | `ZanoTxAllInputsSet{}` → `Ack{sorted_order[]}` | Sorts key images ascending; fixes vin order. |
| 4×N | `ZanoTxInputVini{index, vini_bin, source_hmac}` → `Ack{}` | Verifies the HMAC, hashes `vini_bin` into the prefix hasher. (Skip this phase entirely if you buffer the vin blobs at step 2 — ~130 B each at ring 16.) |
| 5×M | `ZanoTxDestination{addr, amount, asset_id, payment_id, flags, is_change}` → `Ack{out_bin}` | Displays non-change; verifies change against its own address; builds `tx_out_zarcanum`; hashes it. Retains running `sum(y_j)`, `sum(s_j·a_j)`, `sum(A_j)`, and — for the range proof offload — `(a_j, y_j)`. |
| 6 | `ZanoTxAllOutputsSet{}` → `Ack{tx_pub_key, fee_entry, derivation_hints, tx_prefix_hash, rsig_data{amounts[], masks[]}}` | Appends `R`, fee entry, derivation hints to `extra`; finalises prefix hash; **asks the user to confirm**. |
| 7×N | `ZanoTxSignInput{index, source_entry (re-sent), source_hmac}` → `Ack{ZC_sig}` | Re-verifies the digest. Draws `r′_i`; computes `f′_i` (random, or the `:2468` residual for the last ZC input); `f = y_i − f′_i`, `t = −r′_i`; emits `A^p`, `T^p`, CLSAG_GGX. Retains `sum(r_i·a_i)`, `pseudo_outs_blinded_asset_ids[]`, `r_i + r′_i`. |
| 8 | `ZanoTxFinal{}` → `Ack{asset_surjection_proof, balance_proof, opening_key}` | Generates BGE proofs and the balance double-Schnorr. |

**Round trips for 2-in / 2-out: 12** (1 + 2 + 1 + 2 + 2 + 1 + 2 + 1). **10** if you buffer vin blobs and drop phase 4.

**Which proofs the device must own.** The balance proof signs with `ogc.tx_key.sec` (= `r`) as one of its two secrets (`currency_format_utils_transactions.cpp:340`, `generate_double_schnorr_sig<gt_X, gt_G>`), so it is device-side; with ZC inputs `secret_x = sum(r_i·a_i) − sum(s_j·a_j)` (`:328`). The asset surjection proof is device-side too, and this is not optional: its per-output secret is `−s_j + (r_i + r′_i)` (`currency_format_utils.cpp:307`, `:324`), and exporting `r_i + r′_i` would expose `t` and break the CLSAG ring. The **range proof can be offloaded**: `generate_zc_outs_range_proof` (`:494-548`) needs only `(amounts, y_j, T_j, A_j)` — all quantities the host already knows or can be told harmlessly — and a forged range proof only makes the tx invalid, it cannot steal.

---

## 4. MVP cut

**Scope: one ZC input, two `tx_out_zarcanum` outputs (destination + change), native ZANO only, `version = 4`, `tx_flags = 0`.**

What that buys you:

- One CLSAG_GGX with `f = y_0 − f′_0` where `f′_0 = sum(y_j)` (single input ⇒ it is the last input ⇒ the `:2468` branch, with no asset-operation term).
- `s_j = 0` and `T_j = H` **iff** every ring member's `blinded_asset_id == native_coin_asset_id_1div8`. Evaluate the `:2933` predicate; for the MVP, if it comes out false, refuse rather than implementing the `s_j = Hs(...)` branch. (Caveat: this constrains decoy selection, which is an anonymity cost — it is an MVP shortcut, not a design.)
- Balance proof: `secret_x = 0 − 0 = 0`, a `double_schnorr_sig<gt_X, gt_G>` over `(0, r)`. Cheap.
- Asset surjection proof: two BGE proofs, each over a ring of **size 1** (`confidential_inputs_count == 1`, no bare native inputs ⇒ no extra ring member), secret `= r′_0`, `m = 1`, `mn = 4` (`src/crypto/one_out_of_many_proofs.cpp:61-91`). Still a new primitive to port; it is the only genuinely new proof system in the MVP.
- Range proof: offloaded to the host.

Excluded, and each must be an explicit refusal, not an omission: non-native assets and all asset operations (`asset_descriptor_operation` in extra); gateway inputs and outputs; burn destinations (null/null address); `TX_FLAG_SIGNATURE_MODE_SEPARATE`; multisig; bare `txin_to_key` inputs; more than one ZC input; more than 32 outputs (`CURRENCY_TX_MAX_ALLOWED_OUTS`, `currency_config.h:23`); `version != 4`; change to any address other than the device's own.

---

## 5. Still unknown

- **Does `generate_BGE_proof` / `verify_BGE_proof` actually round-trip at ring size 1?** `constexpr_pow(m, n)` at `one_out_of_many_proofs.cpp:76` reads as `pow(m, n)`, not `pow(n, m)`, which looks wrong for the intended `N`. Test against the reference before committing to the MVP shape.
- **How common are all-explicit-native rings in practice?** The MVP's `s_j = 0` shortcut depends on wallets picking decoys that all carry `tdef_explicit_native_asset_id`. I did not sample chain data.
- **Integration surface.** `wallet2::sign_transfer` (`src/wallet/wallet2.h:646`, `src/wallet/wallet2.cpp:4243-4297`) is the existing cold-signing entry point: it takes a chacha-encrypted `finalize_tx_param` blob and calls `finalize_transaction`. Whether a device-constructed tx can be returned through that same `signed_tx_blob` contract, or whether `finalize_transaction` must be re-plumbed to call the device step by step, I did not trace.
- **Derivation hints.** `add_random_derivation_hints_and_put_them_to_tx` (`:3046`) puts random padding into `extra`. Since the device authors `extra`, this is its choice — but I did not check whether consensus imposes any count or ordering rule on hints.
- **Whether `A^p`/`T^p` need to reach the host before step 8.** They are `ZC_sig` fields (`currency_basic.h:487-494`) and are outside the prefix, so ordering is free — but the ASP verifier re-derives `T^p` from `real_zc_ins_asset_ids[i] + (r_i + r′_i)·X` (`currency_format_utils_transactions.cpp:1010-1013`) in the tx-generation-context validation path. If that path is ever exercised in a HW flow, the device would have to export `r_i + r′_i`, which it must not. I did not confirm that path is unreachable for a normal (non-separately-signed) transfer.
- **Monero precedent for `t`.** There is none — Monero has no asset ids. Anything asserting one is extrapolation.