/**
 * clsag_ggx.c — CLSAG (G,G,X) ring signature for Zano / Zarcanum
 *
 * Implements generate_CLSAG_GGX and verify_CLSAG_GGX for the Trezor firmware.
 * This is the core signing primitive for every confidential Zano transfer,
 * including native ZANO (the v1 target per crypto-delta-spec.md §3).
 *
 * Algorithm source: hyle-team/zano src/crypto/clsag.cpp
 * Spec: eprint 2019/654 (d-CLSAG) + dv-CLSAG extension whitepaper
 *
 * ALL primitives used here already exist in Trezor's crypto layer:
 *   - Keccak-256       (crypto/sha3)
 *   - ed25519-donna    (scalar/point arithmetic)
 *   - xmr_hash_to_ec   (hash-to-point, from Monero code)
 *
 * The port is assembly — calling existing functions in the exact order
 * with byte-identical domain-separation tags.
 *
 * SPDX-License-Identifier: MIT
 * Part of the beehive-nature ecosystem.
 */

#include "clsag_ggx.h"
#include "../ed25519-donna/ed25519-donna.h"
#include "../sha3.h"
#include "../monero/xmr.h"
#include "../rand.h"
#include "zano_generators.h"
#include "zano_transcript.h"

// ── Domain-Separation Tags (32 bytes each: 31 chars + NUL) ──────────
// These MUST be byte-identical to Zano's crypto_config.h.
// One wrong byte → signatures rejected by the daemon.

static const char DS_GGX_LAYER_0[32]    = "ZANO_HDS_CLSAG_GGX_LAYER_ZERO__";
static const char DS_GGX_LAYER_1[32]    = "ZANO_HDS_CLSAG_GGX_LAYER_ONE___";
static const char DS_GGX_LAYER_2[32]    = "ZANO_HDS_CLSAG_GGX_LAYER_TWO___";
static const char DS_GGX_CHALLENGE[32]  = "ZANO_HDS_CLSAG_GGX_CHALLENGE___";

// Generator constants (c_point_X, c_scalar_1div8) and the Fiat-Shamir
// transcript now live in the shared headers, so the Keccak-vs-SHA3 choice and
// the generator encodings exist in exactly one place across the Zano port.

#define ZANO_HS_MAX_ITEMS 256  // ring transcript: 1 + 3*ring_size + 5 items

// ── Helpers ──────────────────────────────────────────────────────────

// Hash a point to another point: hp(P) = hash_to_point(P)
// Uses Trezor's existing xmr_hash_to_ec (same algorithm as Zano's hp())
static void zano_hp(ge25519 *out, const ge25519 *p) {
    uint8_t compressed[32];
    ge25519_pack(compressed, p);
    // xmr_hash_to_ec takes 32-byte input and produces a ge point
    xmr_hash_to_ec(out, compressed, 32);
}

// ge25519_mul8 is provided by ed25519-donna (built-in)

// ── generate_CLSAG_GGX ──────────────────────────────────────────────

bool zano_generate_clsag_ggx(
    const uint8_t  message_hash[32],        // m: transaction hash to sign
    const zano_ring_member *ring,            // ring members
    size_t          ring_size,
    const ge25519  *pseudo_out_amount_commitment,  // NOT premul 1/8
    const ge25519  *pseudo_out_asset_id,           // NOT premul 1/8
    const ge25519  *key_image,                     // ki = hp(P) * x
    const bignum256modm secret_0_xp,               // spend secret component
    const bignum256modm secret_1_f,                // amount-commitment blinding delta
    const bignum256modm secret_2_t,                // asset-id secret
    size_t          secret_index,                  // which ring member is real
    zano_clsag_ggx_sig *sig                        // OUTPUT
) {
    if (ring_size == 0 || secret_index >= ring_size) return false;
    if (ring_size > (ZANO_HS_MAX_ITEMS - 6) / 3) return false;  // 1 + 3n + 5 items
    if (!zano_generators_init()) return false;

    zano_hs_t hsc;
    uint8_t   hs_buf[ZANO_HS_MAX_ITEMS * 32];

    // ── Step 1: Auxiliary key images K1, K2 ──────────────────────
    // K1 = mul8( (1/8 · secret_1_f) · hp(P_real) )
    // K2 = mul8( (1/8 · secret_2_t) · hp(P_real) )
    ge25519 hp_P_real;
    zano_hp(&hp_P_real, &ring[secret_index].stealth_address_pt);

    bignum256modm s1_div8, s2_div8;
    mul256_modm(s1_div8, secret_1_f, zano_scalar_1div8);
    mul256_modm(s2_div8, secret_2_t, zano_scalar_1div8);

    ge25519 K1, K2;
    ge25519_scalarmult(&K1, &hp_P_real, s1_div8);
    ge25519_scalarmult(&K2, &hp_P_real, s2_div8);

    // The WIRE form is the 1/8 point (Zano clsag.cpp:209,214 serialize
    // K1_div8 BEFORE mul8). Pack first, then mul8 local copies for the
    // aggregate key images only.
    ge25519_pack(sig->K1, &K1);
    ge25519_pack(sig->K2, &K2);

    ge25519_mul8(&K1, &K1);
    ge25519_mul8(&K2, &K2);

    // ── Step 2: Input hash (Keccak, NOT reduced mod L) ──────────
    zano_hs_init(&hsc, hs_buf, sizeof(hs_buf));
    zano_hs_add_message(&hsc, message_hash);  // m, reduced mod L

    for (size_t i = 0; i < ring_size; i++) {
        zano_hs_add_point(&hsc, &ring[i].stealth_address_pt);    // P_i
        zano_hs_add(&hsc, ring[i].amount_commitment);            // A_i (premul 1/8, stored as bytes)
        zano_hs_add(&hsc, ring[i].blinded_asset_id);             // T_i (premul 1/8, stored as bytes)
    }

    // pseudo_out values: multiply by 1/8 before hashing
    ge25519 pc_div8, pa_div8;
    ge25519_scalarmult(&pc_div8, pseudo_out_amount_commitment, zano_scalar_1div8);
    ge25519_scalarmult(&pa_div8, pseudo_out_asset_id, zano_scalar_1div8);
    zano_hs_add_point(&hsc, &pc_div8);
    zano_hs_add_point(&hsc, &pa_div8);

    uint8_t ki_bytes[32];
    ge25519_pack(ki_bytes, key_image);
    zano_hs_add(&hsc, ki_bytes);       // ki
    zano_hs_add(&hsc, sig->K1);        // K1
    zano_hs_add(&hsc, sig->K2);        // K2

    uint8_t input_hash[32];
    zano_hs_hash_raw(input_hash, &hsc);

    // ── Step 3: Aggregation coefficients ─────────────────────────
    bignum256modm mu0, mu1, mu2;

    zano_hs_add_ds_tag(&hsc, DS_GGX_LAYER_0);
    zano_hs_add(&hsc, input_hash);
    zano_hs_hash_reduce(mu0, &hsc);

    zano_hs_add_ds_tag(&hsc, DS_GGX_LAYER_1);
    zano_hs_add(&hsc, input_hash);
    zano_hs_hash_reduce(mu1, &hsc);

    zano_hs_add_ds_tag(&hsc, DS_GGX_LAYER_2);
    zano_hs_add(&hsc, input_hash);
    zano_hs_hash_reduce(mu2, &hsc);

    // ── Step 4: Undo 1/8 on ring data ────────────────────────────
    // (done inline in step 5 to avoid large temp arrays)

    // ── Step 5: Aggregate public keys W_g[i], W_x[i] ─────────────
    // W_g[i] = mu0 * P_i + mu1 * (mul8(A_i) - pseudo_C)
    // W_x[i] = mu2 * (mul8(T_i) - pseudo_T)
    //
    // NOTE: For memory-constrained firmware, we compute these inline
    // during the challenge ladder rather than storing the full array.
    // For clarity (and because ring sizes are small on device), we store.

    ge25519 *W_g = (ge25519 *)alloca(ring_size * sizeof(ge25519));
    ge25519 *W_x = (ge25519 *)alloca(ring_size * sizeof(ge25519));
    if (!W_g || !W_x) return false;

    for (size_t i = 0; i < ring_size; i++) {
        ge25519 A_full, T_full;
        // Decompress A_i and T_i, then mul8
        if (ge25519_unpack_vartime(&A_full, ring[i].amount_commitment) == 0) return false;
        if (ge25519_unpack_vartime(&T_full, ring[i].blinded_asset_id) == 0) return false;
        ge25519_mul8(&A_full, &A_full);
        ge25519_mul8(&T_full, &T_full);

        // W_g[i] = mu0 * P_i + mu1 * (A_full - pseudo_C)
        ge25519 sub_result, mu0_P, mu1_diff;
        ge25519_add(&sub_result, &A_full, pseudo_out_amount_commitment, 1);
        ge25519_scalarmult(&mu0_P, &ring[i].stealth_address_pt, mu0);
        ge25519_scalarmult(&mu1_diff, &sub_result, mu1);
        ge25519_add(&W_g[i], &mu0_P, &mu1_diff, 0);

        // W_x[i] = mu2 * (T_full - pseudo_T)
        ge25519_add(&sub_result, &T_full, pseudo_out_asset_id, 1);
        ge25519_scalarmult(&W_x[i], &sub_result, mu2);
    }

    // ── Step 6: Aggregate secret keys ────────────────────────────
    bignum256modm w_g, w_x;
    // w_g = mu0 * secret_0_xp + mu1 * secret_1_f
    bignum256modm t0, t1;
    mul256_modm(t0, mu0, secret_0_xp);
    mul256_modm(t1, mu1, secret_1_f);
    add256_modm(w_g, t0, t1);
    // w_x = mu2 * secret_2_t
    mul256_modm(w_x, mu2, secret_2_t);

    // ── Step 7: Aggregate key images ─────────────────────────────
    ge25519 W_ki_g, W_ki_x;
    ge25519 mu0_ki, mu1_K1, mu2_K2;
    ge25519_scalarmult(&mu0_ki, key_image, mu0);
    ge25519_scalarmult(&mu1_K1, &K1, mu1);
    ge25519_add(&W_ki_g, &mu0_ki, &mu1_K1, 0);
    ge25519_scalarmult(&mu2_K2, &K2, mu2);
    ge25519_copy(&W_ki_x, &mu2_K2);

    // ── Step 8: Initial commitment ───────────────────────────────
    bignum256modm alpha_g, alpha_x;
    // Generate random nonces (MUST be cryptographically random on device)
    // On Trezor, use rng_get() to fill these
    zano_random_scalar(alpha_g);
    zano_random_scalar(alpha_x);

    zano_hs_add_ds_tag(&hsc, DS_GGX_CHALLENGE);
    zano_hs_add(&hsc, input_hash);
    // alpha_g * G
    ge25519 aG;
    ge25519_scalarmult_base_wrapper(&aG, alpha_g);
    zano_hs_add_point(&hsc, &aG);
    // alpha_g * hp(P_real)
    ge25519 aHP;
    ge25519_scalarmult(&aHP, &hp_P_real, alpha_g);
    zano_hs_add_point(&hsc, &aHP);
    // alpha_x * X
    ge25519 aX;
    ge25519_scalarmult(&aX, &zano_point_X, alpha_x);
    zano_hs_add_point(&hsc, &aX);
    // alpha_x * hp(P_real)
    ge25519 aXHP;
    ge25519_scalarmult(&aXHP, &hp_P_real, alpha_x);
    zano_hs_add_point(&hsc, &aXHP);

    bignum256modm c_prev;
    zano_hs_hash_reduce(c_prev, &hsc);

    // ── Step 9: Challenge ladder ─────────────────────────────────
    // Pre-fill random responses for non-real members
    for (size_t i = 0; i < ring_size; i++) {
        if (i != secret_index) {
            zano_random_scalar(sig->r_g[i]);
            zano_random_scalar(sig->r_x[i]);
        }
    }

    for (size_t j = 0, i = (secret_index + 1) % ring_size;
         j < ring_size - 1;
         ++j, i = (i + 1) % ring_size)
    {
        if (i == 0) {
            copy256_modm(sig->c, c_prev);  // capture c_0
        }

        zano_hs_add_ds_tag(&hsc, DS_GGX_CHALLENGE);
        zano_hs_add(&hsc, input_hash);

        // r_g[i] * G + c_prev * W_g[i]
        ge25519 rg_G, cp_Wg, sum_g;
        ge25519_scalarmult_base_wrapper(&rg_G, sig->r_g[i]);
        ge25519_scalarmult(&cp_Wg, &W_g[i], c_prev);
        ge25519_add(&sum_g, &rg_G, &cp_Wg, 0);
        zano_hs_add_point(&hsc, &sum_g);

        // r_g[i] * hp(P_i) + c_prev * W_ki_g
        ge25519 hp_Pi, rg_HP, cp_Ig, sum_kig;
        zano_hp(&hp_Pi, &ring[i].stealth_address_pt);
        ge25519_scalarmult(&rg_HP, &hp_Pi, sig->r_g[i]);
        ge25519_scalarmult(&cp_Ig, &W_ki_g, c_prev);
        ge25519_add(&sum_kig, &rg_HP, &cp_Ig, 0);
        zano_hs_add_point(&hsc, &sum_kig);

        // r_x[i] * X + c_prev * W_x[i]
        ge25519 rx_X, cp_Wx, sum_x;
        ge25519_scalarmult(&rx_X, &zano_point_X, sig->r_x[i]);
        ge25519_scalarmult(&cp_Wx, &W_x[i], c_prev);
        ge25519_add(&sum_x, &rx_X, &cp_Wx, 0);
        zano_hs_add_point(&hsc, &sum_x);

        // r_x[i] * hp(P_i) + c_prev * W_ki_x
        ge25519 rx_HP, cp_Ix, sum_kix;
        ge25519_scalarmult(&rx_HP, &hp_Pi, sig->r_x[i]);
        ge25519_scalarmult(&cp_Ix, &W_ki_x, c_prev);
        ge25519_add(&sum_kix, &rx_HP, &cp_Ix, 0);
        zano_hs_add_point(&hsc, &sum_kix);

        zano_hs_hash_reduce(c_prev, &hsc);
    }

    // ── Step 10: Close the ring ──────────────────────────────────
    if (secret_index == 0) {
        copy256_modm(sig->c, c_prev);
    }

    // r_g[secret_index] = alpha_g - c_prev * w_g
    bignum256modm cp_wg;
    mul256_modm(cp_wg, c_prev, w_g);
    sub256_modm(sig->r_g[secret_index], alpha_g, cp_wg);

    // r_x[secret_index] = alpha_x - c_prev * w_x
    bignum256modm cp_wx;
    mul256_modm(cp_wx, c_prev, w_x);
    sub256_modm(sig->r_x[secret_index], alpha_x, cp_wx);

    return true;
}

// ── verify_CLSAG_GGX ────────────────────────────────────────────────

bool zano_verify_clsag_ggx(
    const uint8_t  message_hash[32],
    const zano_ring_member *ring,
    size_t          ring_size,
    const uint8_t   pseudo_out_amount_commitment[32],  // premul 1/8
    const uint8_t   pseudo_out_asset_id[32],           // premul 1/8
    const uint8_t   key_image[32],
    const zano_clsag_ggx_sig *sig
) {
    if (ring_size == 0) return false;
    if (ring_size > (ZANO_HS_MAX_ITEMS - 6) / 3) return false;  // 1 + 3n + 5 items
    if (!zano_generators_init()) return false;

    zano_hs_t hsc;
    uint8_t   hs_buf[ZANO_HS_MAX_ITEMS * 32];

    // Decompress key image and auxiliary key images
    ge25519 ki_pt, K1_pt, K2_pt;
    if (ge25519_unpack_vartime(&ki_pt, key_image) == 0) return false;
    if (ge25519_unpack_vartime(&K1_pt, sig->K1) == 0) return false;
    if (ge25519_unpack_vartime(&K2_pt, sig->K2) == 0) return false;

    // ── Reconstruct input_hash (same as generate) ────────────────
    zano_hs_init(&hsc, hs_buf, sizeof(hs_buf));
    zano_hs_add_message(&hsc, message_hash);  // m, reduced mod L

    for (size_t i = 0; i < ring_size; i++) {
        zano_hs_add_point(&hsc, &ring[i].stealth_address_pt);
        zano_hs_add(&hsc, ring[i].amount_commitment);
        zano_hs_add(&hsc, ring[i].blinded_asset_id);
    }

    // On verify side, pseudo_out values ARE premultiplied by 1/8
    zano_hs_add(&hsc, pseudo_out_amount_commitment);
    zano_hs_add(&hsc, pseudo_out_asset_id);
    zano_hs_add(&hsc, key_image);
    zano_hs_add(&hsc, sig->K1);
    zano_hs_add(&hsc, sig->K2);

    uint8_t input_hash[32];
    zano_hs_hash_raw(input_hash, &hsc);

    // ── Aggregation coefficients (same derivation) ───────────────
    bignum256modm mu0, mu1, mu2;
    zano_hs_add_ds_tag(&hsc, DS_GGX_LAYER_0); zano_hs_add(&hsc, input_hash);
    zano_hs_hash_reduce(mu0, &hsc);
    zano_hs_add_ds_tag(&hsc, DS_GGX_LAYER_1); zano_hs_add(&hsc, input_hash);
    zano_hs_hash_reduce(mu1, &hsc);
    zano_hs_add_ds_tag(&hsc, DS_GGX_LAYER_2); zano_hs_add(&hsc, input_hash);
    zano_hs_hash_reduce(mu2, &hsc);

    // ── Aggregate public keys (same as generate step 5) ──────────
    ge25519 *W_g = (ge25519 *)alloca(ring_size * sizeof(ge25519));
    ge25519 *W_x = (ge25519 *)alloca(ring_size * sizeof(ge25519));
    if (!W_g || !W_x) return false;

    // Decompress pseudo_out for verify (already premul 1/8)
    ge25519 pc_pt, pa_pt;
    if (ge25519_unpack_vartime(&pc_pt, pseudo_out_amount_commitment) == 0) return false;
    if (ge25519_unpack_vartime(&pa_pt, pseudo_out_asset_id) == 0) return false;

    for (size_t i = 0; i < ring_size; i++) {
        ge25519 A_full, T_full;
        if (ge25519_unpack_vartime(&A_full, ring[i].amount_commitment) == 0) return false;
        if (ge25519_unpack_vartime(&T_full, ring[i].blinded_asset_id) == 0) return false;
        ge25519_mul8(&A_full, &A_full);
        ge25519_mul8(&T_full, &T_full);

        // On verify: A_full - mul8(pc_pt) since pseudo_out is premul 1/8
        ge25519 pc8, sub_result, mu0_P, mu1_diff;
        ge25519_mul8(&pc8, &pc_pt);
        ge25519_add(&sub_result, &A_full, &pc8, 1);
        ge25519_scalarmult(&mu0_P, &ring[i].stealth_address_pt, mu0);
        ge25519_scalarmult(&mu1_diff, &sub_result, mu1);
        ge25519_add(&W_g[i], &mu0_P, &mu1_diff, 0);

        ge25519 pa8;
        ge25519_mul8(&pa8, &pa_pt);
        ge25519_add(&sub_result, &T_full, &pa8, 1);
        ge25519_scalarmult(&W_x[i], &sub_result, mu2);
    }

    // ── Aggregate key images ─────────────────────────────────────
    ge25519 W_ki_g, W_ki_x;
    ge25519 mu0_ki, mu1_K1, mu2_K2;
    // sig->K1/K2 are on the wire in 1/8 form — mul8 before aggregating
    // (Zano clsag.cpp:442,448). The raw bytes were already hashed above.
    ge25519_mul8(&K1_pt, &K1_pt);
    ge25519_mul8(&K2_pt, &K2_pt);
    ge25519_scalarmult(&mu0_ki, &ki_pt, mu0);
    ge25519_scalarmult(&mu1_K1, &K1_pt, mu1);
    ge25519_add(&W_ki_g, &mu0_ki, &mu1_K1, 0);
    ge25519_scalarmult(&mu2_K2, &K2_pt, mu2);
    ge25519_copy(&W_ki_x, &mu2_K2);

    // ── Challenge ladder (start from sig.c, must return to sig.c) ─
    bignum256modm c_prev;
    copy256_modm(c_prev, sig->c);

    for (size_t i = 0; i < ring_size; i++) {
        zano_hs_add_ds_tag(&hsc, DS_GGX_CHALLENGE);
        zano_hs_add(&hsc, input_hash);

        ge25519 rg_G, cp_Wg, sum_g;
        ge25519_scalarmult_base_wrapper(&rg_G, sig->r_g[i]);
        ge25519_scalarmult(&cp_Wg, &W_g[i], c_prev);
        ge25519_add(&sum_g, &rg_G, &cp_Wg, 0);
        zano_hs_add_point(&hsc, &sum_g);

        ge25519 hp_Pi, rg_HP, cp_Ig, sum_kig;
        zano_hp(&hp_Pi, &ring[i].stealth_address_pt);
        ge25519_scalarmult(&rg_HP, &hp_Pi, sig->r_g[i]);
        ge25519_scalarmult(&cp_Ig, &W_ki_g, c_prev);
        ge25519_add(&sum_kig, &rg_HP, &cp_Ig, 0);
        zano_hs_add_point(&hsc, &sum_kig);

        ge25519 rx_X, cp_Wx, sum_x;
        ge25519_scalarmult(&rx_X, &zano_point_X, sig->r_x[i]);
        ge25519_scalarmult(&cp_Wx, &W_x[i], c_prev);
        ge25519_add(&sum_x, &rx_X, &cp_Wx, 0);
        zano_hs_add_point(&hsc, &sum_x);

        ge25519 rx_HP, cp_Ix, sum_kix;
        ge25519_scalarmult(&rx_HP, &hp_Pi, sig->r_x[i]);
        ge25519_scalarmult(&cp_Ix, &W_ki_x, c_prev);
        ge25519_add(&sum_kix, &rx_HP, &cp_Ix, 0);
        zano_hs_add_point(&hsc, &sum_kix);

        zano_hs_hash_reduce(c_prev, &hsc);
    }

    // ── Verify: c_prev must equal sig.c (ring closes) ────────────
    return eq256_modm(c_prev, sig->c);
}

// zano_random_scalar now lives in zano_generators.c (shared).
