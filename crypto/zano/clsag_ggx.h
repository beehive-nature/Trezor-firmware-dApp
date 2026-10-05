/**
 * clsag_ggx.h — CLSAG (G,G,X) ring signature for Zano / Zarcanum
 *
 * This is the core signing primitive for every confidential Zano transfer.
 * See clsag_ggx.c for the full algorithm documentation.
 *
 * SPDX-License-Identifier: MIT
 * Part of the beehive-nature ecosystem.
 */
#ifndef ZANO_CLSAG_GGX_H
#define ZANO_CLSAG_GGX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../ed25519-donna/ed25519-donna.h"

// ── Types ───────────────────────────────────────────────────────────

/// A ring member: the public data visible to all signers and verifiers.
/// Points are stored in compressed (32-byte) form where possible;
/// stealth_address_pt is pre-decompressed for convenience.
typedef struct {
    ge25519    stealth_address_pt;    ///< P_i — decompressed stealth address
    uint8_t    amount_commitment[32]; ///< A_i — premultiplied by 1/8 (compressed)
    uint8_t    blinded_asset_id[32];  ///< T_i — premultiplied by 1/8 (compressed)
} zano_ring_member;

/// CLSAG_GGX signature output.
/// Matches Zano's CLSAG_GGX_signature struct.
typedef struct {
    bignum256modm  c;                 ///< initial challenge (scalar mod L)
    bignum256modm *r_g;              ///< G-layer responses (ring_size elements)
    bignum256modm *r_x;              ///< X-layer responses (ring_size elements)
    uint8_t        K1[32];           ///< auxiliary key image, layer 1 (compressed)
    uint8_t        K2[32];           ///< auxiliary key image, layer 2 (compressed)
} zano_clsag_ggx_sig;

// ── API ─────────────────────────────────────────────────────────────

/**
 * Generate a CLSAG_GGX ring signature.
 *
 * @param message_hash               Transaction hash to sign (m)
 * @param ring                       Array of ring members
 * @param ring_size                  Number of decoys + 1
 * @param pseudo_out_amount_commitment  NOT premultiplied by 1/8
 * @param pseudo_out_asset_id           NOT premultiplied by 1/8
 * @param key_image                  ki = hp(P_real) * spend_secret
 * @param secret_0_xp                Spend secret component
 * @param secret_1_f                 Amount-commitment blinding delta
 * @param secret_2_t                 Asset-id secret
 * @param secret_index               Index of the real signer in the ring
 * @param sig                        [out] Resulting signature
 * @return true on success, false on invalid input
 *
 * THE 1/8 CONVENTION (critical):
 *   - ring[].amount_commitment and blinded_asset_id ARE premultiplied by 1/8
 *   - pseudo_out_* are NOT premultiplied on the generate side
 *   - sig.K1, sig.K2 are stored PREMULTIPLIED by 1/8 (verify mul8s them)
 */
bool zano_generate_clsag_ggx(
    const uint8_t         message_hash[32],
    const zano_ring_member *ring,
    size_t                 ring_size,
    const ge25519         *pseudo_out_amount_commitment,
    const ge25519         *pseudo_out_asset_id,
    const ge25519         *key_image,
    const bignum256modm    secret_0_xp,
    const bignum256modm    secret_1_f,
    const bignum256modm    secret_2_t,
    size_t                 secret_index,
    zano_clsag_ggx_sig    *sig
);

/**
 * Verify a CLSAG_GGX ring signature.
 *
 * @param message_hash               Transaction hash that was signed
 * @param ring                       Array of ring members
 * @param ring_size                  Number of ring members
 * @param pseudo_out_amount_commitment  Premultiplied by 1/8 (verify convention)
 * @param pseudo_out_asset_id           Premultiplied by 1/8 (verify convention)
 * @param key_image                  The key image being proven
 * @param sig                        The signature to verify
 * @return true if the ring closes (signature valid)
 *
 * NOTE: On the verify side, pseudo_out values ARE premultiplied by 1/8,
 * unlike generate. This asymmetry is intentional in the Zano protocol.
 */
bool zano_verify_clsag_ggx(
    const uint8_t         message_hash[32],
    const zano_ring_member *ring,
    size_t                 ring_size,
    const uint8_t          pseudo_out_amount_commitment[32],
    const uint8_t          pseudo_out_asset_id[32],
    const uint8_t          key_image[32],
    const zano_clsag_ggx_sig *sig
);

// ── Device RNG (implementation provides this) ───────────────────────

/// Fill a scalar with a cryptographically random value reduced mod L.
/// On Trezor, backed by the hardware RNG.
void zano_random_scalar(bignum256modm out);

#endif // ZANO_CLSAG_GGX_H
