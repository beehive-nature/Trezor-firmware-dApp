/**
 * schnorr.h — Zano generic Schnorr and double-Schnorr signatures.
 *
 * These are the primitives behind Zano's balance proof: check_tx_balance()
 * proves value and asset conservation with Schnorr signatures over specific
 * generators rather than with one monolithic proof.
 *
 * Reference: hyle-team/zano src/crypto/zarcanum.h
 *   generic_schnorr_sig / generate_schnorr_sig<gen> / verify_schnorr_sig<gen>
 *   generic_double_schnorr_sig / generate_double_schnorr_sig<gen0,gen1>
 *                              / verify_double_schnorr_sig<gen0,gen1>
 *
 * Generator tags implemented here are the ones the reference actually
 * instantiates: gt_G and gt_X for the single sig, (G,G) and (X,G) for the
 * double sig. gt_H / gt_H2 / gt_U have no instantiation in the reference and
 * are deliberately absent rather than guessed at.
 *
 * NOTE ON THE MESSAGE HASH: these signatures append m with add_hash(), i.e.
 * RAW. This differs from CLSAG_GGX, which appends m via add_scalar() and so
 * reduces it mod L first. Do not "harmonise" the two.
 *
 * SPDX-License-Identifier: MIT
 * Part of the beehive-nature ecosystem.
 */
#ifndef ZANO_SCHNORR_H
#define ZANO_SCHNORR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../ed25519-donna/ed25519-donna.h"

/// Which generator a proof is taken over. Values mirror Zano's generator_tag.
typedef enum {
    ZANO_GEN_G = 1,  ///< ed25519 base point
    ZANO_GEN_X = 4,  ///< Zano's asset-id generator c_point_X
} zano_generator_tag;

/// generic_schnorr_sig — proves knowledge of a such that A = a * gen.
typedef struct {
    bignum256modm c;
    bignum256modm y;
} zano_schnorr_sig;

/// generic_double_schnorr_sig — one challenge binding two statements:
/// A = a * gen0 and B = b * gen1.
typedef struct {
    bignum256modm c;
    bignum256modm y0;
    bignum256modm y1;
} zano_double_schnorr_sig;

/**
 * Sign: prove knowledge of secret_a with A = secret_a * gen.
 *
 * @param message_hash  m, appended RAW (add_hash semantics)
 * @param A             the public point, MUST equal secret_a * gen
 * @param secret_a      the witness
 * @param gen           ZANO_GEN_G or ZANO_GEN_X
 * @param sig           [out]
 * @return false on an unsupported generator, a transcript overflow, or if A
 *         does not match secret_a * gen (checked — the reference only checks
 *         this under NDEBUG-off, we check always; it is cheap next to the
 *         scalarmults and catches caller error before a bad proof ships).
 */
bool zano_generate_schnorr_sig(const uint8_t message_hash[32],
                               const ge25519 *A,
                               const bignum256modm secret_a,
                               zano_generator_tag gen,
                               zano_schnorr_sig *sig);

/**
 * Verify a generic_schnorr_sig.
 *
 * @param A_bytes  the public point in compressed form, as it appears on the
 *                 wire (the reference hashes these bytes via add_pub_key)
 * @return true only if the signature is valid AND both scalars are canonical.
 */
bool zano_verify_schnorr_sig(const uint8_t message_hash[32],
                             const uint8_t A_bytes[32],
                             const zano_schnorr_sig *sig,
                             zano_generator_tag gen);

/**
 * Sign a double Schnorr: A = secret_a * gen0 and B = secret_b * gen1 under a
 * single Fiat-Shamir challenge.
 *
 * The reference instantiates only (gt_G, gt_G) and (gt_X, gt_G); gen1 must
 * therefore be ZANO_GEN_G.
 */
bool zano_generate_double_schnorr_sig(const uint8_t message_hash[32],
                                      const ge25519 *A,
                                      const bignum256modm secret_a,
                                      const ge25519 *B,
                                      const bignum256modm secret_b,
                                      zano_generator_tag gen0,
                                      zano_generator_tag gen1,
                                      zano_double_schnorr_sig *sig);

/**
 * Verify a double Schnorr.
 *
 * Mirrors the reference's asymmetry: A enters the transcript via add_point
 * and B via add_pub_key. Both are 32 compressed bytes, so the distinction is
 * cosmetic in the reference — it is preserved here only in the parameter
 * shapes, not in the hashed bytes.
 */
bool zano_verify_double_schnorr_sig(const uint8_t message_hash[32],
                                    const uint8_t A_bytes[32],
                                    const uint8_t B_bytes[32],
                                    const zano_double_schnorr_sig *sig,
                                    zano_generator_tag gen0,
                                    zano_generator_tag gen1);

#endif /* ZANO_SCHNORR_H */
