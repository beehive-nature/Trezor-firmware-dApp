/**
 * schnorr.c — Zano generic Schnorr / double-Schnorr signatures.
 * See schnorr.h. Reference: hyle-team/zano src/crypto/zarcanum.h.
 *
 * Transcripts, verbatim from the reference:
 *
 *   single:  c = H( m , A , R )                       R  = r  * gen
 *            y = r - c*a
 *   verify:  c == H( m , A , y*gen + c*A )
 *
 *   double:  c = H( m , A , B , R0 , R1 )             R0 = r0 * gen0
 *            y0 = r0 - c*a                            R1 = r1 * gen1
 *            y1 = r1 - c*b
 *   verify:  c == H( m , A , B , y0*gen0 + c*A , y1*gen1 + c*B )
 *
 * m is appended RAW (add_hash), unlike CLSAG_GGX which reduces it mod L.
 * H is Keccak-256 reduced mod L (calc_hash).
 *
 * SPDX-License-Identifier: MIT
 */

#include "schnorr.h"

#include "zano_generators.h"
#include "zano_transcript.h"

/* Single sig hashes 3 items, double hashes 5. */
#define ZANO_SCHNORR_ITEMS 5

/// r = a*b is not what we want: the reference's assign_mulsub(c, a, r)
/// computes r - c*a (sc_mulsub(s,a,b,c) = c - a*b). Spelled out here so the
/// sign convention cannot be misread.
static void schnorr_response(bignum256modm out, const bignum256modm c,
                             const bignum256modm secret, const bignum256modm r) {
    bignum256modm c_secret;
    mul256_modm(c_secret, c, secret);
    sub256_modm(out, r, c_secret);  // y = r - c*secret
}

/// Multiply by the generator named by `gen`. Returns false if unsupported.
static bool gen_mul(ge25519 *out, zano_generator_tag gen, const bignum256modm s) {
    switch (gen) {
        case ZANO_GEN_G:
            ge25519_scalarmult_base_wrapper(out, s);
            return true;
        case ZANO_GEN_X:
            ge25519_scalarmult(out, &zano_point_X, s);
            return true;
        default:
            return false;
    }
}

/// A scalar is canonical iff contracting and re-expanding is the identity.
/// Mirrors the reference's sc_check-based is_reduced() guard, which rejects
/// non-canonical scalars before they reach the verification equation.
static bool scalar_is_canonical(const bignum256modm s) {
    uint8_t packed[32];
    bignum256modm reparsed;
    uint8_t repacked[32];
    contract256_modm(packed, s);
    expand256_modm(reparsed, packed, 32);
    contract256_modm(repacked, reparsed);
    return memcmp(packed, repacked, 32) == 0;
}

bool zano_generate_schnorr_sig(const uint8_t message_hash[32],
                               const ge25519 *A,
                               const bignum256modm secret_a,
                               zano_generator_tag gen,
                               zano_schnorr_sig *sig) {
    if (!message_hash || !A || !sig) return false;
    if (!zano_generators_init()) return false;

    /* The reference only checks A == secret_a * gen under NDEBUG-off. Do it
     * always: it is one scalarmult against a proof that would otherwise be
     * silently unverifiable, and it catches caller error at the source. */
    ge25519 expect;
    if (!gen_mul(&expect, gen, secret_a)) return false;
    uint8_t expect_b[32], a_b[32];
    ge25519_pack(expect_b, &expect);
    ge25519_pack(a_b, A);
    if (memcmp(expect_b, a_b, 32) != 0) return false;

    bignum256modm r;
    zano_random_scalar(r);

    ge25519 R;
    if (!gen_mul(&R, gen, r)) return false;

    uint8_t   buf[ZANO_SCHNORR_ITEMS * 32];
    zano_hs_t hsc;
    zano_hs_init(&hsc, buf, sizeof(buf));
    zano_hs_add(&hsc, message_hash);  // add_hash(m) — RAW
    zano_hs_add_point(&hsc, A);
    zano_hs_add_point(&hsc, &R);
    if (!zano_hs_hash_reduce(sig->c, &hsc)) return false;

    schnorr_response(sig->y, sig->c, secret_a, r);
    return true;
}

bool zano_verify_schnorr_sig(const uint8_t message_hash[32],
                             const uint8_t A_bytes[32],
                             const zano_schnorr_sig *sig,
                             zano_generator_tag gen) {
    if (!message_hash || !A_bytes || !sig) return false;
    if (!zano_generators_init()) return false;
    if (!scalar_is_canonical(sig->c) || !scalar_is_canonical(sig->y)) return false;

    ge25519 A;
    if (!ge25519_unpack_vartime(&A, A_bytes)) return false;

    /* R' = y*gen + c*A */
    ge25519 y_gen, c_A, R;
    if (!gen_mul(&y_gen, gen, sig->y)) return false;
    ge25519_scalarmult(&c_A, &A, sig->c);
    ge25519_add(&R, &y_gen, &c_A, 0);

    uint8_t   buf[ZANO_SCHNORR_ITEMS * 32];
    zano_hs_t hsc;
    zano_hs_init(&hsc, buf, sizeof(buf));
    zano_hs_add(&hsc, message_hash);
    zano_hs_add(&hsc, A_bytes);  // add_pub_key(A) — the wire bytes
    zano_hs_add_point(&hsc, &R);

    bignum256modm c_expected;
    if (!zano_hs_hash_reduce(c_expected, &hsc)) return false;
    return eq256_modm(c_expected, sig->c) != 0;
}

bool zano_generate_double_schnorr_sig(const uint8_t message_hash[32],
                                      const ge25519 *A,
                                      const bignum256modm secret_a,
                                      const ge25519 *B,
                                      const bignum256modm secret_b,
                                      zano_generator_tag gen0,
                                      zano_generator_tag gen1,
                                      zano_double_schnorr_sig *sig) {
    if (!message_hash || !A || !B || !sig) return false;
    if (!zano_generators_init()) return false;
    /* The reference instantiates only (G,G) and (X,G). */
    if (gen1 != ZANO_GEN_G) return false;

    ge25519 expect;
    uint8_t expect_b[32], p_b[32];
    if (!gen_mul(&expect, gen0, secret_a)) return false;
    ge25519_pack(expect_b, &expect);
    ge25519_pack(p_b, A);
    if (memcmp(expect_b, p_b, 32) != 0) return false;
    if (!gen_mul(&expect, gen1, secret_b)) return false;
    ge25519_pack(expect_b, &expect);
    ge25519_pack(p_b, B);
    if (memcmp(expect_b, p_b, 32) != 0) return false;

    bignum256modm r0, r1;
    zano_random_scalar(r0);
    zano_random_scalar(r1);

    ge25519 R0, R1;
    if (!gen_mul(&R0, gen0, r0)) return false;
    if (!gen_mul(&R1, gen1, r1)) return false;

    uint8_t   buf[ZANO_SCHNORR_ITEMS * 32];
    zano_hs_t hsc;
    zano_hs_init(&hsc, buf, sizeof(buf));
    zano_hs_add(&hsc, message_hash);
    zano_hs_add_point(&hsc, A);
    zano_hs_add_point(&hsc, B);
    zano_hs_add_point(&hsc, &R0);
    zano_hs_add_point(&hsc, &R1);
    if (!zano_hs_hash_reduce(sig->c, &hsc)) return false;

    schnorr_response(sig->y0, sig->c, secret_a, r0);
    schnorr_response(sig->y1, sig->c, secret_b, r1);
    return true;
}

bool zano_verify_double_schnorr_sig(const uint8_t message_hash[32],
                                    const uint8_t A_bytes[32],
                                    const uint8_t B_bytes[32],
                                    const zano_double_schnorr_sig *sig,
                                    zano_generator_tag gen0,
                                    zano_generator_tag gen1) {
    if (!message_hash || !A_bytes || !B_bytes || !sig) return false;
    if (!zano_generators_init()) return false;
    if (gen1 != ZANO_GEN_G) return false;
    if (!scalar_is_canonical(sig->c) || !scalar_is_canonical(sig->y0) ||
        !scalar_is_canonical(sig->y1)) {
        return false;
    }

    ge25519 A, B;
    if (!ge25519_unpack_vartime(&A, A_bytes)) return false;
    if (!ge25519_unpack_vartime(&B, B_bytes)) return false;

    ge25519 y_gen, c_P, R0, R1;
    if (!gen_mul(&y_gen, gen0, sig->y0)) return false;
    ge25519_scalarmult(&c_P, &A, sig->c);
    ge25519_add(&R0, &y_gen, &c_P, 0);

    if (!gen_mul(&y_gen, gen1, sig->y1)) return false;
    ge25519_scalarmult(&c_P, &B, sig->c);
    ge25519_add(&R1, &y_gen, &c_P, 0);

    uint8_t   buf[ZANO_SCHNORR_ITEMS * 32];
    zano_hs_t hsc;
    zano_hs_init(&hsc, buf, sizeof(buf));
    zano_hs_add(&hsc, message_hash);
    zano_hs_add(&hsc, A_bytes);
    zano_hs_add(&hsc, B_bytes);
    zano_hs_add_point(&hsc, &R0);
    zano_hs_add_point(&hsc, &R1);

    bignum256modm c_expected;
    if (!zano_hs_hash_reduce(c_expected, &hsc)) return false;
    return eq256_modm(c_expected, sig->c) != 0;
}
