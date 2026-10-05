/**
 * test_clsag_ggx.c — self-consistency + constant-validation harness for the
 * Zano CLSAG_GGX port.
 *
 * WHAT THIS PROVES
 *   1. The generator constants decode to the intended, mathematically valid
 *      values (prime-order curve point; 8 * (1/8) == 1 mod L).
 *   2. generate -> verify agrees: a signature built by this code verifies,
 *      and the Fiat-Shamir transcripts on both sides match.
 *   3. Tampering with any signature component makes verification fail.
 *
 * WHAT THIS DOES **NOT** PROVE
 *   Conformance to Zano. Both sides here are OUR code, so a shared
 *   misunderstanding of the protocol (wrong domain-separation tag, wrong
 *   transcript order, wrong 1/8 convention) passes every test below and is
 *   still rejected by the daemon. That requires differential testing against
 *   vectors produced by hyle-team/zano's own crypto library. This harness is
 *   the necessary first gate, not the sufficient one.
 *
 * White-box: includes the .c directly to reach the file-scope constants.
 *
 * Build (host):
 *   see build_test.sh in this directory
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deterministic RNG, replacing crypto/rand.c so runs are reproducible.
 * Must be declared before clsag_ggx.c's zano_random_scalar uses it. */
static uint32_t prng_state = 0x2026072Bu;
void random_buffer(uint8_t *buf, size_t len);
void random_buffer(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        prng_state ^= prng_state << 13;
        prng_state ^= prng_state >> 17;
        prng_state ^= prng_state << 5;
        buf[i] = (uint8_t)(prng_state & 0xFF);
    }
}

/* Host stub for the firmware fault handler pulled in by consteq.c. */
void tc_fault_handler(const char *msg);
void tc_fault_handler(const char *msg) {
    printf("FATAL: fault handler invoked: %s\n", msg ? msg : "(null)");
    abort();
}

#include "clsag_ggx.c"
#include "zano_generators.h"

#define RING_SIZE 8
#define REAL_IDX  3

static int failures = 0;
static int checks   = 0;

static void check(int cond, const char *what) {
    checks++;
    if (cond) {
        printf("  [ok]   %s\n", what);
    } else {
        printf("  [FAIL] %s\n", what);
        failures++;
    }
}

static void rand_scalar(bignum256modm s) {
    uint8_t b[64];
    random_buffer(b, 64);
    expand256_modm(s, b, 64);
}

/* ── Test 1: the constants my fix replaced ───────────────────────────── */

static void test_constants(void) {
    printf("\n[1] generator constants\n");

    check(zano_generators_init(), "zano_generators_init() succeeds");

    /* 1/8: multiply by 8 and expect exactly 1. */
    bignum256modm eight, prod, one;
    uint8_t eight_bytes[32] = {8};
    uint8_t one_bytes[32]   = {1};
    expand256_modm(eight, eight_bytes, 32);
    expand256_modm(one, one_bytes, 32);
    mul256_modm(prod, zano_scalar_1div8, eight);
    check(eq256_modm(prod, one) != 0, "8 * c_scalar_1div8 == 1 (mod L)");

    /* X: assert the decoded generator against the expected encoding stated
     * HERE, independently of the constant the implementation carries — a test
     * that reads its expectation out of the code under test proves nothing.
     * This value is derived from Zano crypto-sugar.h:1129. */
    static const uint8_t EXPECTED_X[32] = {
        0x3a, 0x25, 0xbc, 0xdb, 0x43, 0xf5, 0xd2, 0xc9,
        0xdd, 0x06, 0x3d, 0xc3, 0x9a, 0x9e, 0x09, 0x87,
        0xba, 0xfc, 0x6f, 0xcf, 0x2d, 0xf1, 0xbc, 0x76,
        0x32, 0x2d, 0x75, 0x88, 0x4a, 0x4a, 0x38, 0x20,
    };
    uint8_t repacked[32];
    ge25519_pack(repacked, &zano_point_X);
    check(memcmp(repacked, EXPECTED_X, 32) == 0,
          "c_point_X decodes to the expected Zano encoding");

    /* X must lie in the prime-order subgroup: L*X == identity. */
    static const uint8_t L_bytes[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };
    bignum256modm L_s;
    expand256_modm(L_s, L_bytes, 32);
    ge25519 LX;
    ge25519_scalarmult(&LX, &zano_point_X, L_s);
    uint8_t lx_packed[32], identity[32] = {1};
    ge25519_pack(lx_packed, &LX);
    check(memcmp(lx_packed, identity, 32) == 0, "L * c_point_X == identity");

    /* And must not be a small-order point. */
    ge25519 X8;
    ge25519_mul8(&X8, &zano_point_X);
    uint8_t x8_packed[32];
    ge25519_pack(x8_packed, &X8);
    check(memcmp(x8_packed, identity, 32) != 0, "8 * c_point_X != identity");
}

/* ── Test 2: build an algebraically valid ring, sign, verify ─────────── */

typedef struct {
    zano_ring_member ring[RING_SIZE];
    uint8_t   msg[32];
    ge25519   pseudo_amount_full, pseudo_asset_full;
    ge25519   key_image;
    uint8_t   ki_bytes[32], pc_bytes[32], pa_bytes[32];
    bignum256modm x_p, f, t;
} fixture;

static void build_fixture(fixture *fx) {
    memset(fx, 0, sizeof(*fx));
    random_buffer(fx->msg, 32);

    rand_scalar(fx->x_p);
    rand_scalar(fx->f);
    rand_scalar(fx->t);

    /* Real stealth address P = x_p * G */
    ge25519 P;
    ge25519_scalarmult_base_wrapper(&P, fx->x_p);

    /* Arbitrary but valid pseudo-out points. */
    bignum256modm s_a, s_b;
    rand_scalar(s_a);
    rand_scalar(s_b);
    ge25519_scalarmult_base_wrapper(&fx->pseudo_amount_full, s_a);
    ge25519_scalarmult_base_wrapper(&fx->pseudo_asset_full, s_b);

    /* Decoys: valid random points. */
    for (size_t i = 0; i < RING_SIZE; i++) {
        bignum256modm d;
        rand_scalar(d);
        ge25519_scalarmult_base_wrapper(&fx->ring[i].stealth_address_pt, d);

        ge25519 tmp, tmp8;
        rand_scalar(d);
        ge25519_scalarmult_base_wrapper(&tmp, d);
        ge25519_scalarmult(&tmp8, &tmp, zano_scalar_1div8);
        ge25519_pack(fx->ring[i].amount_commitment, &tmp8);

        rand_scalar(d);
        ge25519_scalarmult_base_wrapper(&tmp, d);
        ge25519_scalarmult(&tmp8, &tmp, zano_scalar_1div8);
        ge25519_pack(fx->ring[i].blinded_asset_id, &tmp8);
    }

    /* Real index must satisfy the relations the ring signature proves:
     *   P_real          = x_p * G
     *   A_full - pc_full = f * G
     *   T_full - pa_full = t * X                                       */
    ge25519_copy(&fx->ring[REAL_IDX].stealth_address_pt, &P);

    ge25519 fG, A_full, A_div8;
    ge25519_scalarmult_base_wrapper(&fG, fx->f);
    ge25519_add(&A_full, &fx->pseudo_amount_full, &fG, 0);
    ge25519_scalarmult(&A_div8, &A_full, zano_scalar_1div8);
    ge25519_pack(fx->ring[REAL_IDX].amount_commitment, &A_div8);

    ge25519 tX, T_full, T_div8;
    ge25519_scalarmult(&tX, &zano_point_X, fx->t);
    ge25519_add(&T_full, &fx->pseudo_asset_full, &tX, 0);
    ge25519_scalarmult(&T_div8, &T_full, zano_scalar_1div8);
    ge25519_pack(fx->ring[REAL_IDX].blinded_asset_id, &T_div8);

    /* key image = x_p * hp(P_real) */
    ge25519 hpP;
    zano_hp(&hpP, &P);
    ge25519_scalarmult(&fx->key_image, &hpP, fx->x_p);
    ge25519_pack(fx->ki_bytes, &fx->key_image);

    /* verify-side pseudo-outs are premultiplied by 1/8 */
    ge25519 pc8, pa8;
    ge25519_scalarmult(&pc8, &fx->pseudo_amount_full, zano_scalar_1div8);
    ge25519_scalarmult(&pa8, &fx->pseudo_asset_full, zano_scalar_1div8);
    ge25519_pack(fx->pc_bytes, &pc8);
    ge25519_pack(fx->pa_bytes, &pa8);
}

static bool do_sign(fixture *fx, zano_clsag_ggx_sig *sig,
                    bignum256modm *rg, bignum256modm *rx) {
    memset(sig, 0, sizeof(*sig));
    sig->r_g = rg;
    sig->r_x = rx;
    return zano_generate_clsag_ggx(
        fx->msg, fx->ring, RING_SIZE,
        &fx->pseudo_amount_full, &fx->pseudo_asset_full, &fx->key_image,
        fx->x_p, fx->f, fx->t, REAL_IDX, sig);
}

static bool do_verify(fixture *fx, const zano_clsag_ggx_sig *sig) {
    return zano_verify_clsag_ggx(
        fx->msg, fx->ring, RING_SIZE,
        fx->pc_bytes, fx->pa_bytes, fx->ki_bytes, sig);
}

static void test_roundtrip(void) {
    printf("\n[2] sign -> verify round-trip (ring=%d, real=%d)\n",
           RING_SIZE, REAL_IDX);

    fixture fx;
    build_fixture(&fx);

    bignum256modm rg[RING_SIZE], rx[RING_SIZE];
    zano_clsag_ggx_sig sig;

    check(do_sign(&fx, &sig, rg, rx), "generate_CLSAG_GGX returns true");
    check(do_verify(&fx, &sig), "verify_CLSAG_GGX accepts a valid signature");
}

/* ── Test 3: tampering must be rejected ──────────────────────────────── */

static void test_negative(void) {
    printf("\n[3] negative tests (each must be REJECTED)\n");

    fixture fx;
    bignum256modm rg[RING_SIZE], rx[RING_SIZE];
    zano_clsag_ggx_sig sig;

    build_fixture(&fx);
    if (!do_sign(&fx, &sig, rg, rx)) {
        printf("  [FAIL] setup: could not sign\n");
        failures++; checks++;
        return;
    }

    /* flipped message */
    uint8_t saved = fx.msg[0];
    fx.msg[0] ^= 0x01;
    check(!do_verify(&fx, &sig), "tampered message rejected");
    fx.msg[0] = saved;

    /* perturbed challenge */
    bignum256modm saved_c;
    copy256_modm(saved_c, sig.c);
    bignum256modm one;
    uint8_t one_b[32] = {1};
    expand256_modm(one, one_b, 32);
    add256_modm(sig.c, sig.c, one);
    check(!do_verify(&fx, &sig), "tampered challenge c rejected");
    copy256_modm(sig.c, saved_c);

    /* perturbed response */
    bignum256modm saved_r;
    copy256_modm(saved_r, sig.r_g[0]);
    add256_modm(sig.r_g[0], sig.r_g[0], one);
    check(!do_verify(&fx, &sig), "tampered response r_g[0] rejected");
    copy256_modm(sig.r_g[0], saved_r);

    /* wrong key image */
    uint8_t saved_ki = fx.ki_bytes[0];
    fx.ki_bytes[0] ^= 0x01;
    check(!do_verify(&fx, &sig), "tampered key image rejected");
    fx.ki_bytes[0] = saved_ki;

    /* swapped auxiliary key images */
    uint8_t tmp[32];
    memcpy(tmp, sig.K1, 32);
    memcpy(sig.K1, sig.K2, 32);
    memcpy(sig.K2, tmp, 32);
    check(!do_verify(&fx, &sig), "swapped K1/K2 rejected");
    memcpy(tmp, sig.K1, 32);
    memcpy(sig.K1, sig.K2, 32);
    memcpy(sig.K2, tmp, 32);

    /* sanity: after restoring everything it must verify again */
    check(do_verify(&fx, &sig), "signature still valid after restore");
}

int main(void) {
    printf("=== Zano CLSAG_GGX self-consistency harness ===\n");
    test_constants();
    test_roundtrip();
    test_negative();

    printf("\n=== %d/%d checks passed ===\n", checks - failures, checks);
    if (failures) {
        printf("RESULT: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("RESULT: all self-consistency checks passed\n");
    printf("NOTE: this proves internal consistency only — NOT Zano conformance.\n");
    printf("      Conformance is proven separately by test_conformance.c, which\n");
    printf("      verifies signatures produced by the real Zano reference.\n");
    return 0;
}
