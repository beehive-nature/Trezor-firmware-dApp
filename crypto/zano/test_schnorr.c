/**
 * test_schnorr.c — conformance + self-consistency tests for schnorr.c.
 *
 * Stage 1 (CONFORMANCE, inbound): our verify must accept signatures produced
 *   by hyle-team/zano's own zarcanum.h, and must reject tampered ones.
 * Stage 2 (self-consistency): our sign -> our verify, plus negative controls.
 * Stage 3 (CONFORMANCE, outbound): emit signatures WE produced to JSON so the
 *   reference implementation can verify them (schnorr_crosscheck.cpp). For a
 *   signing device this direction is the one that matters — the network must
 *   accept what we emit.
 *
 * Usage: test_schnorr [out.json]
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deterministic RNG so runs are reproducible. Declared before schnorr.c's
 * dependency on it is pulled in. */
static uint32_t prng = 0x5EED1234u;
void random_buffer(uint8_t *buf, size_t len);
void random_buffer(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        prng ^= prng << 13;
        prng ^= prng >> 17;
        prng ^= prng << 5;
        buf[i] = (uint8_t)(prng & 0xFF);
    }
}
void tc_fault_handler(const char *msg);
void tc_fault_handler(const char *msg) {
    printf("FATAL: %s\n", msg ? msg : "(null)");
    abort();
}

#include "schnorr.h"
#include "zano_generators.h"
#include "zano_schnorr_vectors.h"

static int failures = 0;
static int checks = 0;

static void ck(int cond, const char *what) {
    checks++;
    if (cond) {
        printf("  [ok]   %s\n", what);
    } else {
        printf("  [FAIL] %s\n", what);
        failures++;
    }
}

static void hexout(FILE *f, const uint8_t *b) {
    for (int i = 0; i < 32; i++) fprintf(f, "%02x", b[i]);
}

int main(int argc, char **argv) {
    printf("=== Zano Schnorr: conformance vs reference ===\n");

    if (!zano_generators_init()) {
        printf("FATAL: generators failed to initialise\n");
        return 1;
    }

    /* ---- Stage 1: inbound conformance ---- */
    printf("\n[1] our verify accepts REFERENCE signatures\n");
    for (int i = 0; i < ZSV_SINGLE_COUNT; i++) {
        const zsv_single_t *v = &ZSV_SINGLE[i];
        zano_schnorr_sig sig;
        expand256_modm(sig.c, v->c, 32);
        expand256_modm(sig.y, v->y, 32);
        bool ok = zano_verify_schnorr_sig(v->m, v->A, &sig,
                                          (zano_generator_tag)v->gen);
        ck(ok, v->name);

        /* negative control: tampering must break it */
        if (ok) {
            uint8_t m2[32];
            memcpy(m2, v->m, 32);
            m2[0] ^= 0x01;
            ck(!zano_verify_schnorr_sig(m2, v->A, &sig,
                                        (zano_generator_tag)v->gen),
               "  ^ tampered message rejected");
        }
    }
    for (int i = 0; i < ZSV_DOUBLE_COUNT; i++) {
        const zsv_double_t *v = &ZSV_DOUBLE[i];
        zano_double_schnorr_sig sig;
        expand256_modm(sig.c, v->c, 32);
        expand256_modm(sig.y0, v->y0, 32);
        expand256_modm(sig.y1, v->y1, 32);
        bool ok = zano_verify_double_schnorr_sig(v->m, v->A, v->B, &sig,
                                                 (zano_generator_tag)v->gen0,
                                                 (zano_generator_tag)v->gen1);
        ck(ok, v->name);
        if (ok) {
            zano_double_schnorr_sig bad = sig;
            bignum256modm one;
            uint8_t one_b[32] = {1};
            expand256_modm(one, one_b, 32);
            add256_modm(bad.y0, bad.y0, one);
            ck(!zano_verify_double_schnorr_sig(v->m, v->A, v->B, &bad,
                                               (zano_generator_tag)v->gen0,
                                               (zano_generator_tag)v->gen1),
               "  ^ tampered y0 rejected");
        }
    }

    /* ---- Stage 2 + 3: our own signatures ---- */
    printf("\n[2] our sign -> our verify (and emit for reference check)\n");

    FILE *out = NULL;
    if (argc > 1) {
        out = fopen(argv[1], "w");
        if (!out) {
            printf("  [FAIL] cannot open %s\n", argv[1]);
            failures++;
        }
    }
    if (out) fprintf(out, "{\n  \"schnorr\": [\n");

    const zano_generator_tag gens[2] = {ZANO_GEN_G, ZANO_GEN_X};
    int emitted = 0;
    for (int gi = 0; gi < 2; gi++) {
        for (int k = 0; k < 2; k++) {
            bignum256modm a;
            zano_random_scalar(a);
            ge25519 A;
            if (gens[gi] == ZANO_GEN_G) {
                ge25519_scalarmult_base_wrapper(&A, a);
            } else {
                ge25519_scalarmult(&A, &zano_point_X, a);
            }
            uint8_t m[32], A_b[32];
            random_buffer(m, 32);
            ge25519_pack(A_b, &A);

            zano_schnorr_sig sig;
            char label[64];
            snprintf(label, sizeof(label), "ours_single_%s_%d",
                     gens[gi] == ZANO_GEN_G ? "G" : "X", k);
            ck(zano_generate_schnorr_sig(m, &A, a, gens[gi], &sig), label);
            ck(zano_verify_schnorr_sig(m, A_b, &sig, gens[gi]),
               "  ^ verifies under our own verifier");

            if (out) {
                uint8_t cb[32], yb[32];
                contract256_modm(cb, sig.c);
                contract256_modm(yb, sig.y);
                if (emitted++) fprintf(out, ",\n");
                fprintf(out, "    {\"gen\": %d, \"m\": \"", (int)gens[gi]);
                hexout(out, m);
                fprintf(out, "\", \"A\": \"");
                hexout(out, A_b);
                fprintf(out, "\", \"c\": \"");
                hexout(out, cb);
                fprintf(out, "\", \"y\": \"");
                hexout(out, yb);
                fprintf(out, "\"}");
            }
        }
    }
    if (out) fprintf(out, "\n  ],\n  \"double_schnorr\": [\n");

    emitted = 0;
    for (int gi = 0; gi < 2; gi++) {
        bignum256modm a, b;
        zano_random_scalar(a);
        zano_random_scalar(b);
        ge25519 A, B;
        if (gens[gi] == ZANO_GEN_G) {
            ge25519_scalarmult_base_wrapper(&A, a);
        } else {
            ge25519_scalarmult(&A, &zano_point_X, a);
        }
        ge25519_scalarmult_base_wrapper(&B, b);

        uint8_t m[32], A_b[32], B_b[32];
        random_buffer(m, 32);
        ge25519_pack(A_b, &A);
        ge25519_pack(B_b, &B);

        zano_double_schnorr_sig sig;
        char label[64];
        snprintf(label, sizeof(label), "ours_double_%sG",
                 gens[gi] == ZANO_GEN_G ? "G" : "X");
        ck(zano_generate_double_schnorr_sig(m, &A, a, &B, b, gens[gi],
                                            ZANO_GEN_G, &sig), label);
        ck(zano_verify_double_schnorr_sig(m, A_b, B_b, &sig, gens[gi],
                                          ZANO_GEN_G),
           "  ^ verifies under our own verifier");

        if (out) {
            uint8_t cb[32], y0b[32], y1b[32];
            contract256_modm(cb, sig.c);
            contract256_modm(y0b, sig.y0);
            contract256_modm(y1b, sig.y1);
            if (emitted++) fprintf(out, ",\n");
            fprintf(out, "    {\"gen0\": %d, \"gen1\": 1, \"m\": \"", (int)gens[gi]);
            hexout(out, m);
            fprintf(out, "\", \"A\": \"");
            hexout(out, A_b);
            fprintf(out, "\", \"B\": \"");
            hexout(out, B_b);
            fprintf(out, "\", \"c\": \"");
            hexout(out, cb);
            fprintf(out, "\", \"y0\": \"");
            hexout(out, y0b);
            fprintf(out, "\", \"y1\": \"");
            hexout(out, y1b);
            fprintf(out, "\"}");
        }
    }
    if (out) {
        fprintf(out, "\n  ]\n}\n");
        fclose(out);
        printf("\n  wrote our signatures to %s for reference cross-check\n",
               argv[1]);
    }

    /* ---- misuse guards ---- */
    printf("\n[3] misuse guards\n");
    {
        bignum256modm a;
        zano_random_scalar(a);
        ge25519 A;
        ge25519_scalarmult_base_wrapper(&A, a);
        uint8_t m[32] = {0};
        zano_schnorr_sig sig;
        /* wrong generator for the point: A = a*G but we claim gt_X */
        ck(!zano_generate_schnorr_sig(m, &A, a, ZANO_GEN_X, &sig),
           "sign rejects A that does not match secret*gen");
        /* unsupported generator tag */
        ck(!zano_generate_schnorr_sig(m, &A, a, (zano_generator_tag)2, &sig),
           "sign rejects unsupported generator tag");
        /* double sig requires gen1 == G */
        zano_double_schnorr_sig d;
        ck(!zano_generate_double_schnorr_sig(m, &A, a, &A, a, ZANO_GEN_G,
                                             ZANO_GEN_X, &d),
           "double sign rejects gen1 != G");
    }

    printf("\n=== %d/%d checks passed ===\n", checks - failures, checks);
    if (failures) {
        printf("RESULT: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("RESULT: our verifier accepts every reference signature.\n");
    return 0;
}
