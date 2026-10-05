/**
 * test_conformance.c — DIFFERENTIAL test of the CLSAG_GGX firmware port
 * against vectors produced by the real Zano reference implementation.
 *
 * THIS is the test that means something. The self-consistency harness
 * (test_clsag_ggx.c) exercises our generate against our verify, so a shared
 * misunderstanding of the protocol passes it. Here, every signature was
 * produced by hyle-team/zano's own clsag.cpp. If our verify accepts them, our
 * transcript, domain-separation tags, hash function, 1/8 conventions and
 * generator constants all match the reference bit-for-bit.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Host stubs for firmware-only dependencies pulled in via consteq.c. */
void tc_fault_handler(const char *msg);
void tc_fault_handler(const char *msg) {
    printf("FATAL: fault handler: %s\n", msg ? msg : "(null)");
    abort();
}
void random_buffer(uint8_t *buf, size_t len);
void random_buffer(uint8_t *buf, size_t len) { memset(buf, 0x42, len); }

#include "clsag_ggx.c"
#include "zano_vectors.h"

static int failures = 0;

static void run_vector(const zano_vector_t *v) {
    const size_t n = v->ring_size;

    zano_ring_member *ring = calloc(n, sizeof(*ring));
    bignum256modm *r_g = calloc(n, sizeof(*r_g));
    bignum256modm *r_x = calloc(n, sizeof(*r_x));
    if (!ring || !r_g || !r_x) {
        printf("  [FAIL] %-24s allocation failed\n", v->name);
        failures++;
        goto done;
    }

    for (size_t i = 0; i < n; i++) {
        /* stealth address is stored decompressed in our ring struct */
        if (!ge25519_unpack_vartime(&ring[i].stealth_address_pt,
                                    v->ring_stealth[i])) {
            printf("  [FAIL] %-24s ring[%zu] stealth address does not decompress\n",
                   v->name, i);
            failures++;
            goto done;
        }
        memcpy(ring[i].amount_commitment, v->ring_commitment[i], 32);
        memcpy(ring[i].blinded_asset_id, v->ring_asset[i], 32);

        expand256_modm(r_g[i], v->sig_r_g[i], 32);
        expand256_modm(r_x[i], v->sig_r_x[i], 32);
    }

    zano_clsag_ggx_sig sig;
    memset(&sig, 0, sizeof(sig));
    expand256_modm(sig.c, v->sig_c, 32);
    sig.r_g = r_g;
    sig.r_x = r_x;
    memcpy(sig.K1, v->sig_K1, 32);
    memcpy(sig.K2, v->sig_K2, 32);

    bool ok = zano_verify_clsag_ggx(v->message_hash, ring, n,
                                    v->pseudo_out_amount_1div8,
                                    v->pseudo_out_asset_1div8,
                                    v->key_image, &sig);
    if (ok) {
        printf("  [ok]   %-24s ring=%-3zu ACCEPTED reference signature\n",
               v->name, n);
    } else {
        printf("  [FAIL] %-24s ring=%-3zu REJECTED a valid Zano signature\n",
               v->name, n);
        failures++;
    }

    /* Negative control: a tampered challenge must be rejected, otherwise a
     * verify that returns true unconditionally would "pass" the test above. */
    if (ok) {
        bignum256modm one, saved;
        uint8_t one_b[32] = {1};
        expand256_modm(one, one_b, 32);
        copy256_modm(saved, sig.c);
        add256_modm(sig.c, sig.c, one);
        bool bad = zano_verify_clsag_ggx(v->message_hash, ring, n,
                                         v->pseudo_out_amount_1div8,
                                         v->pseudo_out_asset_1div8,
                                         v->key_image, &sig);
        copy256_modm(sig.c, saved);
        if (bad) {
            printf("  [FAIL] %-24s accepted a TAMPERED signature\n", v->name);
            failures++;
        }
    }

done:
    free(ring);
    free(r_g);
    free(r_x);
}

int main(void) {
    printf("=== CLSAG_GGX CONFORMANCE: firmware port vs Zano reference ===\n");
    printf("%d vectors, all signatures produced by hyle-team/zano clsag.cpp\n\n",
           ZV_COUNT);

    for (int i = 0; i < ZV_COUNT; i++) {
        run_vector(&ZANO_VECTORS[i]);
    }

    printf("\n");
    if (failures) {
        printf("RESULT: %d FAILURE(S) — the port is NOT conformant with Zano.\n",
               failures);
        return 1;
    }
    printf("RESULT: all %d reference signatures verified by the firmware port.\n",
           ZV_COUNT);
    printf("The port's transcript, DS tags, hash, 1/8 conventions and\n");
    printf("generator constants match the Zano reference implementation.\n");
    return 0;
}
