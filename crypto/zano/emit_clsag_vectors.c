/**
 * emit_clsag_vectors.c — emit CLSAG_GGX signatures produced by THIS port, in a
 * form hyle-team/zano's own verify_CLSAG_GGX can be asked to check.
 *
 * WHY THIS FILE EXISTS
 *   test_clsag_ggx.c states its own limit plainly: both sides of it are our
 *   code, so a shared misunderstanding of the protocol passes every check and
 *   is still rejected by the daemon. test_conformance.c closes half the gap —
 *   OUR verifier accepts the REFERENCE's signatures. This closes the other
 *   half, which is the half that governs spending: does the REFERENCE accept
 *   OURS? A device that signs something the network rejects is useless; one
 *   that signs something subtly wrong is worse than useless.
 *
 * Deliberately varies ring size and the real signer's position, including the
 * first and last slots, because an off-by-one in the ring walk is invisible
 * when the real index sits comfortably in the middle.
 *
 * White-box: includes the .c directly to reach file-scope constants, matching
 * test_clsag_ggx.c.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deterministic RNG so a run is reproducible and a failure is re-checkable.
 * Must precede clsag_ggx.c, whose zano_random_scalar calls it. */
static uint32_t prng_state = 0x5A4E4F21u;   /* "ZNO!" */
void random_buffer(uint8_t *buf, size_t len);
void random_buffer(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        prng_state ^= prng_state << 13;
        prng_state ^= prng_state >> 17;
        prng_state ^= prng_state << 5;
        buf[i] = (uint8_t)(prng_state & 0xFF);
    }
}

void tc_fault_handler(const char *msg);
void tc_fault_handler(const char *msg) {
    printf("FATAL: fault handler invoked: %s\n", msg ? msg : "(null)");
    abort();
}

#include "clsag_ggx.c"
#include "zano_generators.h"

#define MAX_RING 16

static void rand_scalar(bignum256modm s) {
    uint8_t b[64];
    random_buffer(b, 64);
    expand256_modm(s, b, 64);
}

static void hexout(FILE *f, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
}

static void scalar_hex(FILE *f, const bignum256modm s) {
    uint8_t b[32];
    contract256_modm(b, s);
    hexout(f, b, 32);
}

/* One signing case, mirroring build_fixture() in test_clsag_ggx.c exactly:
 *   P_real           = x_p * G
 *   A_full - pc_full = f * G
 *   T_full - pa_full = t * X
 *   ki               = x_p * hp(P_real)
 * Ring members carry A and T premultiplied by 1/8; P is not. Verify-side
 * pseudo-outs are premultiplied by 1/8, generate-side are not. */
static int emit_case(FILE *out, const char *name, size_t ring_size, size_t real_idx,
                     int first) {
    uint8_t  msg[32];
    zano_ring_member ring[MAX_RING];
    ge25519  pseudo_amount_full, pseudo_asset_full, key_image;
    uint8_t  ki_bytes[32], pc_bytes[32], pa_bytes[32];
    uint8_t  sa_bytes[MAX_RING][32];
    bignum256modm x_p, f, t;

    memset(ring, 0, sizeof(ring));
    random_buffer(msg, 32);
    rand_scalar(x_p); rand_scalar(f); rand_scalar(t);

    ge25519 P;
    ge25519_scalarmult_base_wrapper(&P, x_p);

    bignum256modm s_a, s_b;
    rand_scalar(s_a); rand_scalar(s_b);
    ge25519_scalarmult_base_wrapper(&pseudo_amount_full, s_a);
    ge25519_scalarmult_base_wrapper(&pseudo_asset_full,  s_b);

    for (size_t i = 0; i < ring_size; i++) {
        bignum256modm d;
        ge25519 tmp, tmp8;
        rand_scalar(d);
        ge25519_scalarmult_base_wrapper(&ring[i].stealth_address_pt, d);
        rand_scalar(d);
        ge25519_scalarmult_base_wrapper(&tmp, d);
        ge25519_scalarmult(&tmp8, &tmp, zano_scalar_1div8);
        ge25519_pack(ring[i].amount_commitment, &tmp8);
        rand_scalar(d);
        ge25519_scalarmult_base_wrapper(&tmp, d);
        ge25519_scalarmult(&tmp8, &tmp, zano_scalar_1div8);
        ge25519_pack(ring[i].blinded_asset_id, &tmp8);
    }

    ge25519_copy(&ring[real_idx].stealth_address_pt, &P);

    ge25519 fG, A_full, A_div8;
    ge25519_scalarmult_base_wrapper(&fG, f);
    ge25519_add(&A_full, &pseudo_amount_full, &fG, 0);
    ge25519_scalarmult(&A_div8, &A_full, zano_scalar_1div8);
    ge25519_pack(ring[real_idx].amount_commitment, &A_div8);

    ge25519 tX, T_full, T_div8;
    ge25519_scalarmult(&tX, &zano_point_X, t);
    ge25519_add(&T_full, &pseudo_asset_full, &tX, 0);
    ge25519_scalarmult(&T_div8, &T_full, zano_scalar_1div8);
    ge25519_pack(ring[real_idx].blinded_asset_id, &T_div8);

    ge25519 hpP;
    zano_hp(&hpP, &P);
    ge25519_scalarmult(&key_image, &hpP, x_p);
    ge25519_pack(ki_bytes, &key_image);

    ge25519 pc8, pa8;
    ge25519_scalarmult(&pc8, &pseudo_amount_full, zano_scalar_1div8);
    ge25519_scalarmult(&pa8, &pseudo_asset_full,  zano_scalar_1div8);
    ge25519_pack(pc_bytes, &pc8);
    ge25519_pack(pa_bytes, &pa8);

    /* The reference takes P as a compressed public_key. */
    for (size_t i = 0; i < ring_size; i++)
        ge25519_pack(sa_bytes[i], &ring[i].stealth_address_pt);

    bignum256modm rg[MAX_RING], rx[MAX_RING];
    zano_clsag_ggx_sig sig;
    memset(&sig, 0, sizeof(sig));
    sig.r_g = rg;
    sig.r_x = rx;

    if (!zano_generate_clsag_ggx(msg, ring, ring_size,
                                 &pseudo_amount_full, &pseudo_asset_full, &key_image,
                                 x_p, f, t, real_idx, &sig)) {
        fprintf(stderr, "FATAL: our own signer refused case %s\n", name);
        return 0;
    }
    /* Never emit something our own verifier rejects — that would blame the
     * reference for a defect on this side. */
    if (!zano_verify_clsag_ggx(msg, ring, ring_size, pc_bytes, pa_bytes,
                               ki_bytes, &sig)) {
        fprintf(stderr, "FATAL: our signature fails our own verifier: %s\n", name);
        return 0;
    }

    if (!first) fprintf(out, ",\n");
    fprintf(out, "    {\"name\":\"%s\",\"ring_size\":%zu,\"real_idx\":%zu,\n",
            name, ring_size, real_idx);
    fprintf(out, "     \"m\":\"");            hexout(out, msg, 32);      fprintf(out, "\",\n");
    fprintf(out, "     \"ki\":\"");           hexout(out, ki_bytes, 32); fprintf(out, "\",\n");
    fprintf(out, "     \"pseudo_out_amount_commitment\":\""); hexout(out, pc_bytes, 32); fprintf(out, "\",\n");
    fprintf(out, "     \"pseudo_out_asset_id\":\"");          hexout(out, pa_bytes, 32); fprintf(out, "\",\n");

    fprintf(out, "     \"ring\":[");
    for (size_t i = 0; i < ring_size; i++) {
        fprintf(out, "%s\n       {\"P\":\"", i ? "," : "");
        hexout(out, sa_bytes[i], 32);
        fprintf(out, "\",\"A\":\"");
        hexout(out, ring[i].amount_commitment, 32);
        fprintf(out, "\",\"T\":\"");
        hexout(out, ring[i].blinded_asset_id, 32);
        fprintf(out, "\"}");
    }
    fprintf(out, "\n     ],\n");

    fprintf(out, "     \"c\":\"");  scalar_hex(out, sig.c);  fprintf(out, "\",\n");
    fprintf(out, "     \"r_g\":[");
    for (size_t i = 0; i < ring_size; i++) {
        fprintf(out, "%s\"", i ? "," : ""); scalar_hex(out, rg[i]); fprintf(out, "\"");
    }
    fprintf(out, "],\n     \"r_x\":[");
    for (size_t i = 0; i < ring_size; i++) {
        fprintf(out, "%s\"", i ? "," : ""); scalar_hex(out, rx[i]); fprintf(out, "\"");
    }
    fprintf(out, "],\n");
    fprintf(out, "     \"K1\":\""); hexout(out, sig.K1, 32); fprintf(out, "\",\n");
    fprintf(out, "     \"K2\":\""); hexout(out, sig.K2, 32); fprintf(out, "\"}");
    return 1;
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1]
                                : "/mnt/c/Users/travi/zano-port/our_clsag_sigs.json";
    if (!zano_generators_init()) {
        fprintf(stderr, "FATAL: generator init failed\n");
        return 1;
    }
    FILE *out = fopen(path, "w");
    if (!out) { perror(path); return 1; }

    fprintf(out, "{\n  \"clsag_ggx\": [\n");

    struct { const char *name; size_t ring, real; } cases[] = {
        { "ring2_real0",   2,  0 },   /* smallest ring, real first  */
        { "ring2_real1",   2,  1 },   /* smallest ring, real last   */
        { "ring4_real0",   4,  0 },
        { "ring4_real3",   4,  3 },   /* wrap at the end            */
        { "ring8_real3",   8,  3 },   /* the shape the suite uses   */
        { "ring8_real0",   8,  0 },
        { "ring8_real7",   8,  7 },
        { "ring16_real9", 16,  9 },   /* larger ring                */
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0])), ok = 0;
    for (int i = 0; i < n; i++) {
        if (!emit_case(out, cases[i].name, cases[i].ring, cases[i].real, i == 0)) {
            fclose(out);
            return 1;
        }
        ok++;
        printf("  emitted %-14s ring=%-2zu real=%zu\n",
               cases[i].name, cases[i].ring, cases[i].real);
    }

    fprintf(out, "\n  ]\n}\n");
    fclose(out);
    printf("\n  %d CLSAG_GGX signatures -> %s\n", ok, path);
    printf("  each one already verified under our own verifier before emission\n");
    return 0;
}
