/*
 * Host test for crypto/bpq against public vectors: sh crypto/bpq/build_test.sh
 *
 * Key generation is checked by byte equality: ML-DSA-65 and ML-KEM-768
 * against NIST ACVP keyGen cases, and the whole SPEC-BPQ-1 §2 derivation
 * (ML-DSA-65, X-Wing, SLH-DSA-SHAKE-256f, succession commitment) against
 * beehive-nature's bpq-vectors.json roots. Signing is checked by verification,
 * including two refusals, since hedged signatures differ on every call.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpq.h"
#include "bpq_vectors.h"

void *bpq_alloc(size_t size) { return malloc(size); }
void bpq_free(void *ptr, size_t size) {
  (void)size;
  free(ptr);
}

/* ed25519.c is linked for curve25519_scalarmult_basepoint alone. Its signing
 * and point-decoding paths need these two; nothing in this test reaches them,
 * and if anything ever does, the test dies instead of passing. */
void random_buffer(uint8_t *buf, size_t len) {
  (void)buf;
  (void)len;
  fprintf(stderr, "random_buffer reached in test_bpq\n");
  abort();
}
int consteq(const void *a, const void *b, size_t len) {
  (void)a;
  (void)b;
  (void)len;
  fprintf(stderr, "consteq reached in test_bpq\n");
  abort();
}

static int failures = 0;

static void check(int ok, const char *what, const char *name) {
  printf("  [%s] %s %s\n", ok ? "ok" : "FAIL", what, name);
  if (!ok) failures++;
}

#define N(a) (sizeof(a) / sizeof((a)[0]))

int main(void) {
  static uint8_t pk[BPQ_DSA_PK_BYTES];
  static uint8_t kem[BPQ_KEM_PK_BYTES];
  static uint8_t sk_m[BPQ_MLKEM768_SK_BYTES];
  static uint8_t succ[BPQ_HASH_BYTES];
  static uint8_t sig[BPQ_DSA_SIG_BYTES];
  char name[64];

  printf("ML-DSA-65 keyGen, NIST ACVP\n");
  for (size_t i = 0; i < N(BPQ_DSA_KATS); i++) {
    snprintf(name, sizeof(name), "tcId %d", BPQ_DSA_KATS[i].tc);
    int ok = bpq_mldsa65_public_from_seed(BPQ_DSA_KATS[i].seed, pk) == 0 &&
             memcmp(pk, BPQ_DSA_KATS[i].pk, sizeof(pk)) == 0;
    check(ok, "pk byte-equal", name);
  }

  printf("ML-KEM-768 keyGen, NIST ACVP\n");
  for (size_t i = 0; i < N(BPQ_KEM_KATS); i++) {
    snprintf(name, sizeof(name), "tcId %d", BPQ_KEM_KATS[i].tc);
    int ok = bpq_mlkem768_keypair(BPQ_KEM_KATS[i].dz, kem, sk_m) == 0 &&
             memcmp(kem, BPQ_KEM_KATS[i].ek, BPQ_MLKEM768_PK_BYTES) == 0;
    check(ok, "ek byte-equal", name);
  }

  printf("SPEC-BPQ-1 roots, bpq-vectors.json\n");
  for (size_t i = 0; i < N(BPQ_ROOT_VECTORS); i++) {
    const bpq_root_vector *v = &BPQ_ROOT_VECTORS[i];
    snprintf(name, sizeof(name), "root %s, context %s", v->name, v->context);
    int ret =
        bpq_public_keys(v->prk, v->context, strlen(v->context), pk, kem, succ);
    check(ret == 0 && memcmp(pk, v->dsa, sizeof(pk)) == 0, "dsaPublicKey",
          name);
    check(ret == 0 && memcmp(kem, v->kem, sizeof(kem)) == 0, "kemPublicKey",
          name);
    /* SHA3-256 of the SLH-DSA-SHAKE-256f public key: equal commitments mean
     * equal succession keys */
    check(ret == 0 && memcmp(succ, v->succ, sizeof(succ)) == 0,
          "successionCommit", name);

    static const uint8_t msg[] = "bpq1 host test message";
    uint8_t rnd[BPQ_DSA_RND_BYTES] = {7};
    ret = bpq_sign(v->prk, v->context, strlen(v->context), msg, sizeof(msg),
                   rnd, sig);
    check(ret == 0 && bpq_verify(v->dsa, msg, sizeof(msg), sig) == 0,
          "signature verifies under the vector key", name);
    sig[100] ^= 1;
    check(bpq_verify(v->dsa, msg, sizeof(msg), sig) != 0,
          "altered signature refused", name);
  }

  printf("context rules\n");
  check(!bpq_context_ok("root", 4), "\"root\" refused", "");
  check(!bpq_context_ok("", 0), "empty refused", "");
  check(!bpq_context_ok("pq:a\nb", 6), "newline refused", "");
  check(bpq_public_keys(BPQ_ROOT_VECTORS[0].prk, "root", 4, pk, kem, succ) != 0,
        "no keys under \"root\"", "");

  printf(failures ? "FAILURES: %d\n" : "ALL OK\n", failures);
  return failures ? 1 : 0;
}
