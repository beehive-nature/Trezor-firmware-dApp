/*
 * bpq: SPEC-BPQ-1 §2 keys from a 32-byte PRK. See bpq.h and docs/bpq-device.md.
 */

#include "bpq.h"

#include <string.h>

#include "../ed25519-donna/ed25519.h"
#include "../hmac.h"
#include "../memzero.h"
#include "../sha3.h"

/* FROZEN v1 labels (SPEC-BPQ-1 §2, surfaces/bpq.js LABEL, bsigner bpq.rs).
 * Changing a byte orphans every key. */
static const char LABEL_DSA[] = "BDID-v1/ml-dsa-65-record-key";
static const char LABEL_KEM[] = "BDID-v1/x-wing-kem-key";
static const char LABEL_SUCC[] = "BDID-v1/slh-dsa-shake-256f-succession";
static const char DOM_SUCC[] = "bpq1/succession";
static const char ROOT_CONTEXT[] = "root";

/* SHAKE-256 from the SPHINCS+ reference build (bpq_slh.c). */
void bpq_shake256(uint8_t *out, size_t out_len, const uint8_t *in,
                  size_t in_len);

int bpq_context_ok(const char *context, size_t context_len) {
  if (context == NULL || context_len == 0 || context_len > BPQ_CONTEXT_MAX) {
    return 0;
  }
  if (context_len == sizeof(ROOT_CONTEXT) - 1 &&
      memcmp(context, ROOT_CONTEXT, context_len) == 0) {
    return 0;
  }
  for (size_t i = 0; i < context_len; i++) {
    if (context[i] < 0x20 || context[i] > 0x7e) {
      return 0;
    }
  }
  return 1;
}

/* HKDF-Expand(SHA-256, prk, label || context, out_len), RFC 5869 §2.3.
 * out_len <= 96 here (three blocks). */
static void expand(const uint8_t prk[BPQ_PRK_BYTES], const char *label,
                   const char *context, size_t context_len, uint8_t *out,
                   size_t out_len) {
  uint8_t t[SHA256_DIGEST_LENGTH] = {0};
  size_t t_len = 0;
  size_t done = 0;
  for (uint8_t counter = 1; done < out_len; counter++) {
    HMAC_SHA256_CTX ctx = {0};
    hmac_sha256_Init(&ctx, prk, BPQ_PRK_BYTES);
    hmac_sha256_Update(&ctx, t, t_len);
    hmac_sha256_Update(&ctx, (const uint8_t *)label, strlen(label));
    hmac_sha256_Update(&ctx, (const uint8_t *)context, context_len);
    hmac_sha256_Update(&ctx, &counter, 1);
    hmac_sha256_Final(&ctx, t);
    t_len = sizeof(t);
    size_t n = out_len - done < t_len ? out_len - done : t_len;
    memcpy(out + done, t, n);
    done += n;
  }
  memzero(t, sizeof(t));
}

int bpq_mldsa65_public_from_seed(const uint8_t xi[BPQ_DSA_SEED_BYTES],
                                 uint8_t pk[BPQ_DSA_PK_BYTES]) {
  uint8_t *sk = bpq_alloc(BPQ_DSA_SK_BYTES);
  if (sk == NULL) {
    memzero(pk, BPQ_DSA_PK_BYTES);
    return -1;
  }
  int ret = bpq_mldsa65_keypair(xi, pk, sk);
  memzero(sk, BPQ_DSA_SK_BYTES);
  bpq_free(sk, BPQ_DSA_SK_BYTES);
  if (ret != 0) {
    memzero(pk, BPQ_DSA_PK_BYTES);
  }
  return ret;
}

/* X-Wing key generation (draft-connolly-cfrg-xwing-kem, as SPEC-BPQ-1 §2
 * states it): SHAKE-256(seed, 96); bytes 0-63 are the ML-KEM-768 seed d || z,
 * bytes 64-95 the X25519 secret. pk = ML-KEM-768 ek || X25519(sk_X, 9). */
int bpq_xwing_public_from_seed(const uint8_t seed[BPQ_KEM_SEED_BYTES],
                               uint8_t pk[BPQ_KEM_PK_BYTES]) {
  uint8_t expanded[96] = {0};
  uint8_t *sk_m = bpq_alloc(BPQ_MLKEM768_SK_BYTES);
  int ret = -1;
  if (sk_m == NULL) {
    goto cleanup;
  }
  bpq_shake256(expanded, sizeof(expanded), seed, BPQ_KEM_SEED_BYTES);
  if (bpq_mlkem768_keypair(expanded, pk, sk_m) != 0) {
    goto cleanup;
  }
  curve25519_scalarmult_basepoint(pk + BPQ_MLKEM768_PK_BYTES, expanded + 64);
  ret = 0;

cleanup:
  memzero(expanded, sizeof(expanded));
  if (sk_m != NULL) {
    memzero(sk_m, BPQ_MLKEM768_SK_BYTES);
    bpq_free(sk_m, BPQ_MLKEM768_SK_BYTES);
  }
  if (ret != 0) {
    memzero(pk, BPQ_KEM_PK_BYTES);
  }
  return ret;
}

int bpq_public_keys(const uint8_t prk[BPQ_PRK_BYTES], const char *context,
                    size_t context_len, uint8_t dsa_pk[BPQ_DSA_PK_BYTES],
                    uint8_t kem_pk[BPQ_KEM_PK_BYTES],
                    uint8_t succ_commit[BPQ_HASH_BYTES]) {
  uint8_t xi[BPQ_DSA_SEED_BYTES] = {0};
  uint8_t kem_seed[BPQ_KEM_SEED_BYTES] = {0};
  uint8_t slh_seed[BPQ_SLH_SEED_BYTES] = {0};
  uint8_t slh_pk[BPQ_SLH_PK_BYTES] = {0};
  SHA3_CTX h = {0};
  int ret = -1;

  if (!bpq_context_ok(context, context_len)) {
    goto cleanup;
  }
  expand(prk, LABEL_DSA, context, context_len, xi, sizeof(xi));
  expand(prk, LABEL_KEM, context, context_len, kem_seed, sizeof(kem_seed));
  expand(prk, LABEL_SUCC, context, context_len, slh_seed, sizeof(slh_seed));

  if (bpq_mldsa65_public_from_seed(xi, dsa_pk) != 0) {
    goto cleanup;
  }
  if (bpq_xwing_public_from_seed(kem_seed, kem_pk) != 0) {
    goto cleanup;
  }
  if (bpq_slh_shake256f_public_from_seed(slh_seed, slh_pk) != 0) {
    goto cleanup;
  }
  sha3_256_Init(&h);
  sha3_Update(&h, (const uint8_t *)DOM_SUCC, sizeof(DOM_SUCC) - 1);
  sha3_Update(&h, slh_pk, sizeof(slh_pk));
  sha3_Final(&h, succ_commit);
  ret = 0;

cleanup:
  memzero(xi, sizeof(xi));
  memzero(kem_seed, sizeof(kem_seed));
  memzero(slh_seed, sizeof(slh_seed));
  if (ret != 0) {
    memzero(dsa_pk, BPQ_DSA_PK_BYTES);
    memzero(kem_pk, BPQ_KEM_PK_BYTES);
    memzero(succ_commit, BPQ_HASH_BYTES);
  }
  return ret;
}

int bpq_sign(const uint8_t prk[BPQ_PRK_BYTES], const char *context,
             size_t context_len, const uint8_t *msg, size_t msg_len,
             const uint8_t rnd[BPQ_DSA_RND_BYTES],
             uint8_t sig[BPQ_DSA_SIG_BYTES]) {
  uint8_t xi[BPQ_DSA_SEED_BYTES] = {0};
  uint8_t *pk = bpq_alloc(BPQ_DSA_PK_BYTES);
  uint8_t *sk = bpq_alloc(BPQ_DSA_SK_BYTES);
  int ret = -1;

  if (pk == NULL || sk == NULL || !bpq_context_ok(context, context_len)) {
    goto cleanup;
  }
  expand(prk, LABEL_DSA, context, context_len, xi, sizeof(xi));
  if (bpq_mldsa65_keypair(xi, pk, sk) != 0) {
    goto cleanup;
  }
  if (bpq_mldsa65_sign(sk, msg, msg_len, rnd, sig) != 0) {
    goto cleanup;
  }
  ret = 0;

cleanup:
  memzero(xi, sizeof(xi));
  if (sk != NULL) {
    memzero(sk, BPQ_DSA_SK_BYTES);
    bpq_free(sk, BPQ_DSA_SK_BYTES);
  }
  if (pk != NULL) {
    bpq_free(pk, BPQ_DSA_PK_BYTES);
  }
  if (ret != 0) {
    memzero(sig, BPQ_DSA_SIG_BYTES);
  }
  return ret;
}

int bpq_verify(const uint8_t pk[BPQ_DSA_PK_BYTES], const uint8_t *msg,
               size_t msg_len, const uint8_t sig[BPQ_DSA_SIG_BYTES]) {
  return bpq_mldsa65_verify(pk, msg, msg_len, sig);
}
