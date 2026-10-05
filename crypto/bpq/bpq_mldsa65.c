/*
 * vendor/mldsa-native built once more, at ML-DSA-65, for bpq.
 *
 * The tree's own mldsa-native build (ML-DSA-44, prefix "mldsa", MCU device
 * attestation only) is untouched: this unit has its own namespace (bpqmld65_)
 * and its internals are static, so neither build can reach the other's keys.
 * Large working buffers go through bpq_alloc / bpq_free (MicroPython heap on
 * the device); mldsa-native wipes each one before it is freed.
 */

#include <stddef.h>
#include <stdint.h>

#include "bpq.h"

#undef MLD_CONFIG_NAMESPACE_PREFIX
#undef MLD_CONFIG_PARAMETER_SET
#define MLD_CONFIG_PARAMETER_SET 65
#define MLD_CONFIG_NAMESPACE_PREFIX bpqmld65
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static
/* bpq passes its per-signature randomness in (bpq_sign's rnd), so the API
 * that would draw its own is left out. */
#ifndef MLD_CONFIG_NO_RANDOMIZED_API
#define MLD_CONFIG_NO_RANDOMIZED_API
#endif
#define MLD_CONFIG_CUSTOM_ALLOC_FREE
#define MLD_CUSTOM_ALLOC(v, T, N) T *(v) = (T *)bpq_alloc(sizeof(T) * (N))
#define MLD_CUSTOM_FREE(v, T, N) bpq_free((v), sizeof(T) * (N))

#include "mldsa_native.c"

/* FIPS 204 ML-DSA.Sign with an empty context string: M' = 0x00 || 0x00 || M. */
static const uint8_t EMPTY_CONTEXT_PREFIX[2] = {0, 0};

int bpq_mldsa65_keypair(const uint8_t xi[BPQ_DSA_SEED_BYTES],
                        uint8_t pk[BPQ_DSA_PK_BYTES],
                        uint8_t sk[BPQ_DSA_SK_BYTES]) {
  return bpqmld65_keypair_internal(pk, sk, xi);
}

int bpq_mldsa65_sign(const uint8_t sk[BPQ_DSA_SK_BYTES], const uint8_t *msg,
                     size_t msg_len, const uint8_t rnd[BPQ_DSA_RND_BYTES],
                     uint8_t sig[BPQ_DSA_SIG_BYTES]) {
  size_t sig_len = 0;
  if (bpqmld65_signature_internal(
          sig, &sig_len, msg, msg_len, EMPTY_CONTEXT_PREFIX,
          sizeof(EMPTY_CONTEXT_PREFIX), rnd, sk, 0) != 0) {
    return -1;
  }
  return sig_len == BPQ_DSA_SIG_BYTES ? 0 : -1;
}

int bpq_mldsa65_verify(const uint8_t pk[BPQ_DSA_PK_BYTES], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[BPQ_DSA_SIG_BYTES]) {
  return bpqmld65_verify(sig, BPQ_DSA_SIG_BYTES, msg, msg_len, NULL, 0, pk);
}
