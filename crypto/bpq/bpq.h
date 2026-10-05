/*
 * bpq: SPEC-BPQ-1 keys from a 32-byte PRK (beehive-nature
 * docs/specs/SPEC-BPQ-1.md).
 *
 * The caller hands in the device's SLIP-21 child (docs/bpq-device.md §1), never
 * the seed. Every seed and secret key derived below it lives in these functions
 * only and is wiped before they return. Only public keys and signatures leave.
 */

#ifndef __BPQ_H__
#define __BPQ_H__

#include <stddef.h>
#include <stdint.h>

#define BPQ_PRK_BYTES 32
#define BPQ_CONTEXT_MAX 64
#define BPQ_DSA_SEED_BYTES 32
#define BPQ_DSA_PK_BYTES 1952
#define BPQ_DSA_SIG_BYTES 3309
#define BPQ_DSA_RND_BYTES 32
#define BPQ_KEM_SEED_BYTES 32
#define BPQ_KEM_PK_BYTES 1216 /* ML-KEM-768 ek (1184) || X25519 (32) */
#define BPQ_SLH_SEED_BYTES 96
#define BPQ_SLH_PK_BYTES 64
#define BPQ_HASH_BYTES 32

/* 1 when the context may name keys: 1..64 bytes of printable ASCII, not "root".
 * "root" is reserved for the phrase-only vault (SPEC-BPQ-1 §2, ruling R2) and
 * never names a signing, X-Wing or succession key. */
int bpq_context_ok(const char *context, size_t context_len);

/* SPEC-BPQ-1 §2 public keys for (prk, context). succ_commit is
 * SHA3-256("bpq1/succession" || SLH-DSA-SHAKE-256f public key).
 * Returns 0 on success; on failure the outputs are zeroed. */
int bpq_public_keys(const uint8_t prk[BPQ_PRK_BYTES], const char *context,
                    size_t context_len, uint8_t dsa_pk[BPQ_DSA_PK_BYTES],
                    uint8_t kem_pk[BPQ_KEM_PK_BYTES],
                    uint8_t succ_commit[BPQ_HASH_BYTES]);

/* ML-DSA-65 signature (FIPS 204, empty context string) over msg with the key
 * for (prk, context). rnd is the FIPS 204 per-signature randomness: random
 * bytes for the hedged variant, 32 zero bytes for the deterministic one.
 * Returns 0 on success; on failure sig is zeroed. */
int bpq_sign(const uint8_t prk[BPQ_PRK_BYTES], const char *context,
             size_t context_len, const uint8_t *msg, size_t msg_len,
             const uint8_t rnd[BPQ_DSA_RND_BYTES],
             uint8_t sig[BPQ_DSA_SIG_BYTES]);

/* 0 when sig is a valid ML-DSA-65 signature (empty context) of msg under pk. */
int bpq_verify(const uint8_t pk[BPQ_DSA_PK_BYTES], const uint8_t *msg,
               size_t msg_len, const uint8_t sig[BPQ_DSA_SIG_BYTES]);

/* Key generation from a seed, public key out. Used by bpq_public_keys and
 * exposed so the unit tests can check each algorithm against public vectors. */
int bpq_mldsa65_public_from_seed(const uint8_t xi[BPQ_DSA_SEED_BYTES],
                                 uint8_t pk[BPQ_DSA_PK_BYTES]);
int bpq_xwing_public_from_seed(const uint8_t seed[BPQ_KEM_SEED_BYTES],
                               uint8_t pk[BPQ_KEM_PK_BYTES]);
int bpq_slh_shake256f_public_from_seed(const uint8_t seed[BPQ_SLH_SEED_BYTES],
                                       uint8_t pk[BPQ_SLH_PK_BYTES]);

/* Internal seams to the vendored libraries (bpq_mldsa65.c, bpq_mlkem768.c,
 * bpq_slh.c). Secret-key buffers are the caller's to wipe. */
#define BPQ_DSA_SK_BYTES 4032
#define BPQ_MLKEM768_PK_BYTES 1184
#define BPQ_MLKEM768_SK_BYTES 2400
int bpq_mldsa65_keypair(const uint8_t xi[BPQ_DSA_SEED_BYTES],
                        uint8_t pk[BPQ_DSA_PK_BYTES],
                        uint8_t sk[BPQ_DSA_SK_BYTES]);
int bpq_mldsa65_sign(const uint8_t sk[BPQ_DSA_SK_BYTES], const uint8_t *msg,
                     size_t msg_len, const uint8_t rnd[BPQ_DSA_RND_BYTES],
                     uint8_t sig[BPQ_DSA_SIG_BYTES]);
int bpq_mldsa65_verify(const uint8_t pk[BPQ_DSA_PK_BYTES], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[BPQ_DSA_SIG_BYTES]);
int bpq_mlkem768_keypair(const uint8_t coins[64],
                         uint8_t pk[BPQ_MLKEM768_PK_BYTES],
                         uint8_t sk[BPQ_MLKEM768_SK_BYTES]);

/* Working memory for ML-DSA-65 (mldsa-native MLD_CONFIG_CUSTOM_ALLOC_FREE).
 * Provided by the embedding: the MicroPython heap on the device, malloc in
 * host tests. mldsa-native wipes each buffer before handing it back. */
void *bpq_alloc(size_t size);
void bpq_free(void *ptr, size_t size);

#endif
