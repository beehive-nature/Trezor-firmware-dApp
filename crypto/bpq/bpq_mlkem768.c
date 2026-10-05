/*
 * vendor/mlkem-native (v2.0.0) at ML-KEM-768, for the X-Wing public key in a
 * bpq card. Key generation only: this build has no encapsulation and no
 * decapsulation; its API is namespaced bpqmlk768_ and its internals are static.
 */

#include <stddef.h>
#include <stdint.h>

#include "bpq.h"

#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NAMESPACE_PREFIX bpqmlk768
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static
#define MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_NO_ENCAPS_API
#define MLK_CONFIG_NO_DECAPS_API

#include "mlkem_native.c"

/* FIPS 203 ML-KEM.KeyGen_internal(d, z) with coins = d || z. */
int bpq_mlkem768_keypair(const uint8_t coins[64],
                         uint8_t pk[BPQ_MLKEM768_PK_BYTES],
                         uint8_t sk[BPQ_MLKEM768_SK_BYTES]) {
  return bpqmlk768_keypair_derand(pk, sk, coins);
}
