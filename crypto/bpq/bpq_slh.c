/*
 * SLH-DSA-SHAKE-256f key generation for the bpq succession commitment, from
 * the SPHINCS+ reference in vendor/sphincsplus (the boardloader and the
 * emulator build the same tree at SHA2-128s, under the reference's names).
 *
 * Only the public key is computed: PK.seed || root of the top XMSS tree
 * (FIPS 205 slh_keygen_internal). The succession secret is never kept;
 * SPEC-BPQ-1 §5 re-derives it when a rotation needs it.
 *
 * The reference's FIPS 202 functions are extern and unprefixed, and one of
 * them (sha3_256) has the same name as trezor-crypto's, so every one of them
 * is renamed for this unit.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../memzero.h"
#include "bpq.h"

/* The emulator also builds this reference at SHA2-128s with a global PARAMS
 * and the reference's own SPX_ names, so this unit sets its own parameters
 * and renames every SPX_ symbol to bpq_spx256f_. */
#undef PARAMS
// clang-format off: the reference stringifies PARAMS into a file name, so
// no space may enter it
#define PARAMS sphincs-shake-256f
// clang-format on
#include "../../vendor/sphincsplus/ref/params.h"
#undef SPX_NAMESPACE
#define SPX_NAMESPACE(s) bpq_spx256f_##s

#define shake128_absorb bpq_spx_shake128_absorb
#define shake128_squeezeblocks bpq_spx_shake128_squeezeblocks
#define shake128_inc_init bpq_spx_shake128_inc_init
#define shake128_inc_absorb bpq_spx_shake128_inc_absorb
#define shake128_inc_finalize bpq_spx_shake128_inc_finalize
#define shake128_inc_squeeze bpq_spx_shake128_inc_squeeze
#define shake256_absorb bpq_spx_shake256_absorb
#define shake256_squeezeblocks bpq_spx_shake256_squeezeblocks
#define shake256_inc_init bpq_spx_shake256_inc_init
#define shake256_inc_absorb bpq_spx_shake256_inc_absorb
#define shake256_inc_finalize bpq_spx_shake256_inc_finalize
#define shake256_inc_squeeze bpq_spx_shake256_inc_squeeze
#define shake128 bpq_spx_shake128
#define shake256 bpq_spx_shake256
#define sha3_256_inc_init bpq_spx_sha3_256_inc_init
#define sha3_256_inc_absorb bpq_spx_sha3_256_inc_absorb
#define sha3_256_inc_finalize bpq_spx_sha3_256_inc_finalize
#define sha3_256 bpq_spx_sha3_256
#define sha3_512_inc_init bpq_spx_sha3_512_inc_init
#define sha3_512_inc_absorb bpq_spx_sha3_512_inc_absorb
#define sha3_512_inc_finalize bpq_spx_sha3_512_inc_finalize
#define sha3_512 bpq_spx_sha3_512

#include "../../vendor/sphincsplus/ref/address.c"
#include "../../vendor/sphincsplus/ref/fips202.c"
#include "../../vendor/sphincsplus/ref/hash_shake.c"
#include "../../vendor/sphincsplus/ref/merkle.c"
#include "../../vendor/sphincsplus/ref/thash_shake_simple.c"
#include "../../vendor/sphincsplus/ref/utils.c"
#include "../../vendor/sphincsplus/ref/utilsx1.c"
#include "../../vendor/sphincsplus/ref/wots.c"
#include "../../vendor/sphincsplus/ref/wotsx1.c"

#if SPX_N != 32 || SPX_FULL_HEIGHT != 68 || SPX_D != 17
#error "bpq_slh.c must be built at SLH-DSA-SHAKE-256f"
#endif

/* seed = SK.seed || SK.prf || PK.seed (FIPS 205 order, 3n bytes). SK.prf only
 * enters signing, so key generation reads SK.seed and PK.seed. */
int bpq_slh_shake256f_public_from_seed(const uint8_t seed[BPQ_SLH_SEED_BYTES],
                                       uint8_t pk[BPQ_SLH_PK_BYTES]) {
  spx_ctx ctx = {0};
  uint8_t root[SPX_N] = {0};

  memcpy(ctx.sk_seed, seed, SPX_N);
  memcpy(ctx.pub_seed, seed + 2 * SPX_N, SPX_N);
  initialize_hash_function(&ctx);
  merkle_gen_root(root, &ctx);

  memcpy(pk, ctx.pub_seed, SPX_N);
  memcpy(pk + SPX_N, root, SPX_N);
  memzero(&ctx, sizeof(ctx));
  return 0;
}

void bpq_shake256(uint8_t *out, size_t out_len, const uint8_t *in,
                  size_t in_len) {
  shake256(out, out_len, in, in_len);
}
