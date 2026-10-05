/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef USE_BPQ

#include "py/objstr.h"
#include "py/runtime.h"

#include "bpq/bpq.h"
#include "memzero.h"
#include "rand.h"

// ML-DSA-65 working memory on the MicroPython heap (docs/bpq-device.md §4).
// mldsa-native and bpq.c wipe every buffer before it comes back here.
void *bpq_alloc(size_t size) { return m_malloc_maybe(size); }

void bpq_free(void *ptr, size_t size) { m_del(uint8_t, ptr, size); }

/// package: trezorcrypto.bpq

static void bpq_get_prk(mp_obj_t prk, mp_buffer_info_t *buf) {
  mp_get_buffer_raise(prk, buf, MP_BUFFER_READ);
  if (buf->len != BPQ_PRK_BYTES) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid length of PRK"));
  }
}

static void bpq_get_context(mp_obj_t context, mp_buffer_info_t *buf) {
  mp_get_buffer_raise(context, buf, MP_BUFFER_READ);
  if (!bpq_context_ok((const char *)buf->buf, buf->len)) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid context"));
  }
}

/// def public_keys(prk: AnyBytes, context: str) -> tuple[bytes, bytes, bytes]:
///     """
///     SPEC-BPQ-1 public keys for (prk, context): the ML-DSA-65 public key,
///     the X-Wing public key and the succession commitment.
///     """
STATIC mp_obj_t mod_trezorcrypto_bpq_public_keys(mp_obj_t prk,
                                                 mp_obj_t context) {
  mp_buffer_info_t prk_buf = {0}, ctx_buf = {0};
  bpq_get_prk(prk, &prk_buf);
  bpq_get_context(context, &ctx_buf);

  vstr_t dsa = {0}, kem = {0}, succ = {0};
  vstr_init_len(&dsa, BPQ_DSA_PK_BYTES);
  vstr_init_len(&kem, BPQ_KEM_PK_BYTES);
  vstr_init_len(&succ, BPQ_HASH_BYTES);
  if (bpq_public_keys((const uint8_t *)prk_buf.buf, (const char *)ctx_buf.buf,
                      ctx_buf.len, (uint8_t *)dsa.buf, (uint8_t *)kem.buf,
                      (uint8_t *)succ.buf) != 0) {
    vstr_clear(&dsa);
    vstr_clear(&kem);
    vstr_clear(&succ);
    mp_raise_msg(&mp_type_RuntimeError,
                 MP_ERROR_TEXT("Key derivation failed."));
  }
  mp_obj_t tuple[3] = {
      mp_obj_new_str_from_vstr(&mp_type_bytes, &dsa),
      mp_obj_new_str_from_vstr(&mp_type_bytes, &kem),
      mp_obj_new_str_from_vstr(&mp_type_bytes, &succ),
  };
  return mp_obj_new_tuple(3, tuple);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_bpq_public_keys_obj,
                                 mod_trezorcrypto_bpq_public_keys);

/// def sign(prk: AnyBytes, context: str, message: AnyBytes) -> bytes:
///     """
///     Hedged ML-DSA-65 signature (FIPS 204, empty context string) over
///     message with the key for (prk, context).
///     """
STATIC mp_obj_t mod_trezorcrypto_bpq_sign(mp_obj_t prk, mp_obj_t context,
                                          mp_obj_t message) {
  mp_buffer_info_t prk_buf = {0}, ctx_buf = {0}, msg_buf = {0};
  bpq_get_prk(prk, &prk_buf);
  bpq_get_context(context, &ctx_buf);
  mp_get_buffer_raise(message, &msg_buf, MP_BUFFER_READ);

  uint8_t rnd[BPQ_DSA_RND_BYTES] = {0};
  random_buffer(rnd, sizeof(rnd));

  vstr_t sig = {0};
  vstr_init_len(&sig, BPQ_DSA_SIG_BYTES);
  int ret = bpq_sign((const uint8_t *)prk_buf.buf, (const char *)ctx_buf.buf,
                     ctx_buf.len, (const uint8_t *)msg_buf.buf, msg_buf.len,
                     rnd, (uint8_t *)sig.buf);
  memzero(rnd, sizeof(rnd));
  if (ret != 0) {
    vstr_clear(&sig);
    mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("Signing failed."));
  }
  return mp_obj_new_str_from_vstr(&mp_type_bytes, &sig);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_bpq_sign_obj,
                                 mod_trezorcrypto_bpq_sign);

/// def verify(public_key: AnyBytes, message: AnyBytes,
///            signature: AnyBytes) -> bool:
///     """
///     True when signature is a valid ML-DSA-65 signature (empty context
///     string) of message under public_key.
///     """
STATIC mp_obj_t mod_trezorcrypto_bpq_verify(mp_obj_t public_key,
                                            mp_obj_t message,
                                            mp_obj_t signature) {
  mp_buffer_info_t pk = {0}, msg = {0}, sig = {0};
  mp_get_buffer_raise(public_key, &pk, MP_BUFFER_READ);
  mp_get_buffer_raise(message, &msg, MP_BUFFER_READ);
  mp_get_buffer_raise(signature, &sig, MP_BUFFER_READ);
  if (pk.len != BPQ_DSA_PK_BYTES || sig.len != BPQ_DSA_SIG_BYTES) {
    return mp_const_false;
  }
  return mp_obj_new_bool(bpq_verify((const uint8_t *)pk.buf,
                                    (const uint8_t *)msg.buf, msg.len,
                                    (const uint8_t *)sig.buf) == 0);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_bpq_verify_obj,
                                 mod_trezorcrypto_bpq_verify);

typedef int (*bpq_keygen_fn)(const uint8_t *seed, uint8_t *pk);

static mp_obj_t bpq_public_from_seed(mp_obj_t seed, size_t seed_len,
                                     size_t pk_len, bpq_keygen_fn keygen) {
  mp_buffer_info_t seed_buf = {0};
  mp_get_buffer_raise(seed, &seed_buf, MP_BUFFER_READ);
  if (seed_buf.len != seed_len) {
    mp_raise_ValueError(MP_ERROR_TEXT("Invalid length of seed"));
  }
  vstr_t pk = {0};
  vstr_init_len(&pk, pk_len);
  if (keygen((const uint8_t *)seed_buf.buf, (uint8_t *)pk.buf) != 0) {
    vstr_clear(&pk);
    mp_raise_msg(&mp_type_RuntimeError,
                 MP_ERROR_TEXT("Key generation failed."));
  }
  return mp_obj_new_str_from_vstr(&mp_type_bytes, &pk);
}

/// def mldsa65_public_key(seed: AnyBytes) -> bytes:
///     """
///     ML-DSA-65 public key from a 32-byte KeyGen seed (FIPS 204
///     KeyGen_internal).
///     """
STATIC mp_obj_t mod_trezorcrypto_bpq_mldsa65_public_key(mp_obj_t seed) {
  return bpq_public_from_seed(seed, BPQ_DSA_SEED_BYTES, BPQ_DSA_PK_BYTES,
                              bpq_mldsa65_public_from_seed);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_bpq_mldsa65_public_key_obj,
                                 mod_trezorcrypto_bpq_mldsa65_public_key);

/// def xwing_public_key(seed: AnyBytes) -> bytes:
///     """
///     X-Wing public key (ML-KEM-768 ek || X25519) from a 32-byte seed.
///     """
STATIC mp_obj_t mod_trezorcrypto_bpq_xwing_public_key(mp_obj_t seed) {
  return bpq_public_from_seed(seed, BPQ_KEM_SEED_BYTES, BPQ_KEM_PK_BYTES,
                              bpq_xwing_public_from_seed);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_bpq_xwing_public_key_obj,
                                 mod_trezorcrypto_bpq_xwing_public_key);

static int bpq_mlkem768_public_from_coins(const uint8_t *coins, uint8_t *pk) {
  uint8_t *sk = bpq_alloc(BPQ_MLKEM768_SK_BYTES);
  if (sk == NULL) {
    return -1;
  }
  int ret = bpq_mlkem768_keypair(coins, pk, sk);
  memzero(sk, BPQ_MLKEM768_SK_BYTES);
  bpq_free(sk, BPQ_MLKEM768_SK_BYTES);
  return ret;
}

/// def mlkem768_public_key(coins: AnyBytes) -> bytes:
///     """
///     ML-KEM-768 encapsulation key from d || z (FIPS 203 KeyGen_internal).
///     """
STATIC mp_obj_t mod_trezorcrypto_bpq_mlkem768_public_key(mp_obj_t coins) {
  return bpq_public_from_seed(coins, 64, BPQ_MLKEM768_PK_BYTES,
                              bpq_mlkem768_public_from_coins);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_bpq_mlkem768_public_key_obj,
                                 mod_trezorcrypto_bpq_mlkem768_public_key);

STATIC const mp_rom_map_elem_t mod_trezorcrypto_bpq_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_bpq)},
    {MP_ROM_QSTR(MP_QSTR_public_keys),
     MP_ROM_PTR(&mod_trezorcrypto_bpq_public_keys_obj)},
    {MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&mod_trezorcrypto_bpq_sign_obj)},
    {MP_ROM_QSTR(MP_QSTR_verify), MP_ROM_PTR(&mod_trezorcrypto_bpq_verify_obj)},
    {MP_ROM_QSTR(MP_QSTR_mldsa65_public_key),
     MP_ROM_PTR(&mod_trezorcrypto_bpq_mldsa65_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_mlkem768_public_key),
     MP_ROM_PTR(&mod_trezorcrypto_bpq_mlkem768_public_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_xwing_public_key),
     MP_ROM_PTR(&mod_trezorcrypto_bpq_xwing_public_key_obj)},
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_bpq_globals,
                            mod_trezorcrypto_bpq_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_bpq_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mod_trezorcrypto_bpq_globals,
};

#endif  // USE_BPQ
