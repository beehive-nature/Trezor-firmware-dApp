/**
 * zano_address.c — see zano_address.h.
 *
 * SPDX-License-Identifier: MIT
 */

#include "zano_address.h"

#include <string.h>

#include "../hasher.h"
#include "../memzero.h"
#include "../monero/base58.h"

/// Little-endian base-128 varint, as get_varint_data() in the reference emits.
/// For 0xc5 this is {0xc5, 0x01} — two bytes, which is precisely why Monero's
/// single-byte tag path cannot encode a Zano address.
static size_t varint_write(uint64_t v, uint8_t *out) {
  size_t n = 0;
  while (v >= 0x80) {
    out[n++] = (uint8_t)((v & 0x7f) | 0x80);
    v >>= 7;
  }
  out[n++] = (uint8_t)v;
  return n;
}

static size_t varint_read(const uint8_t *in, size_t len, uint64_t *v) {
  uint64_t r = 0;
  size_t n = 0;
  int shift = 0;
  while (n < len) {
    uint8_t b = in[n++];
    r |= (uint64_t)(b & 0x7f) << shift;
    if ((b & 0x80) == 0) {
      *v = r;
      return n;
    }
    shift += 7;
    if (shift > 63) return 0;  // malformed
  }
  return 0;
}

bool zano_address_encode(const uint8_t spend_public_key[32],
                         const uint8_t view_public_key[32], char *out,
                         size_t out_len) {
  if (spend_public_key == NULL || view_public_key == NULL || out == NULL) {
    return false;
  }
  if (out_len < ZANO_ADDRESS_STR_LEN + 1) {
    return false;
  }

  uint8_t blob[ZANO_ADDRESS_BLOB_LEN];
  size_t n = varint_write(ZANO_PUBLIC_ADDRESS_PREFIX, blob);
  memcpy(blob + n, spend_public_key, 32);
  memcpy(blob + n + 32, view_public_key, 32);
  const size_t payload = n + 64;

  // cn_fast_hash is Keccak-256, which trezor-crypto exposes as HASHER_SHA3K.
  // NOT NIST SHA3-256: different padding, different digest, and an address that
  // would be rejected by every node while looking perfectly well-formed here.
  uint8_t hash[32];
  hasher_Raw(HASHER_SHA3K, blob, payload, hash);
  memcpy(blob + payload, hash, 4);

  size_t b58len = out_len;
  bool ok = xmr_base58_encode(out, &b58len, blob, payload + 4);

  memzero(blob, sizeof(blob));
  memzero(hash, sizeof(hash));

  if (!ok || b58len != ZANO_ADDRESS_STR_LEN) {
    memzero(out, out_len);
    return false;
  }
  out[b58len] = '\0';
  return true;
}

bool zano_address_decode(const char *addr, size_t addr_len,
                         uint8_t spend_public_key[32],
                         uint8_t view_public_key[32]) {
  if (addr == NULL || spend_public_key == NULL || view_public_key == NULL) {
    return false;
  }
  if (addr_len != ZANO_ADDRESS_STR_LEN) {
    return false;
  }

  uint8_t blob[ZANO_ADDRESS_BLOB_LEN];
  size_t blob_len = sizeof(blob);
  if (!xmr_base58_decode(addr, addr_len, blob, &blob_len)) {
    return false;
  }
  if (blob_len != ZANO_ADDRESS_BLOB_LEN) {
    memzero(blob, sizeof(blob));
    return false;
  }

  uint64_t tag = 0;
  size_t n = varint_read(blob, blob_len, &tag);
  if (n == 0 || tag != ZANO_PUBLIC_ADDRESS_PREFIX || n + 64 + 4 != blob_len) {
    memzero(blob, sizeof(blob));
    return false;
  }

  uint8_t hash[32];
  hasher_Raw(HASHER_SHA3K, blob, n + 64, hash);
  // Constant-time is not required — the checksum is public data — but a mismatch
  // must be fatal rather than a warning, or a typo'd address becomes a lost payment.
  bool ok = memcmp(hash, blob + n + 64, 4) == 0;
  if (ok) {
    memcpy(spend_public_key, blob + n, 32);
    memcpy(view_public_key, blob + n + 32, 32);
  }

  memzero(blob, sizeof(blob));
  memzero(hash, sizeof(hash));
  return ok;
}
