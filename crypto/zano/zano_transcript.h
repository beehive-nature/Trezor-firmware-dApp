/**
 * zano_transcript.h — Fiat-Shamir transcript accumulator, shared by every
 * Zano primitive.
 *
 * Mirrors Zano's hash_helper_t::hs_t (crypto-sugar.h): a sequence of 32-byte
 * items hashed as one buffer.
 *
 * THE HASH IS LEGACY KECCAK-256, NOT NIST SHA3-256.
 * Zano's cn_fast_hash -> keccak() uses 0x01 domain padding (hash.c/keccak.c);
 * NIST SHA3 uses 0x06. Trezor ships both: keccak_256() is the correct one,
 * sha3_256() is NOT. Getting this wrong produces well-formed signatures that
 * the daemon rejects, and NO self-consistency test can detect it, because
 * both sides of the port share the error. This header exists so the choice
 * is made exactly once.
 *
 * Two hash flavours, matching the reference exactly:
 *   zano_hs_hash_reduce  <-> hs_t::calc_hash()            (reduced mod L)
 *   zano_hs_hash_raw     <-> hs_t::calc_hash_no_reduce()  (raw 32 bytes)
 *
 * And two ways to append the message hash, which are NOT interchangeable:
 *   zano_hs_add_message  <-> hs_t::add_scalar(m)  — implicitly sc_reduce32's
 *                            m (CLSAG uses this)
 *   zano_hs_add          <-> hs_t::add_hash(m)    — raw (the Schnorr sigs in
 *                            zarcanum.h use this)
 *
 * The caller supplies the buffer, so a 5-item proof costs 160 bytes of stack
 * rather than the worst case a ring signature needs.
 *
 * SPDX-License-Identifier: MIT
 * Part of the beehive-nature ecosystem.
 */
#ifndef ZANO_TRANSCRIPT_H
#define ZANO_TRANSCRIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../ed25519-donna/ed25519-donna.h"
#include "../sha3.h"

typedef struct {
    uint8_t *buf;       ///< caller-owned storage, multiple of 32
    size_t   cap;       ///< capacity in BYTES
    size_t   len;       ///< bytes used
    bool     overflow;  ///< sticky: set if any item was dropped
} zano_hs_t;

static inline void zano_hs_init(zano_hs_t *h, uint8_t *buf, size_t cap_bytes) {
    h->buf = buf;
    h->cap = cap_bytes;
    h->len = 0;
    h->overflow = false;
}

/// Append a raw 32-byte item (hs_t::add_hash / add_pub_key / add_key_image).
static inline void zano_hs_add(zano_hs_t *h, const void *data32) {
    if (h->len + 32 > h->cap) {
        h->overflow = true;  // never truncate a transcript silently
        return;
    }
    memcpy(h->buf + h->len, data32, 32);
    h->len += 32;
}

/// Append a group element in compressed form (hs_t::add_point).
static inline void zano_hs_add_point(zano_hs_t *h, const ge25519 *p) {
    uint8_t compressed[32];
    ge25519_pack(compressed, p);
    zano_hs_add(h, compressed);
}

/// Append a 32-byte domain-separation tag (hs_t::add_32_chars).
static inline void zano_hs_add_ds_tag(zano_hs_t *h, const char tag[32]) {
    zano_hs_add(h, tag);
}

/// Append a scalar in canonical little-endian form (hs_t::add_scalar).
static inline void zano_hs_add_scalar(zano_hs_t *h, const bignum256modm s) {
    uint8_t b[32];
    contract256_modm(b, s);
    zano_hs_add(h, b);
}

/**
 * Append the message hash the way hs_t::add_scalar(const hash&) does.
 *
 * That overload implicitly constructs scalar_t(const crypto::hash&), which
 * runs sc_reduce32 — so the item is m REDUCED MOD L, not the raw hash. A
 * uniformly random 32-byte hash is >= L about 93.75% of the time, so the
 * distinction is almost always observable.
 *
 * Use this ONLY where the reference passes m to add_scalar (CLSAG_GGX).
 * Where the reference calls add_hash(m) — e.g. the Schnorr sigs in
 * zarcanum.h — use zano_hs_add() instead.
 */
static inline void zano_hs_add_message(zano_hs_t *h, const uint8_t m[32]) {
    bignum256modm reduced;
    expand256_modm(reduced, m, 32);
    zano_hs_add_scalar(h, reduced);
}

/// hs_t::calc_hash() — Keccak-256 then reduce mod L. Clears the buffer.
/// Returns false if any item was dropped (see zano_hs_add).
static inline bool zano_hs_hash_reduce(bignum256modm out, zano_hs_t *h) {
    if (h->overflow) return false;
    uint8_t digest[32];
    keccak_256(h->buf, h->len, digest);
    expand256_modm(out, digest, 32);
    h->len = 0;
    return true;
}

/// hs_t::calc_hash_no_reduce() — Keccak-256, raw 32 bytes. Clears the buffer.
static inline bool zano_hs_hash_raw(uint8_t out[32], zano_hs_t *h) {
    if (h->overflow) return false;
    keccak_256(h->buf, h->len, out);
    h->len = 0;
    return true;
}

#endif /* ZANO_TRANSCRIPT_H */
