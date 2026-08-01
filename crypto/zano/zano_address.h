/**
 * zano_address.h — Zano public address encoding.
 *
 * WHY THIS IS NOT xmr_base58_addr_encode_check
 *
 * Monero's encoder in crypto/monero/base58.c refuses any tag above 127:
 *
 *     if (binsz > max_bin_data_size || tag > 127) {  // tag varint
 *       return false;
 *     }
 *     buf[0] = (uint8_t)tag;
 *
 * It writes the tag as one byte. Zano's public-address prefix is 0xc5 (197), which
 * needs a two-byte varint, so that function cannot produce a Zano address at all — it
 * returns false rather than producing a wrong one, which is the good failure, but it
 * is still a failure. The raw block encoder `xmr_base58_encode` is shared and reused.
 *
 * FORMAT, read from hyle-team/zano rather than from documentation:
 *
 *   base58.cpp encode_addr(tag, data):
 *     buf  = varint(tag) || data
 *     buf += cn_fast_hash(buf)[0..4]        // Keccak-256, 4-byte checksum
 *     return base58_block_encode(buf)
 *
 *   currency_format_utils.cpp get_account_address_as_str():
 *     flags == 0  ->  encode_addr(0xc5, spend_pub || view_pub)   // classic
 *
 * So a classic address is 2 + 32 + 32 + 4 = 70 bytes, which the block encoder turns
 * into 8 full blocks (88 chars) plus a 6-byte tail (9 chars) = 97 characters, always
 * beginning "Zx". That length is a useful invariant: a Zano address that is not 97
 * characters is not a classic address, and a truncated one is not an address at all.
 *
 * SPDX-License-Identifier: MIT
 * Part of the beehive-nature ecosystem.
 */
#ifndef ZANO_ADDRESS_H
#define ZANO_ADDRESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// Classic public-address prefix. `addresses start with 'Zx'` — currency_config.h.
#define ZANO_PUBLIC_ADDRESS_PREFIX 0xc5

/// A classic address is always exactly this many characters.
#define ZANO_ADDRESS_STR_LEN 97

/// Bytes fed to the base58 block encoder: varint(0xc5) + spend + view + checksum.
#define ZANO_ADDRESS_BLOB_LEN 70

/**
 * Encode a classic Zano public address.
 *
 * @param spend_public_key  32-byte compressed point
 * @param view_public_key   32-byte compressed point
 * @param out               receives a NUL-terminated address
 * @param out_len           size of `out`; must be at least ZANO_ADDRESS_STR_LEN + 1
 * @return true on success
 *
 * Does not validate that the inputs are on the curve. Encoding a garbage key produces
 * a well-formed address for an account nobody controls, so callers deriving keys are
 * responsible for their validity — this function is the encoder, not the gate.
 */
bool zano_address_encode(const uint8_t spend_public_key[32],
                         const uint8_t view_public_key[32], char *out,
                         size_t out_len);

/**
 * Decode a classic Zano address back to its two public keys.
 *
 * Verifies the checksum and the prefix. Returns false on any mismatch, on a wrong
 * length, or on a character outside the base58 alphabet.
 */
bool zano_address_decode(const char *addr, size_t addr_len,
                         uint8_t spend_public_key[32],
                         uint8_t view_public_key[32]);

#endif  // ZANO_ADDRESS_H
