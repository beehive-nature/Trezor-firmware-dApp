/**
 * zano_generators.c — see zano_generators.h.
 *
 * SPDX-License-Identifier: MIT
 */

#include "zano_generators.h"

#include "../rand.h"

// c_point_X compressed (y | sign(x)<<255), derived from the ref10 limbs at
// crypto-sugar.h:1129 and independently validated (see header).
static const uint8_t ZANO_POINT_X_BYTES[32] = {
    0x3a, 0x25, 0xbc, 0xdb, 0x43, 0xf5, 0xd2, 0xc9,
    0xdd, 0x06, 0x3d, 0xc3, 0x9a, 0x9e, 0x09, 0x87,
    0xba, 0xfc, 0x6f, 0xcf, 0x2d, 0xf1, 0xbc, 0x76,
    0x32, 0x2d, 0x75, 0x88, 0x4a, 0x4a, 0x38, 0x20,
};

// c_scalar_1div8 = 8^-1 mod L, 32-byte little-endian. The reference stores
// this as u64 limbs {0x6106e529e2dc2f79, 0x07d39db37d1cdad0, 0x0,
// 0x0600000000000000} (crypto-sugar.h:565) — identical value, different
// container.
static const uint8_t ZANO_SCALAR_1DIV8_BYTES[32] = {
    0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61,
    0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
};

ge25519       zano_point_X;
bignum256modm zano_scalar_1div8;

static bool g_ready = false;

bool zano_generators_init(void) {
    if (g_ready) return true;
    // ge25519_unpack_vartime returns 1 on success, 0 on failure.
    if (!ge25519_unpack_vartime(&zano_point_X, ZANO_POINT_X_BYTES)) return false;
    expand256_modm(zano_scalar_1div8, ZANO_SCALAR_1DIV8_BYTES, 32);
    g_ready = true;
    return true;
}

void zano_random_scalar(bignum256modm out) {
    uint8_t tmp[64];
    random_buffer(tmp, 64);
    expand256_modm(out, tmp, 64);  // 64 random bytes reduced mod L
}
