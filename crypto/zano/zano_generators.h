/**
 * zano_generators.h — Zano's fixed generator set, expressed on ed25519-donna.
 *
 * Reference: hyle-team/zano src/crypto/crypto-sugar.h
 *
 * The constants are stored as canonical WIRE encodings and decoded by
 * ed25519-donna itself. Do NOT transcribe the reference's internal limbs:
 * Zano/ref10's `fe` is a SIGNED int32_t[10], donna's bignum25519 is an
 * UNSIGNED uint32_t[10], and bignum256modm is uint32_t[9] — not uint64_t[4].
 * Copying either layout across compiles with warnings and yields silently
 * invalid crypto.
 *
 * G is ed25519's base point (donna provides it). H is already available as
 * xmr_h from the Monero code. H2, U and H±G have no consumer in the v1 scope
 * and are deliberately not defined here rather than guessed at.
 *
 * SPDX-License-Identifier: MIT
 * Part of the beehive-nature ecosystem.
 */
#ifndef ZANO_GENERATORS_H
#define ZANO_GENERATORS_H

#include <stdbool.h>
#include <stdint.h>

#include "../ed25519-donna/ed25519-donna.h"

/// c_point_X — the asset-id generator.
/// Verified against crypto-sugar.h:1129: on-curve, T*Z == X*Y,
/// L*X == identity (prime order), 8*X != identity.
extern ge25519 zano_point_X;

/// c_scalar_1div8 — 8^-1 mod L. Verified: 8 * this == 1 (mod L), and
/// byte-identical to crypto-sugar.h:565.
extern bignum256modm zano_scalar_1div8;

/**
 * Decode the constants. Idempotent, cheap after the first call.
 * @return false only if a constant fails to decode (a build/corruption bug).
 */
bool zano_generators_init(void);

/// Uniform scalar mod L from the device RNG.
void zano_random_scalar(bignum256modm out);

#endif /* ZANO_GENERATORS_H */
