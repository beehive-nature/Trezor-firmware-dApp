/**
 * emit_address_vectors.c — emit (spend, view) -> address pairs from OUR encoder, for
 * hyle-team/zano's own get_account_address_as_str to check.
 *
 * Encoding is the half of "device shows the right address" that can be verified
 * against a foreign oracle. The derivation half cannot: Trezor derives from a BIP-39
 * seed, Zano's own wallet from a 25-word CryptoNote seed, so no reference wallet can
 * reproduce a Trezor-derived Zano address by construction — the same situation Monero
 * on Trezor is in. What IS checkable, and what actually decides whether funds arrive,
 * is that GIVEN a keypair we produce the identical string the network expects.
 *
 * Includes the founder's published address from the live .b registry as a fixed
 * vector: decoding it must recover two keys and re-encoding those must reproduce it
 * character for character. That one is real-world data, not something we generated.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zano_address.h"

/* Deterministic RNG so a run is reproducible. */
static uint32_t prng_state = 0x5A414E4Fu; /* "ZANO" */
void random_buffer(uint8_t *buf, size_t len);
void random_buffer(uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    prng_state ^= prng_state << 13;
    prng_state ^= prng_state >> 17;
    prng_state ^= prng_state << 5;
    buf[i] = (uint8_t)(prng_state & 0xFF);
  }
}

void tc_fault_handler(const char *msg);
void tc_fault_handler(const char *msg) {
  printf("FATAL: %s\n", msg ? msg : "(null)");
  abort();
}

#include "../ed25519-donna/ed25519-donna.h"

/* remington.b, as published on Vaulta mainnet under slip44:1018. */
static const char *FOUNDER_ADDR =
    "ZxCDR2aGwYhX2ayqCxrp2oAgFzoRaGZodJUWHmPZk7Ho1W4puz6DJDP5k1pDbZqTjQaSRRPg5"
    "ZBDDVsL42pVyQ7d2YM4Vy3Gu";

static void hexout(FILE *f, const uint8_t *b, size_t n) {
  for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
}

int main(int argc, char **argv) {
  const char *path =
      argc > 1 ? argv[1] : "/mnt/c/Users/travi/zano-port/our_addresses.json";
  FILE *out = fopen(path, "w");
  if (!out) {
    perror(path);
    return 1;
  }

  int fail = 0;

  /* 1. The published address must round-trip through our own codec. */
  printf("[1] round-trip of the live remington.b address\n");
  uint8_t fs[32], fv[32];
  if (!zano_address_decode(FOUNDER_ADDR, strlen(FOUNDER_ADDR), fs, fv)) {
    printf("  [FAIL] could not decode the published address\n");
    fail = 1;
  } else {
    char re[ZANO_ADDRESS_STR_LEN + 1];
    if (!zano_address_encode(fs, fv, re, sizeof(re))) {
      printf("  [FAIL] could not re-encode\n");
      fail = 1;
    } else if (strcmp(re, FOUNDER_ADDR) != 0) {
      printf("  [FAIL] re-encode differs\n    got %s\n    want %s\n", re,
             FOUNDER_ADDR);
      fail = 1;
    } else {
      printf("  [ok]   decode -> re-encode is identical (%zu chars)\n",
             strlen(re));
      printf("         spend ");
      hexout(stdout, fs, 32);
      printf("\n         view  ");
      hexout(stdout, fv, 32);
      printf("\n");
    }
  }

  /* 2. A corrupted address must be refused, or a typo becomes a lost payment. */
  printf("\n[2] corruption is rejected\n");
  char bad[ZANO_ADDRESS_STR_LEN + 1];
  uint8_t junk_s[32], junk_v[32];
  memcpy(bad, FOUNDER_ADDR, ZANO_ADDRESS_STR_LEN + 1);
  bad[40] = (bad[40] == 'A') ? 'B' : 'A';
  printf("  one character changed: %s\n",
         zano_address_decode(bad, ZANO_ADDRESS_STR_LEN, junk_s, junk_v)
             ? "[FAIL] ACCEPTED"
             : "[ok]   rejected");
  if (zano_address_decode(bad, ZANO_ADDRESS_STR_LEN, junk_s, junk_v)) fail = 1;

  memcpy(bad, FOUNDER_ADDR, ZANO_ADDRESS_STR_LEN + 1);
  bad[ZANO_ADDRESS_STR_LEN - 1] = '\0';
  printf("  truncated by one char: %s\n",
         zano_address_decode(bad, ZANO_ADDRESS_STR_LEN - 1, junk_s, junk_v)
             ? "[FAIL] ACCEPTED"
             : "[ok]   rejected");
  if (zano_address_decode(bad, ZANO_ADDRESS_STR_LEN - 1, junk_s, junk_v))
    fail = 1;

  /* 3. Emit generated vectors for the reference to verify. */
  printf("\n[3] emitting vectors for the reference\n");
  fprintf(out, "{\n  \"addresses\": [\n");
  int n = 0;
  for (int i = 0; i < 12; i++) {
    uint8_t sk[32], vk[32], sp[32], vp[32];
    bignum256modm s, v;
    ge25519 S, V;
    uint8_t b[64];

    random_buffer(b, 64);
    expand256_modm(s, b, 64);
    random_buffer(b, 64);
    expand256_modm(v, b, 64);
    contract256_modm(sk, s);
    contract256_modm(vk, v);
    ge25519_scalarmult_base_wrapper(&S, s);
    ge25519_scalarmult_base_wrapper(&V, v);
    ge25519_pack(sp, &S);
    ge25519_pack(vp, &V);

    char addr[ZANO_ADDRESS_STR_LEN + 1];
    if (!zano_address_encode(sp, vp, addr, sizeof(addr))) {
      printf("  [FAIL] encode failed at vector %d\n", i);
      fail = 1;
      break;
    }
    /* Never emit something our own decoder rejects. */
    uint8_t rs[32], rv[32];
    if (!zano_address_decode(addr, strlen(addr), rs, rv) ||
        memcmp(rs, sp, 32) != 0 || memcmp(rv, vp, 32) != 0) {
      printf("  [FAIL] self round-trip failed at vector %d\n", i);
      fail = 1;
      break;
    }

    if (n) fprintf(out, ",\n");
    fprintf(out, "    {\"spend\":\"");
    hexout(out, sp, 32);
    fprintf(out, "\",\"view\":\"");
    hexout(out, vp, 32);
    fprintf(out, "\",\"addr\":\"%s\"}", addr);
    n++;
  }
  fprintf(out, "\n  ]\n}\n");
  fclose(out);
  printf("  emitted %d vectors -> %s\n", n, path);
  printf("  each self-round-tripped before emission\n");

  printf("\n=== %s ===\n", fail ? "FAILURES" : "OUR SIDE CLEAN");
  return fail;
}
