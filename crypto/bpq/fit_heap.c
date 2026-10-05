/*
 * Heap high-water mark of crypto/bpq, measured through bpq_alloc / bpq_free:
 *   sh crypto/bpq/fit.sh
 *
 * On the device bpq_alloc is the MicroPython heap (m_malloc_maybe), so these
 * are the bytes the GC heap must hand out. Every allocation is sizeof(T) * N of
 * fixed-width types, so the counts do not depend on the host's word size.
 * The C stack is measured separately, from an ARM build (fit_stack.py).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpq.h"
#include "bpq_vectors.h"

static size_t live, peak, largest, count;

void *bpq_alloc(size_t size) {
  void *p = malloc(size);
  if (p == NULL) return NULL;
  live += size;
  count++;
  if (live > peak) peak = live;
  if (size > largest) largest = size;
  return p;
}

void bpq_free(void *ptr, size_t size) {
  if (ptr == NULL) return;
  live -= size;
  free(ptr);
}

/* Linked for curve25519_scalarmult_basepoint alone, as in test_bpq.c. */
void random_buffer(uint8_t *buf, size_t len) {
  (void)buf;
  (void)len;
  abort();
}
int consteq(const void *a, const void *b, size_t len) {
  (void)a;
  (void)b;
  (void)len;
  abort();
}

static void reset(void) { live = peak = largest = count = 0; }

static int report(const char *what, int ret) {
  printf("%-26s peak %6zu B  largest block %6zu B  allocations %3zu  %s\n",
         what, peak, largest, count,
         ret == 0 && live == 0 ? "ok" : "FAIL (error or leak)");
  return ret == 0 && live == 0 ? 0 : 1;
}

int main(void) {
  static uint8_t pk[BPQ_DSA_PK_BYTES];
  static uint8_t kem[BPQ_KEM_PK_BYTES];
  static uint8_t succ[BPQ_HASH_BYTES];
  static uint8_t sig[BPQ_DSA_SIG_BYTES];
  static const uint8_t msg[] = "bpq1 fit measurement message";
  int bad = 0;
  size_t worst = 0;

  for (size_t i = 0; i < sizeof(BPQ_ROOT_VECTORS) / sizeof(BPQ_ROOT_VECTORS[0]);
       i++) {
    const bpq_root_vector *v = &BPQ_ROOT_VECTORS[i];
    char what[40];

    reset();
    int ret =
        bpq_public_keys(v->prk, v->context, strlen(v->context), pk, kem, succ);
    snprintf(what, sizeof(what), "bpq_public_keys root %s", v->name);
    bad |= report(what, ret);
    if (peak > worst) worst = peak;

    /* ML-DSA signing rejects and retries; the vector roots and a few rnd
     * values give different iteration counts. */
    for (uint8_t r = 0; r < 4; r++) {
      uint8_t rnd[BPQ_DSA_RND_BYTES] = {r};
      reset();
      ret = bpq_sign(v->prk, v->context, strlen(v->context), msg, sizeof(msg),
                     rnd, sig);
      snprintf(what, sizeof(what), "bpq_sign root %s rnd %u", v->name, r);
      bad |= report(what, ret);
      if (peak > worst) worst = peak;
    }

    reset();
    ret = bpq_verify(pk, msg, sizeof(msg), sig);
    snprintf(what, sizeof(what), "bpq_verify root %s", v->name);
    bad |= report(what, ret);
    if (peak > worst) worst = peak;
  }
  printf("worst heap high-water mark: %zu B\n", worst);
  return bad;
}
