/* Does the reference's BGE one-out-of-many proof round-trip at ring size 1?
 *
 * This decides the Zano MVP shape before a line of it is ported. The design note
 * flagged constexpr_pow(m, n) at one_out_of_many_proofs.cpp:76 as reading like
 * pow(m,n) where pow(n,m) looks intended, which would break small rings. A native
 * ZANO transfer with one confidential input needs exactly ring size 1, so if that
 * is broken the MVP has to grow.
 *
 * Asking the reference rather than reasoning about it. Also emits vectors we can
 * port against, the same way the CLSAG and address work was done.
 */
#include "crypto-sugar.h"
#include "one_out_of_many_proofs.h"
#include <cstdio>
#include <vector>

using namespace crypto;

static int checks = 0, failures = 0;

static void report(const char *what, bool ok) {
    checks++;
    if (!ok) failures++;
    printf("  [%s] %s\n", ok ? "ok" : "FAIL", what);
}

/* One ring of the given size, secret at the given index, generate then verify. */
static bool round_trip(size_t ring_size, size_t secret_index, bool emit) {
    hash ctx = *(hash *)"BGE probe ctx 32 bytes exactly!!";

    scalar_t secret = scalar_t::random();
    std::vector<point_t> ring;
    ring.reserve(ring_size);
    for (size_t i = 0; i < ring_size; i++) {
        if (i == secret_index)
            // BGE proves knowledge w.r.t. the X generator, not G — see the debug
            // assertion at one_out_of_many_proofs.cpp:71. Same X as the asset
            // surjection relation T - pa = t*X, which is what this proof is for.
            ring.push_back(secret * c_point_X);
        else
            ring.push_back(scalar_t::random() * c_point_X);
    }

    BGE_proof proof{};
    uint8_t err = 0;
    if (!generate_BGE_proof(ctx, ring, secret, secret_index, proof, &err)) {
        printf("       generate failed, err=%u\n", (unsigned)err);
        return false;
    }

    // The 1/8 asymmetry, third time in this codebase: generate takes the FULL
    // points, verify takes them premultiplied by 1/8. Copied from the reference's
    // own call site, currency_format_utils.cpp:186 —
    //   ring[i] = (c_scalar_1div8 * (pseudo_outs_blinded_asset_ids[i] - T)).to_public_key()
    std::vector<const public_key *> vring;
    std::vector<public_key> packed(ring_size);
    vring.reserve(ring_size);
    for (size_t i = 0; i < ring_size; i++) {
        packed[i] = (c_scalar_1div8 * ring[i]).to_public_key();
        vring.push_back(&packed[i]);
    }

    err = 0;
    bool ok = verify_BGE_proof(ctx, vring, proof, &err);
    if (!ok) printf("       verify failed, err=%u\n", (unsigned)err);

    if (ok && emit) {
        printf("       ring=%zu secret_index=%zu -> proof accepted\n", ring_size, secret_index);
    }
    return ok;
}

int main() {
    printf("=== BGE one-out-of-many: does it work at the sizes the MVP needs? ===\n\n");

    printf("ring size 1 (the MVP case: one confidential input):\n");
    report("ring=1, secret at 0", round_trip(1, 0, true));

    printf("\nsmall rings:\n");
    report("ring=2, secret at 0", round_trip(2, 0, true));
    report("ring=2, secret at 1", round_trip(2, 1, true));
    report("ring=3, secret at 2", round_trip(3, 2, true));
    report("ring=4, secret at 0", round_trip(4, 0, true));
    report("ring=4, secret at 3", round_trip(4, 3, true));

    printf("\nlarger, for shape:\n");
    report("ring=8,  secret at 5", round_trip(8, 5, true));
    report("ring=16, secret at 9", round_trip(16, 9, true));

    printf("\n=== %d/%d passed ===\n", checks - failures, checks);
    if (failures) {
        printf("RESULT: BGE does NOT round-trip everywhere. The MVP shape depends on\n");
        printf("        which sizes work — see the failures above.\n");
        return 1;
    }
    printf("RESULT: BGE round-trips at every size tested, including ring=1.\n");
    printf("        The one-input native MVP is viable as specified.\n");
    return 0;
}
