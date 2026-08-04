#!/bin/sh
# Run every Zano crypto test in one shot.
#
#  1. CLSAG_GGX self-consistency   (our sign <-> our verify + tamper controls)
#  2. CLSAG_GGX conformance        (our verify accepts real Zano signatures)
#  3. Schnorr conformance          (both directions, see build_crosscheck.sh)
#
# Only 2 and 3 can detect a shared misunderstanding of the protocol; 1 exists
# to localise regressions, not to prove conformance.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
fail=0

run() {
    echo
    echo "############################################################"
    echo "# $1"
    echo "############################################################"
    if sh "$2"; then :; else fail=1; echo "*** SUITE FAILED: $1"; fi
}

run "1/3  CLSAG_GGX self-consistency"      "$HERE/build_test.sh"
run "2/3  CLSAG_GGX conformance vs Zano"   "$HERE/build_conformance.sh"
run "3/3  Schnorr conformance vs Zano"     "$HERE/build_schnorr.sh"

echo
echo "############################################################"
if [ "$fail" -eq 0 ]; then
    echo "# ALL ZANO CRYPTO SUITES PASSED"
    echo "#"
    echo "# These three prove the INBOUND direction: our verifier accepts what"
    echo "# the reference produces. That is compatible with our SIGNER being"
    echo "# wrong, so it is only half the gate. The outbound half needs the Zano"
    echo "# source tree and runs separately:"
    echo "#"
    echo "#   sh /mnt/c/Users/travi/zano-port/build_crosscheck.sh          # Schnorr  6/6"
    echo "#   sh /mnt/c/Users/travi/zano-port/build_clsag_crosscheck.sh    # CLSAG    8/8"
    echo "#   sh /mnt/c/Users/travi/zano-port/build_address_crosscheck.sh  # address 12/12"
    echo "#"
    echo "# Not yet ported, reference-side only — the BGE one-out-of-many proof"
    echo "# the asset surjection needs. This probe answers whether it works at"
    echo "# ring size 1, which is the whole shape of a one-input native MVP:"
    echo "#   sh /mnt/c/Users/travi/zano-port/build_bge_probe.sh          # BGE     8/8"
    echo "#"
    echo "# CLSAG_GGX is the spend path. Run both before trusting a signature"
    echo "# this code produces on a network where the funds are real."
else
    echo "# FAILURES PRESENT"
fi
echo "############################################################"
exit $fail
