# flake8: noqa: F403,F405
from common import *  # isort:skip

if utils.USE_BPQ:
    from trezorcrypto import bpq

    from bpq_vectors import DSA_KATS, KEM_KATS, ROOTS

    from apps.bpq.common import bpq_id

    class TestCryptoBpq(unittest.TestCase):
        # Public vectors only: NIST ACVP keyGen cases and beehive-nature's
        # bpq-vectors.json roots (SHA-256 of public sentences). No real phrase.

        def test_mldsa65_keygen_acvp(self):
            for tc, seed, pk in DSA_KATS:
                self.assertEqual(
                    bpq.mldsa65_public_key(unhexlify(seed)), unhexlify(pk), tc
                )

        def test_mlkem768_keygen_acvp(self):
            for tc, dz, ek in KEM_KATS:
                self.assertEqual(
                    bpq.mlkem768_public_key(unhexlify(dz)), unhexlify(ek), tc
                )

        def test_spec_bpq_1_roots(self):
            for v in ROOTS:
                dsa, kem, succ = bpq.public_keys(unhexlify(v["prk"]), v["context"])
                self.assertEqual(dsa, unhexlify(v["dsa"]), v["name"])
                self.assertEqual(kem, unhexlify(v["kem"]), v["name"])
                self.assertEqual(succ, unhexlify(v["succ"]), v["name"])
                self.assertEqual(bpq_id(dsa, succ), v["id"], v["name"])

        def test_sign_verifies_under_vector_key(self):
            v = ROOTS[0]
            msg = b"bpq1 emulator unit test"
            sig = bpq.sign(unhexlify(v["prk"]), v["context"], msg)
            self.assertEqual(len(sig), 3309)
            self.assertTrue(bpq.verify(unhexlify(v["dsa"]), msg, sig))
            self.assertFalse(bpq.verify(unhexlify(v["dsa"]), msg + b"!", sig))
            self.assertFalse(bpq.verify(unhexlify(ROOTS[1]["dsa"]), msg, sig))

        def test_context_refusals(self):
            prk = unhexlify(ROOTS[0]["prk"])
            for bad in ("root", "", "pq:a\nb", "x" * 65):
                with self.assertRaises(ValueError):
                    bpq.public_keys(prk, bad)
                with self.assertRaises(ValueError):
                    bpq.sign(prk, bad, b"m")
            with self.assertRaises(ValueError):
                bpq.public_keys(prk[:31], "pq:vector")


if __name__ == "__main__":
    unittest.main()
