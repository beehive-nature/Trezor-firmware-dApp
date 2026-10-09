// JS oracle for crypto/bpq/emu_xcheck.py: beehive-nature's surfaces/bpq.js.
//
//   BEEHIVE_NATURE=<checkout> node crypto/bpq/js-xcheck.mjs < input.json
//
// input: {prk, context, card, binding, detached, file_hex, wallet_root_from,
//         wallet_context, at}. prk is the device's SLIP-21 child for the PUBLIC
// BIP-39 test vector, recomputed by the harness; nothing here is a real key.
// Prints one JSON object; exit 1 when any check fails.

import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const BN = process.env.BEEHIVE_NATURE;
if (!BN) { console.error('set BEEHIVE_NATURE to a beehive-nature checkout'); process.exit(2); }
const require = createRequire(import.meta.url);
require(join(BN, 'surfaces', 'onboarding', 'vendor', 'bpq-lib.js'));
require(join(BN, 'surfaces', 'bpq.js'));
const B = globalThis.BPQ;
if (!B) { console.error('bpq.js did not load'); process.exit(2); }

const input = JSON.parse(readFileSync(0, 'utf8'));
const hex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const b64u = (b) => Buffer.from(b).toString('base64url');
const sha256 = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');

const checks = {};
const k = B.keys(hex(input.prk), input.context);
checks.dsa_equal = b64u(k.dsa.publicKey) === input.card.dsa;
checks.kem_equal = b64u(k.kem.publicKey) === input.card.kem;
checks.succ_equal = b64u(k.succession.commit) === input.card.succ;
checks.id_equal = k.id === input.card.id;
k.wipe();

const file = Buffer.from(input.file_hex, 'hex');
checks.verifyCard_device = B.verifyCard(input.card);
checks.verifyBind_device = B.verifyBind(input.binding);
checks.verifyFile_device = B.verifyFile(input.detached, file).ok === true;

// controls: one flipped signature bit and one changed claim must each fail
const flip = (o) => { const s = Buffer.from(o.sig, 'base64url'); s[100] ^= 1; return { ...o, sig: b64u(s) }; };
checks.control_card_bitflip_refused = B.verifyCard(flip(input.card)) === false;
checks.control_binding_claim_changed_refused =
  B.verifyBind({ ...input.binding, claims: { ...input.binding.claims, 'bzpq-wallet': 'bzpq1other' } }) === false;
checks.control_file_changed_refused = B.verifyFile(input.detached, Buffer.concat([file, Buffer.from('x')])).ok === false;

// The wallet's half of the R4 binding, from the public vector root A.
const root = createHash('sha256').update(input.wallet_root_from, 'utf8').digest();
const w = B.keys(new Uint8Array(root), input.wallet_context);
const walletBinding = B.bind(w, { 'bsafe-pq': input.card.id }, input.at);
w.wipe();
checks.wallet_binding_names_device = walletBinding.claims['bsafe-pq'] === input.card.id;
checks.device_binding_names_wallet = input.binding.claims['bzpq-wallet'] === walletBinding.id;
checks.verifyBind_wallet = B.verifyBind(walletBinding);

// Three summaries beside the flat checks, so key equality, signature
// verification and the controls are read apart (the Rust oracle prints the same).
const keys_equal = checks.dsa_equal && checks.kem_equal && checks.succ_equal && checks.id_equal;
const signatures_verify = checks.verifyCard_device && checks.verifyBind_device
  && checks.verifyFile_device && checks.verifyBind_wallet
  && checks.wallet_binding_names_device && checks.device_binding_names_wallet;
const controls_refused = checks.control_card_bitflip_refused
  && checks.control_binding_claim_changed_refused && checks.control_file_changed_refused;
const ok = Object.values(checks).every((v) => v === true);
console.log(JSON.stringify({
  oracle: 'surfaces/bpq.js',
  bpq_js_sha256: sha256(join(BN, 'surfaces', 'bpq.js')),
  bpq_lib_sha256: sha256(join(BN, 'surfaces', 'onboarding', 'vendor', 'bpq-lib.js')),
  checks, keys_equal, signatures_verify, controls_refused, ok, wallet_binding: walletBinding,
}));
process.exit(ok ? 0 : 1);
