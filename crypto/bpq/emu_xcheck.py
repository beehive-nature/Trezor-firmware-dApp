"""bpq on the T3W1 emulator, checked against two oracles foreign to the device.

    BEEHIVE_NATURE=<checkout> uv run python crypto/bpq/emu_xcheck.py

Run from the repository root after
    xtask build firmware --emulator --model T3W1 --pyopt false --debug-link true --disable-tropic

EMULATOR ONLY. Never enumerates USB or Bluetooth; each run uses a fresh
temporary profile loaded with the PUBLIC BIP-39 test vector
("abandon" x 11, "about"). There is no seed parameter.

For two fresh profiles, the device must:
  1. return a card (BpqGetCard) whose dsa, kem, succ and id equal what
     beehive-nature's surfaces/bpq.js derives from the same PRK and context,
     and whose dsa, kem and id equal what crates/bsigner/src/bpq.rs derives;
  2. sign, after an on-screen confirmation, a SPEC-BPQ-1 binding naming the
     wallet id (vector root A) and a detached file signature, each of which
     verifies in both oracles, while a flipped bit or changed field does not;
  3. refuse the reserved context "root", a request with both statements, and
     a statement the user cancels on screen;
  4. give the same card in the second profile as in the first.
The PRK the oracles use is the SLIP-21 child of the public test vector's seed,
recomputed here; it is printed because it guards nothing.
"""

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EMU = ROOT / "core/build-xtask/artifacts/T3W1/firmware-emu"
MNEMONIC = " ".join(["abandon"] * 11 + ["about"])  # PUBLIC BIP-39 test vector
CONTEXT = "pq:bsafe"
AT = "2026-10-04T12:00:00Z"
FILE = b"bpq1 emulator detached-signature fixture\n"
WALLET_ROOT_FROM = "bpq1 test vector root A"  # bpq-vectors.json, public
WALLET_CONTEXT = "pq:vector"


def slip21_prk(seed: bytes) -> bytes:
    node = hmac.new(b"Symmetric key seed", seed, hashlib.sha512).digest()
    for label in (b"BZPQ-DEVICE", b"v1"):
        node = hmac.new(node[:32], b"\x00" + label, hashlib.sha512).digest()
    return node[32:]


def b64u(b: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def run_profile(index: int, wallet_id: str) -> dict:
    from tests.input_flows import InputFlowConfirmAllWarnings
    from trezorlib import debuglink, exceptions, messages
    from trezorlib._internal.emulator import CoreEmulator

    out: dict = {"profile": index}
    with tempfile.TemporaryDirectory(prefix="bpq-emu-fixture-") as profile:
        emu = CoreEmulator(
            EMU,
            profile,
            headless=True,
            port=29424,
            workdir=ROOT / "core/src",
            debug=True,
        )
        try:
            emu.start()
            session = emu.client.get_seedless_session()
            debuglink.load_device(
                session,
                mnemonic=MNEMONIC,
                pin=None,
                passphrase_protection=False,
                label="PUBLIC TEST VECTOR ONLY",
            )
            session = emu.client.get_session()
            assert (
                session.features.internal_model == "T3W1"
            ), session.features.internal_model
            out["firmware"] = [
                session.features.major_version,
                session.features.minor_version,
                session.features.patch_version,
            ]

            card = session.call(
                messages.BpqGetCard(context=CONTEXT), expect=messages.BpqCard
            )
            out["card"] = {
                "bpq": 1,
                "id": card.id,
                "dsa": b64u(card.dsa_public_key),
                "kem": b64u(card.kem_public_key),
                "succ": b64u(card.succession_commit),
                "sig": b64u(card.signature),
            }

            def confirmed(msg, screens):
                with session.test_ctx as client:
                    flow = InputFlowConfirmAllWarnings(
                        session,
                        on_page=lambda layout: screens.append(layout.screen_content()),
                    )
                    client.set_input_flow(flow.get())
                    return session.call(msg, expect=messages.BpqSignature)

            claims = [messages.BpqClaim(kind="bzpq-wallet", value=wallet_id)]
            screens_bind: list = []
            sig = confirmed(
                messages.BpqSign(
                    context=CONTEXT, binding=messages.BpqBinding(at=AT, claims=claims)
                ),
                screens_bind,
            )
            out["binding"] = {
                "bpq": 1,
                "kind": "binding",
                "id": sig.id,
                "at": AT,
                "claims": {"bzpq-wallet": wallet_id},
                "dsa": out["card"]["dsa"],
                "succ": out["card"]["succ"],
                "sig": b64u(sig.signature),
            }
            out["screens_binding"] = screens_bind

            sha3 = hashlib.sha3_256(FILE).digest()
            screens_file: list = []
            sig = confirmed(
                messages.BpqSign(
                    context=CONTEXT,
                    detached=messages.BpqDetached(at=AT, size=len(FILE), sha3=sha3),
                ),
                screens_file,
            )
            out["detached"] = {
                "bpq": 1,
                "kind": "detached",
                "id": sig.id,
                "at": AT,
                "file": {"size": len(FILE), "sha3": b64u(sha3)},
                "dsa": out["card"]["dsa"],
                "succ": out["card"]["succ"],
                "sig": b64u(sig.signature),
            }
            out["screens_detached"] = screens_file

            refusals = {}
            try:
                session.call(
                    messages.BpqGetCard(context="root"), expect=messages.BpqCard
                )
                refusals["context_root"] = "ACCEPTED"
            except exceptions.TrezorFailure as e:
                refusals["context_root"] = f"refused: {e.message}"
            try:
                session.call(
                    messages.BpqSign(
                        context=CONTEXT,
                        binding=messages.BpqBinding(at=AT, claims=claims),
                        detached=messages.BpqDetached(at=AT, size=1, sha3=sha3),
                    ),
                    expect=messages.BpqSignature,
                )
                refusals["both_statements"] = "ACCEPTED"
            except exceptions.TrezorFailure as e:
                refusals["both_statements"] = f"refused: {e.message}"
            try:
                session.call(
                    messages.BpqSign(
                        context=CONTEXT,
                        binding=messages.BpqBinding(
                            at="2026-10-04 12:00:00", claims=claims
                        ),
                    ),
                    expect=messages.BpqSignature,
                )
                refusals["bad_at"] = "ACCEPTED"
            except exceptions.TrezorFailure as e:
                refusals["bad_at"] = f"refused: {e.message}"

            def cancel():
                yield
                session.debug.press_no()

            try:
                with session.test_ctx as client:
                    client.set_input_flow(cancel())
                    session.call(
                        messages.BpqSign(
                            context=CONTEXT,
                            binding=messages.BpqBinding(at=AT, claims=claims),
                        ),
                        expect=messages.BpqSignature,
                    )
                refusals["user_cancel"] = "ACCEPTED"
            except (exceptions.TrezorFailure, exceptions.Cancelled) as e:
                refusals["user_cancel"] = (
                    f"refused: {type(e).__name__} {getattr(e, 'message', '')}".strip()
                )
            out["refusals"] = refusals
        except Exception:
            log = Path(profile) / "trezor.log"
            if log.exists():
                print(log.read_text(errors="replace")[-4000:], file=sys.stderr)
            raise
        finally:
            emu.stop()
    return out


def oracle(cmd: list[str], payload: dict, cwd: Path | None = None) -> dict:
    run = subprocess.run(
        cmd,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=600,
        cwd=cwd,
    )
    if run.stdout.strip() == "":
        raise RuntimeError(f"{cmd[0]} printed nothing; stderr:\n{run.stderr[-3000:]}")
    return json.loads(run.stdout.strip().splitlines()[-1])


def main() -> int:
    bn = os.environ.get("BEEHIVE_NATURE")
    if not bn:
        print("set BEEHIVE_NATURE to a beehive-nature checkout", file=sys.stderr)
        return 2
    os.environ["TREZOR_SRC"] = str(ROOT / "core/src")
    sys.path.insert(0, str(ROOT))

    vectors = json.load(open(Path(bn) / "surfaces/bpq-vectors.json", encoding="utf-8"))
    wallet_id = next(
        k["id"]
        for k in vectors["keys"]
        if k["rootFrom"] == WALLET_ROOT_FROM and k["context"] == WALLET_CONTEXT
    )

    seed = hashlib.pbkdf2_hmac("sha512", MNEMONIC.encode(), b"mnemonic", 2048)
    prk = slip21_prk(seed).hex()

    runs = [run_profile(i, wallet_id) for i in (1, 2)]
    first = runs[0]
    payload = {
        "prk": prk,
        "context": CONTEXT,
        "card": first["card"],
        "binding": first["binding"],
        "detached": first["detached"],
        "file_hex": FILE.hex(),
        "wallet_root_from": WALLET_ROOT_FROM,
        "wallet_context": WALLET_CONTEXT,
        "at": AT,
    }
    env = dict(os.environ, BEEHIVE_NATURE=bn)
    js = oracle(["node", str(ROOT / "crypto/bpq/js-xcheck.mjs")], payload)
    payload["wallet_binding"] = js["wallet_binding"]
    # The Rust oracle lives in beehive-nature (crates/bpq-device-xcheck): bsigner's
    # own bpq.rs compiled by #[path], built from the workspace lockfile at whatever
    # revision BEEHIVE_NATURE has checked out; the receipt records that revision.
    # Nothing of it is copied here.
    subprocess.run(
        [
            "cargo",
            "build",
            "--quiet",
            "--release",
            "--locked",
            "-p",
            "bpq-device-xcheck",
        ],
        cwd=bn,
        env=env,
        check=True,
    )
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", str(Path(bn) / "target")))
    rust = oracle([str(target_dir / "release/bpq-device-xcheck")], payload)

    same_card = runs[0]["card"]["id"] == runs[1]["card"]["id"] and all(
        runs[0]["card"][f] == runs[1]["card"][f] for f in ("dsa", "kem", "succ")
    )
    refusals_ok = all(
        r["refusals"][k].startswith("refused") for r in runs for k in r["refusals"]
    )

    receipt = {
        "classification": "PUBLIC-CONSTANT",
        "schema": "bpq.safe7.emulator.v1",
        "fixture": "public BIP-39 test vector, abandon x11 about, no passphrase",
        "fork_revision": subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        ).strip(),
        "fork_dirty": bool(
            subprocess.check_output(
                [
                    "git",
                    "-C",
                    str(ROOT),
                    "status",
                    "--porcelain",
                    "--untracked-files=no",
                ],
                text=True,
            ).strip()
        ),
        # a Windows worktree's .git is unreadable from WSL, so the caller may name it
        "beehive_nature_revision": os.environ.get("BEEHIVE_NATURE_REV")
        or subprocess.check_output(
            ["git", "-C", bn, "rev-parse", "HEAD"], text=True
        ).strip(),
        "emulator_sha256": hashlib.sha256(EMU.read_bytes()).hexdigest(),
        "context": CONTEXT,
        "device_prk_public_fixture": prk,
        "device_id": first["card"]["id"],
        "wallet_id": wallet_id,
        "second_profile_same_card": same_card,
        "refusals": [r["refusals"] for r in runs],
        "screens": {
            "binding": first["screens_binding"],
            "detached": first["screens_detached"],
        },
        "js": {
            k: js[k]
            for k in (
                "oracle",
                "bpq_js_sha256",
                "bpq_lib_sha256",
                "checks",
                "keys_equal",
                "signatures_verify",
                "controls_refused",
                "ok",
            )
        },
        "rust": rust,
        "device_binding": first["binding"],
        "wallet_binding": js["wallet_binding"],
        "device_detached": first["detached"],
    }
    print(json.dumps(receipt, indent=1))
    ok = js["ok"] and rust["ok"] and same_card and refusals_ok
    print(
        (
            "PASS: device card equals bpq.js and bsigner; device binding and detached signature verify in both; "
            "R4 binding both ways; refusals held; second profile gave the same card. EMULATOR ONLY."
            if ok
            else "FAIL"
        ),
        file=sys.stderr,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
