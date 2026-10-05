from micropython import const
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import BpqClaim

_CONTEXT_MAX = const(64)
_CLAIMS_MAX = const(16)
_VALUE_MAX = const(256)
_FILE_SIZE_MAX = const(0x1F_FFFF_FFFF_FFFF)  # JS Number.MAX_SAFE_INTEGER
_DIGITS = "0123456789"


async def device_prk() -> bytes:
    """The SLIP-21 child of the device seed, through the keychain's namespace check."""
    from apps.common.keychain import get_keychain

    from . import SLIP21_NAMESPACE, SLIP21_PATH

    keychain = await get_keychain("", [], [SLIP21_NAMESPACE])
    with keychain:
        return keychain.derive_slip21(SLIP21_PATH).key()


def check_context(context: str) -> None:
    """1..64 bytes of printable ASCII, never the reserved "root" (SPEC-BPQ-1 §2)."""
    from trezor.wire import DataError

    raw = context.encode()
    if not raw or len(raw) > _CONTEXT_MAX or context == "root":
        raise DataError("bpq: context must be 1-64 bytes and not root")
    for b in raw:
        if b < 0x20 or b > 0x7E:
            raise DataError("bpq: context must be printable ASCII")


def bpq_id(dsa_public_key: bytes, succession_commit: bytes) -> str:
    """bech32m("bzpq", SHA3-256("bpq1/id" || dsa || succ)) (SPEC-BPQ-1 §2)."""
    from trezor.crypto import bech32
    from trezor.crypto.hashlib import sha3_256

    d = sha3_256(b"bpq1/id" + dsa_public_key + succession_commit).digest()
    return bech32.bech32_encode(
        "bzpq", bech32.convertbits(d, 8, 5), bech32.Encoding.BECH32M
    )


def check_at(at: str) -> None:
    """^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d(\\.\\d{1,9})?Z$, the shape only (SPEC-BPQ-1 §3)."""
    from trezor.wire import DataError

    def bad() -> DataError:
        return DataError("bpq: at must have the shape YYYY-MM-DDTHH:MM:SS[.f]Z")

    n = len(at)
    if n < 20 or n > 30 or at[-1] != "Z":
        raise bad()
    for i, c in enumerate(at[:19]):
        want = {4: "-", 7: "-", 10: "T", 13: ":", 16: ":"}.get(i)
        if want is not None:
            if c != want:
                raise bad()
        elif c not in _DIGITS:
            raise bad()
    frac = at[19:-1]
    if frac:
        if frac[0] != "." or not 2 <= len(frac) <= 10:
            raise bad()
        for c in frac[1:]:
            if c not in _DIGITS:
                raise bad()


def claim_lines(claims: list[BpqClaim]) -> str:
    """kind=value\\n for each claim, kinds sorted (SPEC-BPQ-1 §3)."""
    from trezor.wire import DataError

    if not claims or len(claims) > _CLAIMS_MAX:
        raise DataError("bpq: a binding names 1-16 claims")
    seen = set()
    for c in claims:
        k = c.kind
        kb = k.encode()
        if not 1 <= len(kb) <= 32 or k in seen:
            raise DataError("bpq: claim kinds are 1-32 bytes and unique")
        for i, b in enumerate(kb):
            # ^[a-z0-9][a-z0-9._-]{0,31}$
            ok = 0x61 <= b <= 0x7A or 0x30 <= b <= 0x39
            if i > 0:
                ok = ok or b in b"._-"
            if not ok:
                raise DataError("bpq: claim kind must match [a-z0-9][a-z0-9._-]*")
        seen.add(k)
        v = c.value
        if not v or len(v.encode()) > _VALUE_MAX or "\n" in v or "\r" in v:
            raise DataError("bpq: claim value must be one non-empty line")
    out = ""
    for c in sorted(claims, key=lambda c: c.kind):
        out += c.kind + "=" + c.value + "\n"
    return out


def check_file_size(size: int) -> None:
    from trezor.wire import DataError

    if size > _FILE_SIZE_MAX:
        raise DataError("bpq: file size is past what a verifier can read")
