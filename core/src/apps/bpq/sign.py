from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import BpqSign, BpqSignature


async def sign(msg: BpqSign) -> BpqSignature:
    """A SPEC-BPQ-1 binding (§3) or detached file signature (§3b).

    The host sends fields, never the bytes to be signed. The device checks the
    fields, builds the signed bytes itself, shows the id and every field, and
    signs only after the user confirms.
    """
    from trezorcrypto import bpq
    from ubinascii import hexlify

    from trezor.crypto.hashlib import sha3_256
    from trezor.enums import ButtonRequestType
    from trezor.messages import BpqSignature
    from trezor.ui.layouts import confirm_properties
    from trezor.wire import DataError

    from .common import (
        bpq_id,
        check_at,
        check_context,
        check_file_size,
        claim_lines,
        device_prk,
    )

    check_context(msg.context)
    if (msg.binding is None) == (msg.detached is None):
        raise DataError("bpq: sign exactly one of binding or detached")

    if msg.binding is not None:
        b = msg.binding
        check_at(b.at)
        lines = claim_lines(b.claims)
    else:
        d = msg.detached
        assert d is not None
        check_at(d.at)
        check_file_size(d.size)
        if len(d.sha3) != 32:
            raise DataError("bpq: sha3 must be the file's 32-byte SHA3-256")

    prk = await device_prk()
    dsa, _, succ = bpq.public_keys(prk, msg.context)
    signer = bpq_id(dsa, succ)

    if msg.binding is not None:
        b = msg.binding
        props = [("Identity", signer, True), ("Context", msg.context, False)]
        props.append(("Time", b.at, True))
        for c in sorted(b.claims, key=lambda c: c.kind):
            props.append((c.kind, c.value, True))
        await confirm_properties(
            "bpq_bind",
            "Bind identity",
            props,
            hold=True,
            br_code=ButtonRequestType.SignTx,
        )
        message = (
            b"bpq1/bind"
            + sha3_256((signer + "\n" + b.at + "\n" + lines).encode()).digest()
        )
    else:
        d = msg.detached
        assert d is not None
        props = [
            ("Identity", signer, True),
            ("Context", msg.context, False),
            ("Time", d.at, True),
            ("Size (bytes)", str(d.size), True),
            ("SHA3-256", hexlify(d.sha3).decode(), True),
        ]
        await confirm_properties(
            "bpq_detached",
            "Sign file",
            props,
            hold=True,
            br_code=ButtonRequestType.SignTx,
        )
        message = (
            b"bpq1/detached"
            + d.sha3
            + sha3_256((signer + "\n" + d.at + "\n" + str(d.size)).encode()).digest()
        )

    return BpqSignature(id=signer, signature=bpq.sign(prk, msg.context, message))
