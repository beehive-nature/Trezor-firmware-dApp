from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import BpqCard, BpqGetCard


async def get_card(msg: BpqGetCard) -> BpqCard:
    """The device's SPEC-BPQ-1 §3 card for a context.

    The card signature covers only the device's own public keys
    ("bpq1/card" || dsa || kem || succ), so it authorizes nothing and is made
    without a confirmation, like an address. With show_display the id is shown
    first.
    """
    from trezorcrypto import bpq

    from trezor.messages import BpqCard
    from trezor.ui.layouts import show_address

    from .common import bpq_id, check_context, device_prk

    check_context(msg.context)
    prk = await device_prk()
    dsa, kem, succ = bpq.public_keys(prk, msg.context)
    card_id = bpq_id(dsa, succ)

    if msg.show_display:
        await show_address(
            card_id,
            title="Post-quantum identity",
            subtitle=msg.context,
            path=None,
            account=None,
        )

    sig = bpq.sign(prk, msg.context, b"bpq1/card" + dsa + kem + succ)
    return BpqCard(
        id=card_id,
        dsa_public_key=dsa,
        kem_public_key=kem,
        succession_commit=succ,
        signature=sig,
    )
