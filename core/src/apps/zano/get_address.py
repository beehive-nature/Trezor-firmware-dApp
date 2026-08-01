from typing import TYPE_CHECKING

from apps.common.keychain import auto_keychain

if TYPE_CHECKING:
    from trezor.messages import ZanoAddress, ZanoGetAddress

    from apps.common.keychain import Keychain


@auto_keychain(__name__)
async def get_address(msg: ZanoGetAddress, keychain: Keychain) -> ZanoAddress:
    import trezorzano
    from trezor.messages import ZanoAddress
    from trezor.ui.layouts import show_address

    from apps.common import paths
    from apps.monero.xmr import crypto_helpers, monero

    from . import PATTERN, SLIP44_ID

    address_n = msg.address_n  # local_cache_attribute

    await paths.validate_path(keychain, address_n)

    node = keychain.derive(address_n)

    # Zano and Monero share the key derivation exactly. The reference's
    # account.cpp calls dependent_key(spend, view), and crypto.cpp:119 shows that is
    # hash_to_scalar(&first, 32, second) — cn_fast_hash then sc_reduce32 — which is
    # precisely what generate_monero_keys does. Reusing it is not a shortcut; it is
    # the same algorithm, already shipped and exercised.
    _, spend_pub, _, view_pub = monero.generate_monero_keys(node.private_key())

    address = trezorzano.address_from_keys(
        crypto_helpers.encodepoint(spend_pub),
        crypto_helpers.encodepoint(view_pub),
    )

    if msg.show_display:
        await show_address(
            address,
            path=paths.address_n_to_str(address_n),
            account=paths.get_account_name("ZANO", address_n, PATTERN, SLIP44_ID),
            chunkify=bool(msg.chunkify),
        )

    return ZanoAddress(address=address)
