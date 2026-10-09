from typing import *
from buffer_types import *


# rust/src/crypto/zano_micropython.rs
def generators_init() -> None:
    """
    Initialise the Zano generator constants. Idempotent. Must succeed before
    signing. Not thread-safe, which is irrelevant on device and matters only
    to host harnesses.
    """


# rust/src/crypto/zano_micropython.rs
def address_from_keys(spend_public_key: bytes, view_public_key: bytes) -> str:
    """
    Encode a classic Zano public address. Always exactly 97 characters,
    beginning "Zx".
    Zano derives the view key from the spend key the same way Monero does
    (cn_fast_hash then sc_reduce32), so the existing Monero key derivation
    produces the right keys; only this encoding differs.
    """


# rust/src/crypto/zano_micropython.rs
def sign(
    *,
    message_hash: bytes,
    ring_stealth_addresses: list[bytes],
    ring_amount_commitments: list[bytes],
    ring_blinded_asset_ids: list[bytes],
    pseudo_out_amount_commitment: bytes,
    pseudo_out_asset_id: bytes,
    key_image: bytes,
    secret_spend: bytes,
    secret_amount_blind: bytes,
    secret_asset: bytes,
    secret_index: int,
) -> bytes:
    """
    Produce a CLSAG_GGX ring signature in one call.
    Returns c ‖ K1 ‖ K2 ‖ r_g[0..n] ‖ r_x[0..n], all 32-byte little-endian.
    The ring is three parallel lists of equal length. amount_commitments and
    blinded_asset_ids are premultiplied by 1/8; stealth_addresses are not.
    pseudo_out_* are NOT premultiplied on this side —
    the asymmetry against verification is Zano's, not an oversight.
    The three secrets are consumed and wiped before this returns. That is a
    guarantee about this layer only: whatever held them before the call is
    beyond its reach.
    """
