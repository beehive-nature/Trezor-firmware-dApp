from typing import *
from buffer_types import *


# upymod/modtrezorcrypto/modtrezorcrypto-bpq.h
def public_keys(prk: AnyBytes, context: str) -> tuple[bytes, bytes, bytes]:
    """
    SPEC-BPQ-1 public keys for (prk, context): the ML-DSA-65 public key,
    the X-Wing public key and the succession commitment.
    """


# upymod/modtrezorcrypto/modtrezorcrypto-bpq.h
def sign(prk: AnyBytes, context: str, message: AnyBytes) -> bytes:
    """
    Hedged ML-DSA-65 signature (FIPS 204, empty context string) over
    message with the key for (prk, context).
    """


# upymod/modtrezorcrypto/modtrezorcrypto-bpq.h
def verify(public_key: AnyBytes, message: AnyBytes,
           signature: AnyBytes) -> bool:
    """
    True when signature is a valid ML-DSA-65 signature (empty context
    string) of message under public_key.
    """


# upymod/modtrezorcrypto/modtrezorcrypto-bpq.h
def mldsa65_public_key(seed: AnyBytes) -> bytes:
    """
    ML-DSA-65 public key from a 32-byte KeyGen seed (FIPS 204 KeyGen_internal).
    """


# upymod/modtrezorcrypto/modtrezorcrypto-bpq.h
def xwing_public_key(seed: AnyBytes) -> bytes:
    """
    X-Wing public key (ML-KEM-768 ek || X25519) from a 32-byte seed.
    """


# upymod/modtrezorcrypto/modtrezorcrypto-bpq.h
def mlkem768_public_key(coins: AnyBytes) -> bytes:
    """
    ML-KEM-768 encapsulation key from d || z (FIPS 203 KeyGen_internal).
    """
