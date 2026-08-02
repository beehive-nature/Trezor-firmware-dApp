# Does one custom firmware give both Vaulta and Zano?
#
# Vaulta is EOS. Upstream support.json marks eos "not for T3W1 (#2793)" — the app
# exists and is gated off by model. This fork's SConscript sets USE_EOS=1 for T3W1,
# so the question is whether that actually produces a working app or just a flag.

fail = 0


def unhex(s):
    return bytes(int(s[i : i + 2], 16) for i in range(0, len(s), 2))


print("=== EOS / Vaulta ===")
try:
    from trezor.enums import MessageType
    from apps import workflow_handlers

    h = workflow_handlers._find_message_handler_module(MessageType.EosGetPublicKey)
    print("  EosGetPublicKey ->", h)
    import apps.eos.get_public_key as eos_gpk

    print("  [ok] eos app imports")
    from trezor.messages import EosGetPublicKey, EosSignTx

    print("  [ok] eos wire messages present:", EosGetPublicKey.MESSAGE_WIRE_TYPE,
          EosSignTx.MESSAGE_WIRE_TYPE)
except Exception as e:
    print("  [FAIL]", type(e).__name__, e)
    fail += 1

print()
print("=== Zano ===")
try:
    from trezor.enums import MessageType
    from apps import workflow_handlers

    h = workflow_handlers._find_message_handler_module(MessageType.ZanoGetAddress)
    print("  ZanoGetAddress ->", h)
    import trezorzano

    a = trezorzano.address_from_keys(
        unhex("3a9f316c2eceb38591737031b2fc39daaf379caaab786878b80ea658cf1e02ff"),
        unhex("00b51be3b5821c592a4b21fb2e83c7ea1c792f9e164cac96c1e7b3118b5cb36b"),
    )
    print("  address:", a[:24] + "..." + a[-8:], f"({len(a)} chars)")
    print("  [ok] matches chain" if a.startswith("ZxCDR2aG") and len(a) == 97
          else "  [FAIL] wrong address")
except Exception as e:
    print("  [FAIL]", type(e).__name__, e)
    fail += 1

print()
print("=== what else does this firmware carry? ===")
for name, mod in (
    ("bitcoin", "apps.bitcoin.get_address"),
    ("ethereum", "apps.ethereum.get_address"),
    ("solana", "apps.solana.get_address"),
    ("ripple", "apps.ripple.get_address"),
    ("stellar", "apps.stellar.get_address"),
    ("monero", "apps.monero.get_address"),
    ("nem", "apps.nem.get_address"),
):
    try:
        __import__(mod)
        print(f"  [ok]      {name}")
    except Exception as e:
        print(f"  [absent]  {name}  ({type(e).__name__})")

print()
print("FAILURES:" if fail else "BOTH PRESENT", fail if fail else "")
