use std::env;
use std::path::PathBuf;

const CRYPTO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    // 1. Build the real C primitive, exactly as build_test.sh does.
    let mut b = cc::Build::new();
    b.include(CRYPTO)
        .include(format!("{}/ed25519-donna", CRYPTO))
        .include(format!("{}/monero", CRYPTO))
        .define("ED25519_CUSTOMRANDOM", None)
        .define("ED25519_CUSTOMHASH", None)
        .define("ED25519_NO_INLINE_ASM", None)
        .define("ED25519_FORCE_32BIT", "1")
        .define("USE_KECCAK", "1")
        .define("USE_MONERO", "1")
        .warnings(false);
    for f in [
        "zano/clsag_ggx.c", "zano/zano_generators.c",
        "ed25519-donna/ed25519-donna-impl-base.c",
        "ed25519-donna/ed25519-donna-32bit-tables.c",
        "ed25519-donna/ed25519-donna-basepoint-table.c",
        "ed25519-donna/modm-donna-32bit.c",
        "ed25519-donna/curve25519-donna-32bit.c",
        "ed25519-donna/curve25519-donna-helpers.c",
        "ed25519-donna/curve25519-donna-scalarmult-base.c",
        "ed25519-donna/ed25519-keccak.c", "ed25519-donna/ed25519.c",
        "sha3.c", "hasher.c", "blake256.c", "blake2b.c", "groestl.c",
        "sha2.c", "ripemd160.c", "memzero.c", "consteq.c",
        "monero/xmr.c", "monero/serialize.c", "rand.c",
    ] {
        b.file(format!("{}/{}", CRYPTO, f));
    }
    b.compile("zanocrypto");

    // 2. Generate bindings from the SAME header the firmware crypto.h pulls in,
    //    with the SAME allowlist entries added to build.rs.
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", CRYPTO))
        .clang_arg(format!("-I{}/ed25519-donna", CRYPTO))
        .clang_arg("-DED25519_CUSTOMRANDOM")
        .clang_arg("-DED25519_CUSTOMHASH")
        .clang_arg("-DED25519_NO_INLINE_ASM")
        .clang_arg("-DED25519_FORCE_32BIT=1")
        .clang_arg("-DUSE_KECCAK=1")
        .clang_arg("-DUSE_MONERO=1")
        .use_core()
        .allowlist_type("zano_ring_member")
        .allowlist_type("zano_clsag_ggx_sig")
        .allowlist_function("zano_generators_init")
        .allowlist_function("zano_generate_clsag_ggx")
        .allowlist_function("zano_verify_clsag_ggx")
        .allowlist_type("bignum256modm")
        .allowlist_type("bignum256modm_element_t")
        .allowlist_type("ge25519")
        .allowlist_function("expand256_modm")
        .allowlist_function("contract256_modm")
        .allowlist_function("ge25519_unpack_vartime")
        .allowlist_function("ge25519_pack")
        .generate()
        .expect("bindgen failed on the zano header");
    bindings.write_to_file(out.join("bindings.rs")).unwrap();
}
