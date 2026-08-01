use core::hint::black_box;

use crate::error::value_error;

pub mod aesgcm;
pub mod cosi;
pub mod crc32;
pub mod curve25519;
pub mod ed25519;
mod ffi;
pub mod hmac;
pub mod memory;
pub mod merkle;
pub mod sha256;
pub mod sha512;
pub mod zano;
// UNCOMPILED. Written to the obj_module!/obj_fn_kw pattern and every API it uses was
// checked to exist, but it needs the micropython feature, which needs SCons-generated
// qstrs and headers. It has never been through a compiler. Gated so it cannot break a
// build that does not ask for it; do not treat it as working until a firmware build says so.
#[cfg(feature = "micropython")]
pub mod zano_micropython;

#[cfg_attr(feature = "test", derive(core::fmt::Debug))]
pub enum Error {
    // Signature verification failed
    SignatureVerificationFailed,
    // Provided value is not a valid public key / signature / etc.
    InvalidEncoding,
    // Provided parameters are not accepted (e.g., signature threshold out of bounds)
    InvalidParams,
    // State precondition check failed (possibly raised by C implementation)
    InvalidContext,
    // Authentication failed (e.g. AEAD tag mismatch)
    AuthenticationFailed,
}

impl From<Error> for crate::error::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::SignatureVerificationFailed => value_error!(c"Signature verification failed"),
            Error::InvalidEncoding => value_error!(c"Invalid key or signature encoding"),
            Error::InvalidParams => value_error!(c"Invalid cryptographic parameters"),
            Error::InvalidContext => value_error!(c"Invalid cryptographic context"),
            Error::AuthenticationFailed => value_error!(c"Authentication failed"),
        }
    }
}

/// Constant time bytestring comparison for two arrays of the same length.
fn consteq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..N {
        diff |= a[i] ^ b[i];
    }
    black_box(black_box(diff) == 0)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_consteq() {
        assert!(consteq(&[], &[]));
        assert!(consteq(&[0u8; 256], &[0u8; 256]));
        assert!(consteq(&[0xffu8; 256], &[0xffu8; 256]));
        assert!(consteq(b"0123456789abcdef", b"0123456789abcdef"));

        assert!(!consteq(&[0u8; 256], &[0xffu8; 256]));
        assert!(!consteq(&[0xffu8; 256], &[0u8; 256]));
        assert!(!consteq(b"0123456789abcdef", b"123456789abcdef0"));
        assert!(!consteq(b"0000000000000000", b"0000000000000001"));
    }
}
