//! Harness only. The module under test is the REAL file in the firmware tree,
//! mounted with #[path] so it compiles exactly as it does in core/embed/rust.
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]

pub mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

/// Mirrors core/embed/rust/src/crypto/mod.rs::Error so zano.rs sees the same shape.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    SignatureVerificationFailed,
    InvalidEncoding,
    InvalidParams,
    InvalidContext,
    AuthenticationFailed,
}

/// consteq.c calls this on a fault. The firmware supplies the real one; on host it
/// must abort loudly rather than be silently absent.
#[no_mangle]
pub extern "C" fn tc_fault_handler(_msg: *const core::ffi::c_char) {
    panic!("tc_fault_handler invoked");
}

#[path = "../../../../core/embed/rust/src/crypto/zano.rs"]
pub mod zano;

#[cfg(test)]
mod vector;

#[cfg(test)]
mod conformance {
    use super::vector as v;
    use super::zano::*;
    use super::Error;

    fn hex32(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    }

    /// The real gate: a signature the ZANO REFERENCE already accepted, marshalled
    /// through the Rust wrapper into the C verifier. If the wrapper mis-orders a
    /// field, mishandles the 1/8 convention, or gets the ring walk wrong, this fails.
    #[test]
    fn reference_accepted_signature_verifies_through_the_rust_wrapper() {
        init().expect("generator init");

        let ring: Vec<RingMember> = v::RING
            .iter()
            .map(|m| RingMember {
                stealth_address: hex32(m[0]),
                amount_commitment_div8: hex32(m[1]),
                blinded_asset_id_div8: hex32(m[2]),
            })
            .collect();

        let mut sig = Signature {
            c: hex32(v::C),
            r_g: [[0u8; 32]; MAX_RING_SIZE],
            r_x: [[0u8; 32]; MAX_RING_SIZE],
            k1: hex32(v::K1),
            k2: hex32(v::K2),
            ring_size: v::RING.len(),
        };
        for i in 0..v::RING.len() {
            sig.r_g[i] = hex32(v::RG[i]);
            sig.r_x[i] = hex32(v::RX[i]);
        }

        verify(&hex32(v::M), &ring, &hex32(v::PC), &hex32(v::PA), &hex32(v::KI), &sig)
            .expect("the reference accepted this signature; the wrapper must too");
    }

    /// Flipping one bit of the challenge must be rejected — otherwise the test above
    /// proves only that the function returns Ok, not that it is verifying anything.
    #[test]
    fn tampered_challenge_is_rejected() {
        init().unwrap();
        let ring: Vec<RingMember> = v::RING
            .iter()
            .map(|m| RingMember {
                stealth_address: hex32(m[0]),
                amount_commitment_div8: hex32(m[1]),
                blinded_asset_id_div8: hex32(m[2]),
            })
            .collect();
        let mut c = hex32(v::C);
        c[0] ^= 0x01;
        let mut sig = Signature {
            c,
            r_g: [[0u8; 32]; MAX_RING_SIZE],
            r_x: [[0u8; 32]; MAX_RING_SIZE],
            k1: hex32(v::K1),
            k2: hex32(v::K2),
            ring_size: v::RING.len(),
        };
        for i in 0..v::RING.len() {
            sig.r_g[i] = hex32(v::RG[i]);
            sig.r_x[i] = hex32(v::RX[i]);
        }
        assert_eq!(
            verify(&hex32(v::M), &ring, &hex32(v::PC), &hex32(v::PA), &hex32(v::KI), &sig),
            Err(Error::SignatureVerificationFailed)
        );
    }

    /// A malformed ring point must be an encoding error, not a panic and not a pass.
    /// This is the path where the inverted unpack return would have shown up.
    #[test]
    fn malformed_ring_point_is_rejected() {
        init().unwrap();
        let ring = vec![
            RingMember {
                // Probed, not assumed: 0xff*32 DECODES fine in donna. This one
                // ge25519_unpack_vartime genuinely rejects.
                stealth_address: {
                    let mut b = [0u8; 32];
                    b[0] = 0x02;
                    b
                },
                amount_commitment_div8: hex32(v::RING[0][1]),
                blinded_asset_id_div8: hex32(v::RING[0][2]),
            },
            RingMember {
                stealth_address: hex32(v::RING[1][0]),
                amount_commitment_div8: hex32(v::RING[1][1]),
                blinded_asset_id_div8: hex32(v::RING[1][2]),
            },
        ];
        let sig = Signature {
            c: hex32(v::C),
            r_g: [[0u8; 32]; MAX_RING_SIZE],
            r_x: [[0u8; 32]; MAX_RING_SIZE],
            k1: hex32(v::K1),
            k2: hex32(v::K2),
            ring_size: 2,
        };
        assert_eq!(
            verify(&hex32(v::M), &ring, &hex32(v::PC), &hex32(v::PA), &hex32(v::KI), &sig),
            Err(Error::InvalidEncoding)
        );
    }
}
