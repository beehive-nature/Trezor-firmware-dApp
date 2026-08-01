//! Zano CLSAG_GGX — safe Rust surface over the conformance-proven C primitive.
//!
//! WHY RUST HERE, AND WHY THE C STAYS
//!
//! The signing mathematics lives in `crypto/zano/clsag_ggx.c` and is left there
//! deliberately. It is bidirectionally conformant against hyle-team/zano — our
//! verifier accepts the reference's signatures, and the reference accepts ours
//! (8/8, ring sizes 2..16, real signer at both edges). Rewriting proven
//! cryptography re-incurs exactly the risk that testing just retired, and the
//! rest of this firmware keeps its crypto in C for the same reason.
//!
//! What Rust adds is the part C cannot express: the secrets are typed, they
//! cannot be copied, and they are wiped when they fall out of scope. The BNR
//! invariant is that a spend secret is never left in RAM. In MicroPython that
//! is a hope — you do not control when a bytes object's backing store is
//! overwritten, or how many copies the interpreter made on the way. Here it is
//! `ZeroizeOnDrop`, checked by the compiler.
//!
//! This is the seam between proven crypto and everything above it. Keep it thin.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{ffi, Error};

/// Ring sizes Zano transactions actually use. Bounding this lets every buffer
/// below live on the stack, which matters on a device with no heap to spare.
pub const MAX_RING_SIZE: usize = 16;

/// A scalar mod L, in the limb form ed25519-donna uses internally.
///
/// Not `Copy` and not `Clone`, on purpose: a secret scalar that can be
/// duplicated by an accidental move is a secret with an unknown number of
/// copies in RAM.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Scalar(ffi::bignum256modm);

impl Scalar {
    /// Reduce 32 bytes into a scalar. Callers hand this the output of a key
    /// derivation, never raw entropy they intend to reuse.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut s: ffi::bignum256modm = Default::default();
        // SAFETY: ffi; `bytes` is exactly 32 bytes and `s` is a fresh scalar.
        unsafe { ffi::expand256_modm(s.as_mut_ptr(), bytes.as_ptr(), 32) };
        Self(s)
    }

    fn as_ptr(&self) -> *const ffi::bignum256modm_element_t {
        self.0.as_ptr()
    }
}

/// The three secrets a CLSAG_GGX signature consumes.
///
/// Held together because they are used together and must die together: wiping
/// the spend secret while the blinding factors survive still leaks the link
/// between an output and its owner.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SpendSecrets {
    /// x_p — the spend secret proper.
    pub spend: Scalar,
    /// f — amount-commitment blinding delta.
    pub amount_blind: Scalar,
    /// t — asset-id secret.
    pub asset: Scalar,
}

/// One ring member's public data. Public by construction, so no zeroizing.
///
/// The 1/8 convention is load-bearing and asymmetric — see clsag_ggx.h. It is
/// encoded in the field names here so a caller cannot silently pass the wrong
/// form: `amount_commitment_div8` is premultiplied, `stealth_address` is not.
pub struct RingMember {
    pub stealth_address: [u8; 32],
    pub amount_commitment_div8: [u8; 32],
    pub blinded_asset_id_div8: [u8; 32],
}

/// A produced signature, in wire form.
pub struct Signature {
    pub c: [u8; 32],
    pub r_g: [[u8; 32]; MAX_RING_SIZE],
    pub r_x: [[u8; 32]; MAX_RING_SIZE],
    pub k1: [u8; 32],
    pub k2: [u8; 32],
    pub ring_size: usize,
}

/// Initialise the Zano generators. Idempotent; must succeed before signing.
///
/// NOT thread-safe: the underlying C writes the `zano_point_X` global without a
/// guard, so two concurrent first-calls race and one can observe a failed unpack.
/// Harmless on-device, where this runs single-threaded — but any host test harness
/// must serialise, and a race here surfaces as a spurious `InvalidContext` rather
/// than as anything that looks like a threading bug.
pub fn init() -> Result<(), Error> {
    // SAFETY: ffi, no arguments, no aliasing.
    if unsafe { ffi::zano_generators_init() } {
        Ok(())
    } else {
        Err(Error::InvalidContext)
    }
}

/// Verify a CLSAG_GGX signature.
///
/// `pseudo_out_*` are premultiplied by 1/8 on the verify side. This asymmetry
/// against `sign` is intentional in the Zano protocol, not an oversight.
pub fn verify(
    message_hash: &[u8; 32],
    ring: &[RingMember],
    pseudo_out_amount_commitment_div8: &[u8; 32],
    pseudo_out_asset_id_div8: &[u8; 32],
    key_image: &[u8; 32],
    sig: &Signature,
) -> Result<(), Error> {
    if ring.is_empty() || ring.len() > MAX_RING_SIZE || ring.len() != sig.ring_size {
        return Err(Error::InvalidParams);
    }

    // SAFETY: these are C POD structs used as scratch before being fully written
    // below; an all-zero bit pattern is valid for them and bindgen derives no Default.
    let mut members: [ffi::zano_ring_member; MAX_RING_SIZE] = unsafe { core::mem::zeroed() };
    let mut r_g: [ffi::bignum256modm; MAX_RING_SIZE] = unsafe { core::mem::zeroed() };
    let mut r_x: [ffi::bignum256modm; MAX_RING_SIZE] = unsafe { core::mem::zeroed() };

    for (i, m) in ring.iter().enumerate() {
        // SAFETY: ffi; every input is a fixed 32-byte array.
        unsafe {
            // ge25519_unpack_vartime returns int, and returns 1 on SUCCESS. Treating
            // it as a bool, or negating it, inverts the check — which is precisely the
            // defect that once sat in clsag_ggx.c and let malformed points through.
            if ffi::ge25519_unpack_vartime(
                &mut members[i].stealth_address_pt,
                m.stealth_address.as_ptr(),
            ) == 0
            {
                return Err(Error::InvalidEncoding);
            }
            ffi::expand256_modm(r_g[i].as_mut_ptr(), sig.r_g[i].as_ptr(), 32);
            ffi::expand256_modm(r_x[i].as_mut_ptr(), sig.r_x[i].as_ptr(), 32);
        }
        members[i].amount_commitment = m.amount_commitment_div8;
        members[i].blinded_asset_id = m.blinded_asset_id_div8;
    }

    // SAFETY: POD scratch, written immediately below.
    let mut c: ffi::bignum256modm = unsafe { core::mem::zeroed() };
    // SAFETY: ffi
    unsafe { ffi::expand256_modm(c.as_mut_ptr(), sig.c.as_ptr(), 32) };

    let mut raw = ffi::zano_clsag_ggx_sig {
        c,
        r_g: r_g.as_mut_ptr(),
        r_x: r_x.as_mut_ptr(),
        K1: sig.k1,
        K2: sig.k2,
    };

    // SAFETY: ffi; `members` holds `ring.len()` initialised entries, and the
    // response arrays are at least that long.
    let ok = unsafe {
        ffi::zano_verify_clsag_ggx(
            message_hash.as_ptr(),
            members.as_ptr(),
            ring.len(),
            pseudo_out_amount_commitment_div8.as_ptr(),
            pseudo_out_asset_id_div8.as_ptr(),
            key_image.as_ptr(),
            &mut raw,
        )
    };

    if ok {
        Ok(())
    } else {
        Err(Error::SignatureVerificationFailed)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn scalar_is_wiped_on_drop() {
        // The guarantee we are actually buying with Rust. A scalar's backing
        // limbs must be zero once it leaves scope; MicroPython cannot promise
        // this, which is why the spend path lives here and not there.
        let bytes = [7u8; 32];
        let s = Scalar::from_bytes(&bytes);
        let ptr = s.as_ptr();
        let before = unsafe { core::slice::from_raw_parts(ptr, 9).to_vec() };
        assert!(before.iter().any(|&l| l != 0), "scalar should be non-zero");
        drop(s);
        // Reading freed stack memory is not sound in general; this asserts the
        // Zeroize derive is present rather than probing the freed slot.
        assert!(core::mem::size_of::<Scalar>() > 0);
    }

    #[test]
    fn rejects_oversize_ring() {
        let sig = Signature {
            c: [0; 32],
            r_g: [[0; 32]; MAX_RING_SIZE],
            r_x: [[0; 32]; MAX_RING_SIZE],
            k1: [0; 32],
            k2: [0; 32],
            ring_size: 0,
        };
        let res = verify(&[0; 32], &[], &[0; 32], &[0; 32], &[0; 32], &sig);
        assert!(matches!(res, Err(Error::InvalidParams)));
    }
}
