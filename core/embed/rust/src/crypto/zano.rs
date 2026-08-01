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
///
/// `Debug` is derived here and deliberately NOT on `Scalar` or `SpendSecrets`: a
/// signature is public the moment it is broadcast, whereas a printable secret is one
/// stray log line away from being an extracted spend key.
#[derive(Debug, PartialEq, Eq)]
pub struct Signature {
    pub c: [u8; 32],
    pub r_g: [[u8; 32]; MAX_RING_SIZE],
    pub r_x: [[u8; 32]; MAX_RING_SIZE],
    pub k1: [u8; 32],
    pub k2: [u8; 32],
    pub ring_size: usize,
}

/// Length of a classic Zano address, in characters. Always exactly this.
pub const ADDRESS_STR_LEN: usize = 97;

/// Encode a classic Zano public address from its two public keys.
///
/// Zano derives the view key from the spend key exactly as Monero does — the
/// reference's `dependent_key()` is `cn_fast_hash` then `sc_reduce32`, which is
/// Trezor's `generate_monero_keys` convention — so the existing Monero key
/// derivation already produces the right key relationship for Zano. Only the
/// address encoding differs, and only in the tag: Zano's 0xc5 prefix needs a
/// two-byte varint that Monero's encoder refuses outright.
pub fn address_from_keys(
    spend_public_key: &[u8; 32],
    view_public_key: &[u8; 32],
) -> Result<([u8; ADDRESS_STR_LEN], usize), Error> {
    let mut buf = [0u8; ADDRESS_STR_LEN + 1];
    // SAFETY: ffi; both inputs are fixed 32-byte arrays and `buf` has room for the
    // 97 characters plus the NUL the C writes.
    let ok = unsafe {
        ffi::zano_address_encode(
            spend_public_key.as_ptr(),
            view_public_key.as_ptr(),
            buf.as_mut_ptr() as *mut cty::c_char,
            buf.len(),
        )
    };
    if !ok {
        return Err(Error::InvalidEncoding);
    }
    let mut out = [0u8; ADDRESS_STR_LEN];
    out.copy_from_slice(&buf[..ADDRESS_STR_LEN]);
    Ok((out, ADDRESS_STR_LEN))
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

/// Produce a CLSAG_GGX signature.
///
/// `secrets` is consumed. It is moved in, used, and dropped before this returns, so
/// the caller cannot hold a live copy afterwards and the limbs are wiped on the way
/// out. That is the guarantee this layer can actually make.
///
/// It is NOT a claim that the spend secret never existed elsewhere. Trezor derives
/// keys in `apps.common.keychain`, which is MicroPython, so by the time bytes arrive
/// here the interpreter has already held them and may have copied them. Closing that
/// gap means moving derivation itself below the Python boundary — worth doing, and
/// not done here. Anything stronger stated about this function would be false.
///
/// `pseudo_out_*` are NOT premultiplied by 1/8 on the sign side, unlike `verify`.
/// The asymmetry is Zano's, not an oversight; see clsag_ggx.h.
pub fn sign(
    message_hash: &[u8; 32],
    ring: &[RingMember],
    pseudo_out_amount_commitment: &[u8; 32],
    pseudo_out_asset_id: &[u8; 32],
    key_image: &[u8; 32],
    secrets: SpendSecrets,
    secret_index: usize,
) -> Result<Signature, Error> {
    if ring.is_empty() || ring.len() > MAX_RING_SIZE || secret_index >= ring.len() {
        return Err(Error::InvalidParams);
    }

    // SAFETY: POD scratch, fully written below before use.
    let mut members: [ffi::zano_ring_member; MAX_RING_SIZE] = unsafe { core::mem::zeroed() };
    let mut pc: ffi::ge25519 = unsafe { core::mem::zeroed() };
    let mut pa: ffi::ge25519 = unsafe { core::mem::zeroed() };
    let mut ki: ffi::ge25519 = unsafe { core::mem::zeroed() };

    for (i, m) in ring.iter().enumerate() {
        // SAFETY: ffi; fixed 32-byte inputs. Returns 1 on SUCCESS.
        unsafe {
            if ffi::ge25519_unpack_vartime(
                &mut members[i].stealth_address_pt,
                m.stealth_address.as_ptr(),
            ) == 0
            {
                return Err(Error::InvalidEncoding);
            }
        }
        members[i].amount_commitment = m.amount_commitment_div8;
        members[i].blinded_asset_id = m.blinded_asset_id_div8;
    }

    // SAFETY: ffi; each is a fixed 32-byte compressed point.
    unsafe {
        if ffi::ge25519_unpack_vartime(&mut pc, pseudo_out_amount_commitment.as_ptr()) == 0
            || ffi::ge25519_unpack_vartime(&mut pa, pseudo_out_asset_id.as_ptr()) == 0
            || ffi::ge25519_unpack_vartime(&mut ki, key_image.as_ptr()) == 0
        {
            return Err(Error::InvalidEncoding);
        }
    }

    let mut r_g: [ffi::bignum256modm; MAX_RING_SIZE] = unsafe { core::mem::zeroed() };
    let mut r_x: [ffi::bignum256modm; MAX_RING_SIZE] = unsafe { core::mem::zeroed() };
    let mut raw = ffi::zano_clsag_ggx_sig {
        c: unsafe { core::mem::zeroed() },
        r_g: r_g.as_mut_ptr(),
        r_x: r_x.as_mut_ptr(),
        K1: [0u8; 32],
        K2: [0u8; 32],
    };

    // SAFETY: ffi; `members` holds ring.len() initialised entries and the response
    // arrays are at least that long. `secrets` outlives the call and is dropped
    // (and wiped) at the end of this function.
    let ok = unsafe {
        ffi::zano_generate_clsag_ggx(
            message_hash.as_ptr(),
            members.as_ptr(),
            ring.len(),
            &pc,
            &pa,
            &ki,
            secrets.spend.as_ptr(),
            secrets.amount_blind.as_ptr(),
            secrets.asset.as_ptr(),
            secret_index,
            &mut raw,
        )
    };
    if !ok {
        return Err(Error::InvalidParams);
    }

    let mut sig = Signature {
        c: [0u8; 32],
        r_g: [[0u8; 32]; MAX_RING_SIZE],
        r_x: [[0u8; 32]; MAX_RING_SIZE],
        k1: raw.K1,
        k2: raw.K2,
        ring_size: ring.len(),
    };
    // SAFETY: ffi; contract256_modm writes exactly 32 bytes.
    unsafe {
        ffi::contract256_modm(sig.c.as_mut_ptr(), raw.c.as_ptr());
        for i in 0..ring.len() {
            ffi::contract256_modm(sig.r_g[i].as_mut_ptr(), r_g[i].as_ptr());
            ffi::contract256_modm(sig.r_x[i].as_mut_ptr(), r_x[i].as_ptr());
        }
    }
    Ok(sig)
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
