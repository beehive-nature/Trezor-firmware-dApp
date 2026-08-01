//! MicroPython surface for Zano CLSAG_GGX.
//!
//! WHERE THE BOUNDARY IS DRAWN, AND WHY
//!
//! One call does the whole signature. Python hands in the ring, the message, the
//! pseudo-outs, the key image and the three secrets; Rust marshals, signs, wipes, and
//! returns wire bytes. Python never sees a scalar, an intermediate, or the challenge
//! before it is final, so there is no partial state for interpreter-side code to hold
//! or leak, and no way to drive the signer into an inconsistent sequence.
//!
//! What this does NOT do — stated plainly, because the opposite is easy to imply:
//! Trezor derives keys in `apps.common.keychain`, which is MicroPython. By the time
//! secret bytes reach this module the interpreter has already held them and may have
//! copied them, and nothing here can retract that. What is guaranteed is narrower and
//! real: the Rust-side copy is typed, moved, used once, and wiped by ZeroizeOnDrop.
//! Closing the remaining gap means moving derivation below the Python boundary. That
//! is worth doing and is not done here.

use crate::micropython::{
    buffer::get_buffer,
    macros::{obj_fn_0, obj_fn_2, obj_fn_kw, obj_module},
    map::Map,
    module::Module,
    obj::Obj,
    qstr::Qstr,
    util,
};

use super::zano::{self, RingMember, Scalar, Signature, SpendSecrets, MAX_RING_SIZE};

/// Pull exactly 32 bytes out of a Python buffer, refusing anything else.
///
/// A short buffer here would be read past by the C, and a long one would silently
/// ignore the tail — the class of defect that publishes a truncated address.
fn arg32(map: &Map, key: Qstr) -> Result<[u8; 32], crate::error::Error> {
    let obj = map.get(key)?;
    // SAFETY: the buffer is borrowed for the duration of this call only.
    let slice = unsafe { get_buffer(obj)? };
    if slice.len() != 32 {
        return Err(crate::error::value_error!(c"expected exactly 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Serialise a signature into the flat wire layout the host protocol expects:
///   c ‖ K1 ‖ K2 ‖ r_g[0..n] ‖ r_x[0..n]
fn signature_bytes(sig: &Signature) -> Result<Obj, crate::error::Error> {
    let n = sig.ring_size;
    let mut buf = [0u8; 32 * 3 + 32 * MAX_RING_SIZE * 2];
    let mut o = 0;
    buf[o..o + 32].copy_from_slice(&sig.c);
    o += 32;
    buf[o..o + 32].copy_from_slice(&sig.k1);
    o += 32;
    buf[o..o + 32].copy_from_slice(&sig.k2);
    o += 32;
    for i in 0..n {
        buf[o..o + 32].copy_from_slice(&sig.r_g[i]);
        o += 32;
    }
    for i in 0..n {
        buf[o..o + 32].copy_from_slice(&sig.r_x[i]);
        o += 32;
    }
    buf[..o].try_into()
}

/// Collect a list of 32-byte buffers.
///
/// Three parallel lists rather than a list of triples: `(Obj, Obj, Obj)` has no
/// `TryFrom<Obj>`, so nested destructuring does not compile, and flat `repeated bytes`
/// is the shape protobuf will carry anyway. Length agreement between the three is
/// checked by the caller, which is where a mismatch is actually meaningful.
fn read_b32_list(
    obj: Obj,
) -> Result<heapless::Vec<[u8; 32], MAX_RING_SIZE>, crate::error::Error> {
    let mut out: heapless::Vec<[u8; 32], MAX_RING_SIZE> = heapless::Vec::new();
    for item in crate::micropython::iter::IterBuf::new().try_iterate(obj)? {
        // SAFETY: the buffer is borrowed only within this iteration.
        let b = unsafe { get_buffer(item)? };
        if b.len() != 32 {
            return Err(crate::error::value_error!(c"ring entries must be 32 bytes"));
        }
        let mut e = [0u8; 32];
        e.copy_from_slice(b);
        out.push(e)
            .map_err(|_| crate::error::value_error!(c"ring too large"))?;
    }
    Ok(out)
}

/// Read the ring from three parallel lists: stealth addresses, amount commitments,
/// blinded asset ids. Premultiplication conventions are as documented in clsag_ggx.h —
/// commitments and asset ids are 1/8, stealth addresses are not.
fn read_ring(
    p: Obj,
    a: Obj,
    t: Obj,
) -> Result<heapless::Vec<RingMember, MAX_RING_SIZE>, crate::error::Error> {
    let (ps, as_, ts) = (read_b32_list(p)?, read_b32_list(a)?, read_b32_list(t)?);
    if ps.is_empty() {
        return Err(crate::error::value_error!(c"ring must not be empty"));
    }
    if ps.len() != as_.len() || ps.len() != ts.len() {
        return Err(crate::error::value_error!(
            c"ring lists must be the same length"
        ));
    }
    let mut ring: heapless::Vec<RingMember, MAX_RING_SIZE> = heapless::Vec::new();
    for i in 0..ps.len() {
        ring.push(RingMember {
            stealth_address: ps[i],
            amount_commitment_div8: as_[i],
            blinded_asset_id_div8: ts[i],
        })
        .map_err(|_| crate::error::value_error!(c"ring too large"))?;
    }
    Ok(ring)
}

extern "C" fn py_address_from_keys(spend: Obj, view: Obj) -> Obj {
    let block = || {
        // SAFETY: buffers borrowed only for the duration of this call.
        let (sb, vb) = unsafe { (get_buffer(spend)?, get_buffer(view)?) };
        if sb.len() != 32 || vb.len() != 32 {
            return Err(crate::error::value_error!(c"keys must be 32 bytes"));
        }
        let mut s = [0u8; 32];
        let mut v = [0u8; 32];
        s.copy_from_slice(sb);
        v.copy_from_slice(vb);
        let (addr, n) = zano::address_from_keys(&s, &v)?;
        // A Zano classic address is ASCII base58, so this is a str, not bytes.
        let text = core::str::from_utf8(&addr[..n])
            .map_err(|_| crate::error::value_error!(c"address is not valid ascii"))?;
        text.try_into()
    };
    unsafe { util::try_or_raise(block) }
}

extern "C" fn py_generators_init() -> Obj {
    let block = || {
        zano::init()?;
        Ok(Obj::const_none())
    };
    unsafe { util::try_or_raise(block) }
}

extern "C" fn py_sign(_n_args: usize, _args: *const Obj, kwargs: *mut Map) -> Obj {
    let block = |_args: &[Obj], kwargs: &Map| {
        let ring = read_ring(
            kwargs.get(Qstr::MP_QSTR_ring_stealth_addresses)?,
            kwargs.get(Qstr::MP_QSTR_ring_amount_commitments)?,
            kwargs.get(Qstr::MP_QSTR_ring_blinded_asset_ids)?,
        )?;
        let msg = arg32(kwargs, Qstr::MP_QSTR_message_hash)?;
        let pc = arg32(kwargs, Qstr::MP_QSTR_pseudo_out_amount_commitment)?;
        let pa = arg32(kwargs, Qstr::MP_QSTR_pseudo_out_asset_id)?;
        let ki = arg32(kwargs, Qstr::MP_QSTR_key_image)?;
        let index: usize = kwargs.get(Qstr::MP_QSTR_secret_index)?.try_into()?;

        // Absorbed into zeroizing types immediately; the Python-side bytes are the
        // caller's problem and cannot be reached from here.
        let secrets = SpendSecrets {
            spend: Scalar::from_bytes(&arg32(kwargs, Qstr::MP_QSTR_secret_spend)?),
            amount_blind: Scalar::from_bytes(&arg32(kwargs, Qstr::MP_QSTR_secret_amount_blind)?),
            asset: Scalar::from_bytes(&arg32(kwargs, Qstr::MP_QSTR_secret_asset)?),
        };

        let sig = zano::sign(&msg, &ring, &pc, &pa, &ki, secrets, index)?;
        signature_bytes(&sig)
    };
    unsafe { util::try_with_args_and_kwargs(_n_args, _args, kwargs, block) }
}

#[no_mangle]
#[rustfmt::skip]
pub static mp_module_trezorzano: Module = obj_module! {
    Qstr::MP_QSTR___name__ => Qstr::MP_QSTR_trezorzano.to_obj(),

    /// mock:global

    /// def generators_init() -> None:
    ///     """
    ///     Initialise the Zano generator constants. Idempotent. Must succeed before
    ///     signing. Not thread-safe, which is irrelevant on device and matters only
    ///     to host harnesses.
    ///     """
    Qstr::MP_QSTR_generators_init => obj_fn_0!(py_generators_init).as_obj(),

    /// def address_from_keys(spend_public_key: bytes, view_public_key: bytes) -> str:
    ///     """
    ///     Encode a classic Zano public address. Always exactly 97 characters,
    ///     beginning "Zx".
    ///
    ///     Zano derives the view key from the spend key the same way Monero does
    ///     (cn_fast_hash then sc_reduce32), so the existing Monero key derivation
    ///     produces the right keys; only this encoding differs.
    ///     """
    Qstr::MP_QSTR_address_from_keys => obj_fn_2!(py_address_from_keys).as_obj(),

    /// def sign(
    ///     *,
    ///     message_hash: bytes,
    ///     ring_stealth_addresses: list[bytes],
    ///     ring_amount_commitments: list[bytes],
    ///     ring_blinded_asset_ids: list[bytes],
    ///     pseudo_out_amount_commitment: bytes,
    ///     pseudo_out_asset_id: bytes,
    ///     key_image: bytes,
    ///     secret_spend: bytes,
    ///     secret_amount_blind: bytes,
    ///     secret_asset: bytes,
    ///     secret_index: int,
    /// ) -> bytes:
    ///     """
    ///     Produce a CLSAG_GGX ring signature in one call.
    ///
    ///     Returns c ‖ K1 ‖ K2 ‖ r_g[0..n] ‖ r_x[0..n], all 32-byte little-endian.
    ///
    ///     The ring is three parallel lists of equal length. amount_commitments and
    ///     blinded_asset_ids are premultiplied by 1/8; stealth_addresses are not.
    ///     pseudo_out_* are NOT premultiplied on this side —
    ///     the asymmetry against verification is Zano's, not an oversight.
    ///
    ///     The three secrets are consumed and wiped before this returns. That is a
    ///     guarantee about this layer only: whatever held them before the call is
    ///     beyond its reach.
    ///     """
    Qstr::MP_QSTR_sign => obj_fn_kw!(0, py_sign).as_obj(),
};
