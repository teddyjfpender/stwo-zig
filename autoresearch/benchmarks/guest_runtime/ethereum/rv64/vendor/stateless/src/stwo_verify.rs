//! stwo: batched ECDSA verification against the supplied public keys.
//!
//! Upstream recovers each sender from its signature (`recover_signer`: a
//! square root to decompress `R`, a scalar inversion of `r` and a field
//! inversion to normalize the key) and compares the address with the one of
//! the supplied key. Here the supplied key `Q` is checked directly:
//!
//! * `Q` is a canonical uncompressed point on the curve, `r, s` in
//!   `[1, n)`; a high `s` (pre-Homestead only) is negated and the parity
//!   flipped, exactly as the recovery path normalizes it;
//! * `R' = z s^-1 G + r s^-1 Q` has affine `x = r` and `y` parity `v`.
//!
//! This accepts exactly when recovery returns `Q` (up to Keccak collisions,
//! as upstream's address comparison): if it holds, `R'` is the point recovery
//! decompresses from `(r, v)` and `r^-1 (s R' - z G) = Q`; conversely a
//! recovered `Q` gives `s R = z G + r Q`, so `R = R'`. No square root is
//! needed, and the `s` inversions and the normalizations of all `R'` of the
//! block each share one inversion (Montgomery's trick).
use crate::{recover_block::UncompressedPublicKey, validation::StatelessValidationError};
use alloc::vec::Vec;
use alloy_primitives::{Address, B256, Signature};
use k256::{
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar, U256,
    elliptic_curve::{
        BatchNormalize, PrimeField,
        ops::{Invert, LinearCombination, Reduce},
        point::AffineCoordinates,
        scalar::IsHigh,
        sec1::FromEncodedPoint,
    },
};

struct Pending {
    r: Scalar,
    r_bytes: FieldBytes,
    s: Scalar,
    z: Scalar,
    q: ProjectivePoint,
    y_odd: bool,
}

fn nonzero_scalar(bytes: FieldBytes) -> Option<Scalar> {
    let s: Option<Scalar> = Scalar::from_repr(bytes).into();
    s.filter(|s| !bool::from(s.is_zero()))
}

fn prepare(
    vk: &UncompressedPublicKey,
    sig: &Signature,
    sig_hash: B256,
) -> Result<Pending, StatelessValidationError> {
    let err = || StatelessValidationError::SignerRecovery;
    let encoded = EncodedPoint::from_bytes(&vk.0[..]).map_err(|_| err())?;
    let q: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
    let q = q.ok_or_else(err)?;
    let r_bytes = FieldBytes::from(sig.r().to_be_bytes::<32>());
    let r = nonzero_scalar(r_bytes).ok_or_else(err)?;
    let mut s = nonzero_scalar(FieldBytes::from(sig.s().to_be_bytes::<32>())).ok_or_else(err)?;
    let mut y_odd = sig.v();
    if bool::from(s.is_high()) {
        s = -s;
        y_odd = !y_odd;
    }
    let z = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(sig_hash.0));
    Ok(Pending { r, r_bytes, s, z, q: ProjectivePoint::from(q), y_odd })
}

/// Verifies every `(public key, signature, signature hash)` of a block and
/// returns the senders in order. `expected` are the addresses of the keys.
pub(crate) fn verify_senders(
    items: Vec<(&UncompressedPublicKey, &Signature, B256)>,
    expected: Vec<Address>,
) -> Result<Vec<Address>, StatelessValidationError> {
    let pending =
        items.iter().map(|(vk, sig, h)| prepare(vk, sig, *h)).collect::<Result<Vec<_>, _>>()?;
    if pending.is_empty() {
        return Ok(expected);
    }
    // s^-1 for all signatures with one inversion
    let mut prefix = Vec::with_capacity(pending.len());
    let mut acc = Scalar::ONE;
    for p in &pending {
        acc *= p.s;
        prefix.push(acc);
    }
    let inv: Option<Scalar> = acc.invert_vartime().into();
    let mut inv = inv.ok_or(StatelessValidationError::SignerRecovery)?;
    let mut points = alloc::vec![ProjectivePoint::IDENTITY; pending.len()];
    for i in (0..pending.len()).rev() {
        let w = if i == 0 { inv } else { inv * prefix[i - 1] };
        inv *= pending[i].s;
        let p = &pending[i];
        points[i] = ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, &(p.z * w), &p.q, &(p.r * w));
    }
    let affine = <ProjectivePoint as BatchNormalize<[ProjectivePoint]>>::batch_normalize(&points);
    for (a, p) in affine.iter().zip(&pending) {
        // x = r >= 1 also rules out the identity (whose x encodes as zero)
        if a.x() != p.r_bytes || bool::from(a.y_is_odd()) != p.y_odd {
            return Err(StatelessValidationError::SignerRecovery);
        }
    }
    Ok(expected)
}
