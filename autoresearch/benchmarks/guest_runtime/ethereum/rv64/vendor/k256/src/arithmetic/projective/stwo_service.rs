//! Optional RV64 Ethereum-services v1 lowering. The unchanged software formulas
//! remain the host reference; production results require the constrained group
//! service and its authenticated CPU/RAM bridge, not trust in host computation.
use super::{FieldElement, ProjectivePoint};
#[cfg(not(feature = "stwo-projective-word-service"))]
use crate::FieldBytes;
use abi::{AddPacket, DoublePacket};
#[cfg(not(feature = "stwo-projective-word-service"))]
use stwo_rv64_service_abi as abi;
#[cfg(feature = "stwo-projective-word-service")]
use stwo_rv64_service_abi::words as abi;
#[cfg(not(feature = "stwo-projective-word-service"))]
type Coordinate = [u8; 32];
#[cfg(feature = "stwo-projective-word-service")]
type Coordinate = [u64; 4];

// Inline fixed-size packet conversion so callers write their destination
// directly instead of materializing and copying a second projective tuple.
#[inline(always)]
fn encode(point: &ProjectivePoint) -> [Coordinate; 3] {
    #[cfg(not(feature = "stwo-projective-word-service"))]
    {
        [
            point.x.to_bytes().into(),
            point.y.to_bytes().into(),
            point.z.to_bytes().into(),
        ]
    }
    #[cfg(feature = "stwo-projective-word-service")]
    {
        [
            point.x.stwo_to_words(),
            point.y.stwo_to_words(),
            point.z.stwo_to_words(),
        ]
    }
}
// Inline fixed-size packet conversion so callers write their destination
// directly instead of materializing and copying a second projective tuple.
#[inline(always)]
fn decode(words: &[Coordinate]) -> ProjectivePoint {
    #[cfg(not(feature = "stwo-projective-word-service"))]
    let field = |bytes: &Coordinate| FieldElement::from_bytes(&FieldBytes::from(*bytes)).unwrap();
    #[cfg(feature = "stwo-projective-word-service")]
    let field = |words: &Coordinate| FieldElement::stwo_from_words(*words).unwrap();
    ProjectivePoint {
        x: field(&words[0]),
        y: field(&words[1]),
        z: field(&words[2]),
    }
}

pub(super) fn add(lhs: &ProjectivePoint, rhs: &ProjectivePoint) -> ProjectivePoint {
    let left = encode(lhs);
    let right = encode(rhs);
    let mut packet = AddPacket([left[0], left[1], left[2], right[0], right[1], right[2]]);
    #[cfg(target_arch = "riscv64")]
    abi::add(&mut packet);
    #[cfg(not(target_arch = "riscv64"))]
    {
        let result = decode(&packet.0[..3]).add_software(&decode(&packet.0[3..]));
        packet.0[..3].copy_from_slice(&encode(&result));
    }
    decode(&packet.0[..3])
}

pub(super) fn double(point: &ProjectivePoint) -> ProjectivePoint {
    let mut packet = DoublePacket(encode(point));
    #[cfg(target_arch = "riscv64")]
    abi::double(&mut packet);
    #[cfg(not(target_arch = "riscv64"))]
    {
        let result = decode(&packet.0).double_software();
        packet.0 = encode(&result);
    }
    decode(&packet.0)
}

/// Word-packet point arithmetic that never leaves the service representation.
/// A scalar multiplication chain feeds each service result straight into the
/// next packet, so no per-call field normalization or limb repacking occurs.
/// Variable-time call sites only: the digits and points are public ECDSA data.
#[cfg(feature = "stwo-vartime")]
pub(crate) mod words {
    use super::super::ProjectivePoint;
    use super::{decode, encode, Coordinate};
    use stwo_rv64_service_abi::words as abi;

    pub type Point = [Coordinate; 3];
    /// Canonical projective identity (0 : 1 : 0).
    pub const IDENTITY: Point = [[0; 4], [1, 0, 0, 0], [0; 4]];
    const FIELD_MODULUS: [u64; 4] = [0xffff_fffe_ffff_fc2f, u64::MAX, u64::MAX, u64::MAX];

    #[inline(always)]
    pub fn from_point(point: &ProjectivePoint) -> Point {
        encode(point)
    }
    #[inline(always)]
    pub fn to_point(point: &Point) -> ProjectivePoint {
        decode(&point[..])
    }
    pub fn add_assign(acc: &mut Point, rhs: &Point) {
        let mut packet = abi::AddPacket([acc[0], acc[1], acc[2], rhs[0], rhs[1], rhs[2]]);
        #[cfg(target_arch = "riscv64")]
        abi::add(&mut packet);
        #[cfg(not(target_arch = "riscv64"))]
        {
            let result = decode(&packet.0[..3]).add_software(&decode(&packet.0[3..]));
            packet.0[..3].copy_from_slice(&encode(&result));
        }
        acc.copy_from_slice(&packet.0[..3]);
    }
    pub fn double_assign(acc: &mut Point) {
        let mut packet = abi::DoublePacket(*acc);
        #[cfg(target_arch = "riscv64")]
        abi::double(&mut packet);
        #[cfg(not(target_arch = "riscv64"))]
        {
            let result = decode(&packet.0).double_software();
            packet.0 = encode(&result);
        }
        *acc = packet.0;
    }
    /// (X : Y : Z) -> (X : p - Y : Z). Service outputs are canonical, so the
    /// result stays canonical; the identity (Y = 1) maps to (0 : p - 1 : 0),
    /// which is the same projective point.
    pub fn negate_assign(point: &mut Point) {
        let y = &mut point[1];
        if *y == [0; 4] {
            return;
        }
        let mut borrow = 0u64;
        for (limb, modulus) in y.iter_mut().zip(FIELD_MODULUS) {
            let (first, b1) = modulus.overflowing_sub(*limb);
            let (second, b2) = first.overflowing_sub(borrow);
            *limb = second;
            borrow = (b1 | b2) as u64;
        }
        debug_assert_eq!(borrow, 0);
    }
}
