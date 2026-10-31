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
