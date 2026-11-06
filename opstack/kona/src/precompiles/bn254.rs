//! Canonical G1 arithmetic with explicit infinity/exceptional-case handling.
//! The 4-bit window follows the already qualified evmone service integration;
//! input validation and scalar reduction precede partial affine service calls.
use super::modular::mul_add;
use alloy_primitives::{U256, uint};
use revm_precompile::PrecompileHalt;
#[cfg(not(target_arch = "riscv64"))]
use revm_precompile::{Crypto, DefaultCrypto};

const P: U256 = uint!(0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47_U256);
const ORDER: U256 = uint!(0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001_U256);
#[derive(Clone, Copy)]
struct Point {
    x: U256,
    y: U256,
}

fn decode(input: &[u8]) -> Result<Option<Point>, PrecompileHalt> {
    if input.len() != 64 {
        return Err(PrecompileHalt::Bn254FieldPointNotAMember);
    }
    let x = U256::from_be_slice(&input[..32]);
    let y = U256::from_be_slice(&input[32..]);
    if x >= P || y >= P {
        return Err(PrecompileHalt::Bn254FieldPointNotAMember);
    }
    if x.is_zero() && y.is_zero() {
        return Ok(None);
    }
    let x2 = mul_add(x, x, U256::ZERO, P);
    if mul_add(y, y, U256::ZERO, P) != mul_add(x2, x, U256::from(3), P) {
        return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
    }
    Ok(Some(Point { x, y }))
}
fn encode(point: Option<Point>) -> [u8; 64] {
    let mut bytes = [0; 64];
    if let Some(p) = point {
        bytes[..32].copy_from_slice(&p.x.to_be_bytes::<32>());
        bytes[32..].copy_from_slice(&p.y.to_be_bytes::<32>());
    }
    bytes
}
fn affine(p: Point, q: Point, double: bool) -> Point {
    #[cfg(target_arch = "riscv64")]
    {
        #[repr(C, align(32))]
        struct Packet([u64; 16]);
        let [x0, x1, x2, x3] = *p.x.as_limbs();
        let [y0, y1, y2, y3] = *p.y.as_limbs();
        let [u0, u1, u2, u3] = *q.x.as_limbs();
        let [v0, v1, v2, v3] = *q.y.as_limbs();
        let mut packet = Packet([
            x0, x1, x2, x3, y0, y1, y2, y3, u0, u1, u2, u3, v0, v1, v2, v3,
        ]);
        let tag = if double {
            0x0003_0101usize
        } else {
            0x0003_0100usize
        };
        // SAFETY: unique 32-aligned live packet; all inputs canonical. The
        // caller has discharged x1!=x2 / y!=0 before issuing these partial
        // affine services. Registers preserved; output overwrites x,y.
        unsafe {
            core::arch::asm!("ecall", in("a0") packet.0.as_mut_ptr(), in("a7") tag, options(nostack));
        }
        Point {
            x: U256::from_limbs([packet.0[0], packet.0[1], packet.0[2], packet.0[3]]),
            y: U256::from_limbs([packet.0[4], packet.0[5], packet.0[6], packet.0[7]]),
        }
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        let _ = double;
        let bytes = DefaultCrypto
            .bn254_g1_add(&encode(Some(p)), &encode(Some(q)))
            .expect("validated finite G1 service reference");
        Point {
            x: U256::from_be_slice(&bytes[..32]),
            y: U256::from_be_slice(&bytes[32..]),
        }
    }
}
fn sum(p: Option<Point>, q: Option<Point>) -> Option<Point> {
    let (p, q) = match (p, q) {
        (None, q) => return q,
        (p, None) => return p,
        (Some(p), Some(q)) => (p, q),
    };
    if p.x == q.x {
        if p.y != q.y || p.y.is_zero() {
            None
        } else {
            Some(affine(p, p, true))
        }
    } else {
        Some(affine(p, q, false))
    }
}
pub(super) fn add(p: &[u8], q: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
    Ok(encode(sum(decode(p)?, decode(q)?)))
}
pub(super) fn mul(point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
    // Decode even when scalar=0: malformed points must still be rejected.
    let p = decode(point)?;
    if scalar.len() != 32 {
        return Err(PrecompileHalt::Bn254FieldPointNotAMember);
    }
    let k = U256::from_be_slice(scalar) % ORDER;
    if p.is_none() || k.is_zero() {
        return Ok([0; 64]);
    }
    let mut table = [None; 16];
    table[1] = p;
    for i in 2..16 {
        table[i] = sum(table[i - 1], p);
    }
    let mut acc = None;
    for byte in k.to_be_bytes::<32>() {
        for digit in [byte >> 4, byte & 15] {
            if acc.is_some() {
                for _ in 0..4 {
                    acc = sum(acc, acc);
                }
            }
            if digit != 0 {
                acc = sum(acc, table[digit as usize]);
            }
        }
    }
    Ok(encode(acc))
}
