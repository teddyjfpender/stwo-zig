//! Optional joint-window BN254 GLV over the existing admitted affine services.
//! Constants and bounds: `opstack/tools/derive_bn254_glv.py`. No scalar hint,
//! unverified quotient or new relation enters the guest.
use super::{ORDER, P, Point, mul_add, sum};
use alloy_primitives::{U256, U512, uint};
const A: U256 = uint!(0x6f4d8248eeb859fc8211bbeb7d4f1128_U256);
const B: U256 = uint!(0x89d3256894d213e3_U256);
const C: U256 = uint!(0x6f4d8248eeb859fd0be4e1541221250b_U256);
const RECIP_C: U256 = uint!(0x24ccef014a773d2d25398fd0300ff6565_U256);
const RECIP_B: U256 = uint!(0x2d91d232ec7e0b3d7_U256);
const BETA: U256 = uint!(0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48_U256);

fn quotient(k: U256, coefficient: U256, reciprocal: U256) -> U256 {
    let estimate: U512 = k.widening_mul(reciprocal);
    let limbs = estimate.as_limbs();
    // k<r and coefficient<C<2^127, hence both quotients fit two limbs.
    let q = U256::from_limbs([limbs[4], limbs[5], 0, 0]);
    let numerator: U512 = k.widening_mul(coefficient);
    let multiple: U512 = q.widening_mul(ORDER);
    q + U256::from((numerator - multiple) >= U512::from(ORDER))
}
fn split(k: U256) -> (u128, u128, bool) {
    let u = quotient(k, C, RECIP_C);
    let v = quotient(k, B, RECIP_B);
    let k1 = k - u * A - v * B;
    let lhs = u * B;
    let rhs = v * C;
    let (k2, positive) = if lhs >= rhs {
        (lhs - rhs, true)
    } else {
        (rhs - lhs, false)
    };
    // Checked conversion is intentional: a future constant change must not
    // silently discard the scalar's high bits.
    (
        k1.try_into().expect("GLV k1 bound"),
        k2.try_into().expect("GLV k2 bound"),
        positive,
    )
}
pub(super) fn mul(point: Point, k: U256) -> Option<Point> {
    let (k1, k2, positive) = split(k);
    let mut table = [None; 16];
    table[1] = Some(point);
    for i in 2..16 {
        table[i] = sum(table[i - 1], Some(point));
    }
    let mut endo = [None; 16];
    if k2 != 0 {
        for i in 1..16 {
            endo[i] = table[i].map(|p| Point {
                x: mul_add(p.x, BETA, U256::ZERO, P),
                y: if positive || p.y.is_zero() {
                    p.y
                } else {
                    P - p.y
                },
            });
        }
    }
    let mut acc = None;
    for (a, b) in k1.to_be_bytes().into_iter().zip(k2.to_be_bytes()) {
        for shift in [4, 0] {
            if acc.is_some() {
                for _ in 0..4 {
                    acc = sum(acc, acc);
                }
            }
            let x = (a >> shift) & 15;
            let y = (b >> shift) & 15;
            if x != 0 {
                acc = sum(acc, table[x as usize]);
            }
            if y != 0 {
                acc = sum(acc, endo[y as usize]);
            }
        }
    }
    acc
}
#[cfg(test)]
#[path = "bn254_glv_tests.rs"]
mod tests;
