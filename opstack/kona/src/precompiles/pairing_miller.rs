//! BN254 Miller loop borrowing validated Arkworks line coefficients. Use one
//! accumulator across the bounded request and collapse identical G2 terms by
//! e(P,Q)e(R,Q)=e(P+R,Q) after both points have been validated.
use super::PreparedG2;
use alloc::sync::Arc;
use ark_bn254::{Bn254, Config, Fq12, G1Affine, G1Projective};
use ark_ec::{
    AffineRepr, CurveGroup,
    bn::BnConfig,
    pairing::{MillerLoopOutput, Pairing},
};
use ark_ff::{Field, One};

pub(super) fn check(groups: &mut [(G1Affine, Option<G1Projective>, Arc<PreparedG2>)]) -> bool {
    for (point, sum, _) in groups.iter_mut() {
        if let Some(sum) = sum.take() {
            *point = sum.into_affine();
        }
    }
    if groups.iter().all(|(point, _, _)| point.is_zero()) {
        return true;
    }
    let mut value = Fq12::ONE;
    let mut line = 0;
    let mut evaluate = |value: &mut Fq12| {
        for (point, _, prepared) in groups.iter() {
            if point.is_zero() {
                continue;
            }
            let (mut c0, mut c1, c2) = prepared.ell_coeffs[line];
            // BN254's D twist uses the sparse 034 line placement.
            c0.mul_assign_by_fp(&point.y);
            c1.mul_assign_by_fp(&point.x);
            value.mul_by_034(&c0, &c1, &c2);
        }
        line += 1;
    };
    let count = Config::ATE_LOOP_COUNT;
    for i in (1..count.len()).rev() {
        if i != count.len() - 1 {
            value.square_in_place();
        }
        evaluate(&mut value);
        if count[i - 1] != 0 {
            evaluate(&mut value);
        }
    }
    // The pinned BN254 parameter X is positive. Ark's prepared coefficients
    // end with the two Frobenius correction lines in this order.
    comptime_bn254_parameters();
    evaluate(&mut value);
    evaluate(&mut value);
    Bn254::final_exponentiation(MillerLoopOutput(value)).is_some_and(|output| output.0.is_one())
}

const fn comptime_bn254_parameters() {
    const {
        assert!(!Config::X_IS_NEGATIVE);
        assert!(matches!(Config::TWIST_TYPE, ark_ec::bn::TwistType::D));
    }
}
