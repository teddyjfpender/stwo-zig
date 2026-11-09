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

pub(super) type Group = (G1Affine, Option<G1Projective>, Arc<PreparedG2>);

pub(super) fn normalize(groups: &mut [Group]) -> bool {
    for (point, sum, _) in groups.iter_mut() {
        if let Some(sum) = sum.take() {
            *point = sum.into_affine();
        }
    }
    groups.iter().any(|(point, _, _)| !point.is_zero())
}

#[cfg(any(test, not(feature = "pairing-hints")))]
pub(super) fn check(groups: &[Group]) -> bool {
    check_value(run(groups, None))
}

pub(super) fn check_value(value: Fq12) -> bool {
    Bn254::final_exponentiation(MillerLoopOutput(value)).is_some_and(|o| o.0.is_one())
}

/// With a checked inverse, the same signed loop computes f * seed^(6x+2).
pub(super) fn run(groups: &[Group], seed: Option<(&Fq12, &Fq12)>) -> Fq12 {
    run_skipping(groups, seed, 0)
}

pub(super) fn run_skipping(groups: &[Group], seed: Option<(&Fq12, &Fq12)>, skip: u16) -> Fq12 {
    let mut value = seed.map_or(Fq12::ONE, |(w, _)| *w);
    let mut line = 0;
    let mut evaluate = |value: &mut Fq12| {
        for (i, (point, _, prepared)) in groups.iter().enumerate() {
            if point.is_zero() || (skip != 0 && (skip >> i) & 1 != 0) {
                continue;
            }
            let coefficients = &prepared.ell_coeffs[line];
            // BN254's D twist scales c0 by y and c1 by x before sparse034.
            #[cfg(feature = "pairing-sparse-service")]
            super::sparse::miller_line(
                value,
                &coefficients.0,
                &coefficients.1,
                &coefficients.2,
                &point.x,
                &point.y,
            );
            #[cfg(not(feature = "pairing-sparse-service"))]
            {
                let (mut c0, mut c1, c2) = *coefficients;
                c0.mul_assign_by_fp(&point.y);
                c1.mul_assign_by_fp(&point.x);
                value.mul_by_034(&c0, &c1, &c2);
            }
        }
        line += 1;
    };
    let count = Config::ATE_LOOP_COUNT;
    for i in (1..count.len()).rev() {
        if seed.is_some() || i != count.len() - 1 {
            value.square_in_place();
        }
        evaluate(&mut value);
        let digit = count[i - 1];
        if digit != 0 {
            if let Some((w, inverse)) = seed {
                value *= if digit == 1 { w } else { inverse };
            }
            evaluate(&mut value);
        }
    }
    // The pinned BN254 parameter X is positive. Ark's prepared coefficients
    // end with the two Frobenius correction lines in this order.
    comptime_bn254_parameters();
    evaluate(&mut value);
    evaluate(&mut value);
    value
}

const fn comptime_bn254_parameters() {
    const {
        assert!(!Config::X_IS_NEGATIVE);
        assert!(matches!(Config::TWIST_TYPE, ark_ec::bn::TwistType::D));
    }
}
