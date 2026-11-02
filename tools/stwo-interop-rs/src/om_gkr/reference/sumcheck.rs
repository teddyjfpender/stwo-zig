// Mechanically lifted from pinned Stwo; see provenance.json.
use super::utils::UnivariatePoly;
use crate::om_gkr::{Channel, SecureField};
use num_traits::{One, Zero};
use thiserror::Error;

pub fn partially_verify(
    mut claim: SecureField,
    proof: &SumcheckProof,
    channel: &mut impl Channel,
) -> Result<(Vec<SecureField>, SecureField), SumcheckError> {
    let mut assignment = Vec::new();

    for (round, round_poly) in proof.round_polys.iter().enumerate() {
        if round_poly.degree() > MAX_DEGREE {
            return Err(SumcheckError::DegreeInvalid { round });
        }

        // TODO: optimize this by sending one less coefficient, and computing it from the
        // claim, instead of checking the claim. (Can also be done by quotienting).
        let sum = round_poly.eval_at_point(Zero::zero()) + round_poly.eval_at_point(One::one());

        if claim != sum {
            return Err(SumcheckError::SumInvalid { claim, sum, round });
        }

        channel.mix_felts(round_poly);
        let challenge = channel.draw_secure_felt();
        claim = round_poly.eval_at_point(challenge);
        assignment.push(challenge);
    }

    Ok((assignment, claim))
}

#[derive(Debug, Clone)]
pub struct SumcheckProof {
    pub round_polys: Vec<UnivariatePoly<SecureField>>,
}

/// Max degree of polynomials the verifier accepts in each round of the protocol.
pub const MAX_DEGREE: usize = 3;

/// Sum-check protocol verification error.
#[derive(Error, Debug)]
pub enum SumcheckError {
    #[error("degree of the polynomial in round {round} is too high")]
    DegreeInvalid { round: RoundIndex },
    #[error("sum does not match the claim in round {round} (sum {sum}, claim {claim})")]
    SumInvalid {
        claim: SecureField,
        sum: SecureField,
        round: RoundIndex,
    },
}

/// Sum-check round index where 0 corresponds to the first round.
pub type RoundIndex = usize;
