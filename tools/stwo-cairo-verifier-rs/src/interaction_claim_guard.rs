//! Compatibility guards for proof claims not constrained by the pinned oracle.

use crate::CanonicalVerificationFailure;
use cairo_air::CairoProofForRustVerifier;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;

pub(crate) fn validate_memory_id_to_big_aggregate(
    proof: &CairoProofForRustVerifier<Blake2sMerkleHasher>,
) -> Result<(), CanonicalVerificationFailure> {
    let Some(claim) = proof.interaction_claim.memory_id_to_big.as_ref() else {
        return Ok(());
    };
    if aggregate_is_consistent(&claim.big_claimed_sums, claim.claimed_sum) {
        return Ok(());
    }
    Err(CanonicalVerificationFailure::new(
        "invalid_interaction_claim",
        "memory_id_to_big.claimed_sum is not the sum of its transcript-bound segment claims",
    ))
}

fn aggregate_is_consistent(segment_sums: &[SecureField], claimed_sum: SecureField) -> bool {
    segment_sums
        .iter()
        .copied()
        .fold(SecureField::default(), |total, value| total + value)
        == claimed_sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_must_be_derived_from_all_sixteen_segments() {
        let segment_sums = (0_u32..16)
            .map(|index| SecureField::from_u32_unchecked(index + 1, index + 2, 0, 0))
            .collect::<Vec<_>>();
        let derived = segment_sums
            .iter()
            .copied()
            .fold(SecureField::default(), |total, value| total + value);
        assert!(aggregate_is_consistent(&segment_sums, derived));

        for omitted in 0..segment_sums.len() {
            let incomplete = segment_sums
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != omitted)
                .map(|(_, value)| *value)
                .fold(SecureField::default(), |total, value| total + value);
            assert!(!aggregate_is_consistent(&segment_sums, incomplete));
        }
    }
}
