use core::mem;
use core::ops::Deref;

use serde::{Deserialize, Serialize};
use std_shims::Vec;
use thiserror::Error;

use crate::core::circle::CirclePoint;
use crate::core::fields::m31::BaseField;
use crate::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
use crate::core::fri::{FriLayerProof, FriProof};
use crate::core::pcs::quotients::{CommitmentSchemeProof, CommitmentSchemeProofAux};
use crate::core::pcs::TreeVec;
use crate::core::vcs::hash::Hash;
use crate::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use crate::core::vcs_lifted::verifier::MerkleDecommitmentLifted;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkProof<H: MerkleHasherLifted>(pub CommitmentSchemeProof<H>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtendedStarkProof<H: MerkleHasherLifted> {
    pub proof: StarkProof<H>,
    pub aux: CommitmentSchemeProofAux<H>,
}

impl<H: MerkleHasherLifted> StarkProof<H> {
    /// Returns the estimate size (in bytes) of the proof.
    pub fn size_estimate(&self) -> usize {
        SizeEstimate::size_estimate(self)
    }

    /// Returns size estimates (in bytes) for different parts of the proof.
    pub fn size_breakdown_estimate(&self) -> StarkProofSizeBreakdown {
        let Self(commitment_scheme_proof) = self;

        let CommitmentSchemeProof {
            commitments,
            sampled_values,
            decommitments,
            queried_values,
            proof_of_work: _,
            fri_proof,
            config: _,
        } = commitment_scheme_proof;

        let FriProof {
            first_layer,
            inner_layers,
            last_layer_poly,
        } = fri_proof;

        let mut inner_layers_samples_size = 0;
        let mut inner_layers_hashes_size = 0;

        for FriLayerProof {
            fri_witness,
            decommitment,
            commitment,
        } in inner_layers
        {
            inner_layers_samples_size += fri_witness.size_estimate();
            inner_layers_hashes_size += decommitment.size_estimate() + commitment.size_estimate();
        }

        StarkProofSizeBreakdown {
            oods_samples: sampled_values.size_estimate(),
            queries_values: queried_values.size_estimate(),
            fri_samples: last_layer_poly.size_estimate()
                + inner_layers_samples_size
                + first_layer.fri_witness.size_estimate(),
            fri_decommitments: inner_layers_hashes_size
                + first_layer.decommitment.size_estimate()
                + first_layer.commitment.size_estimate(),
            trace_decommitments: commitments.size_estimate() + decommitments.size_estimate(),
        }
    }
}

/// Reconstructs the split composition opening and compares it with the
/// composition value evaluated from trace openings. Malformed masks fail closed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CompositionOodsValidationError {
    #[error("malformed composition OODS opening")]
    InvalidStructure,
    #[error("composition OODS opening does not match trace evaluation")]
    Mismatch,
}

pub fn validate_composition_oods(
    sampled_values: &TreeVec<Vec<Vec<SecureField>>>,
    oods_point: CirclePoint<SecureField>,
    max_log_degree_bound: u32,
    evaluate_from_trace: impl FnOnce() -> SecureField,
) -> Result<(), CompositionOodsValidationError> {
    let Some(composition_mask) = sampled_values.last() else {
        return Err(CompositionOodsValidationError::InvalidStructure);
    };
    let Some(coordinates): Option<[SecureField; 2 * SECURE_EXTENSION_DEGREE]> = composition_mask
        .iter()
        .map(|column| {
            let &[eval] = column.as_slice() else {
                return None;
            };
            Some(eval)
        })
        .collect::<Option<Vec<_>>>()
        .and_then(|values| values.try_into().ok())
    else {
        return Err(CompositionOodsValidationError::InvalidStructure);
    };
    let (left, right) = coordinates.split_at(SECURE_EXTENSION_DEGREE);
    let Some(left) = left.try_into().ok().map(SecureField::from_partial_evals) else {
        return Err(CompositionOodsValidationError::InvalidStructure);
    };
    let Some(right) = right.try_into().ok().map(SecureField::from_partial_evals) else {
        return Err(CompositionOodsValidationError::InvalidStructure);
    };
    let Some(split_log_degree_bound) = max_log_degree_bound.checked_sub(1) else {
        return Err(CompositionOodsValidationError::InvalidStructure);
    };
    if left + oods_point.repeated_double(split_log_degree_bound).x * right != evaluate_from_trace()
    {
        return Err(CompositionOodsValidationError::Mismatch);
    }
    Ok(())
}

#[cfg(test)]
mod composition_oods_tests {
    use super::*;

    #[test]
    fn composition_oods_matches_fails_closed_on_corruption_or_shape_drift() {
        let zero = SecureField::default();
        let one = SecureField::from(1u32);
        let point = CirclePoint { x: one, y: zero };
        let assert_invalid_without_evaluation =
            |sampled_values: &TreeVec<Vec<Vec<SecureField>>>, max_log_degree_bound| {
                assert_eq!(
                    validate_composition_oods(
                        sampled_values,
                        point,
                        max_log_degree_bound,
                        || panic!("invalid structure must be rejected before trace evaluation"),
                    ),
                    Err(CompositionOodsValidationError::InvalidStructure)
                );
            };
        let mut sampled_values = TreeVec(vec![
            vec![vec![zero]],
            vec![vec![zero]; 2 * SECURE_EXTENSION_DEGREE],
        ]);
        assert_eq!(
            validate_composition_oods(&sampled_values, point, 2, || zero),
            Ok(())
        );
        assert_eq!(
            validate_composition_oods(&sampled_values, point, 2, || one),
            Err(CompositionOodsValidationError::Mismatch)
        );

        sampled_values[1][0][0] = one;
        assert_eq!(
            validate_composition_oods(&sampled_values, point, 2, || zero),
            Err(CompositionOodsValidationError::Mismatch)
        );
        assert_invalid_without_evaluation(&sampled_values, 0);
        assert_invalid_without_evaluation(&TreeVec(vec![]), 2);

        let mut empty_column = sampled_values.clone();
        empty_column[1][0].clear();
        assert_invalid_without_evaluation(&empty_column, 2);
        let mut double_sample = sampled_values.clone();
        double_sample[1][0].push(zero);
        assert_invalid_without_evaluation(&double_sample, 2);

        sampled_values[1].pop();
        assert_invalid_without_evaluation(&sampled_values, 2);
    }
}

impl<H: MerkleHasherLifted> Deref for StarkProof<H> {
    type Target = CommitmentSchemeProof<H>;

    fn deref(&self) -> &CommitmentSchemeProof<H> {
        &self.0
    }
}

/// Size estimate (in bytes) for different parts of the proof.
#[derive(Debug)]
pub struct StarkProofSizeBreakdown {
    pub oods_samples: usize,
    pub queries_values: usize,
    pub fri_samples: usize,
    pub fri_decommitments: usize,
    pub trace_decommitments: usize,
}

trait SizeEstimate {
    fn size_estimate(&self) -> usize;
}

impl<T: SizeEstimate> SizeEstimate for [T] {
    fn size_estimate(&self) -> usize {
        self.iter().map(|v| v.size_estimate()).sum()
    }
}

impl<T: SizeEstimate> SizeEstimate for Vec<T> {
    fn size_estimate(&self) -> usize {
        self.iter().map(|v| v.size_estimate()).sum()
    }
}

impl<H: Hash> SizeEstimate for H {
    fn size_estimate(&self) -> usize {
        mem::size_of::<Self>()
    }
}

impl SizeEstimate for BaseField {
    fn size_estimate(&self) -> usize {
        mem::size_of::<Self>()
    }
}

impl SizeEstimate for SecureField {
    fn size_estimate(&self) -> usize {
        mem::size_of::<Self>()
    }
}

impl<H: MerkleHasherLifted> SizeEstimate for MerkleDecommitmentLifted<H> {
    fn size_estimate(&self) -> usize {
        let Self { hash_witness } = self;
        hash_witness.size_estimate()
    }
}

impl<H: MerkleHasherLifted> SizeEstimate for FriLayerProof<H> {
    fn size_estimate(&self) -> usize {
        let Self {
            fri_witness,
            decommitment,
            commitment,
        } = self;
        fri_witness.size_estimate() + decommitment.size_estimate() + commitment.size_estimate()
    }
}

impl<H: MerkleHasherLifted> SizeEstimate for FriProof<H> {
    fn size_estimate(&self) -> usize {
        let Self {
            first_layer,
            inner_layers,
            last_layer_poly,
        } = self;
        first_layer.size_estimate() + inner_layers.size_estimate() + last_layer_poly.size_estimate()
    }
}

impl<H: MerkleHasherLifted> SizeEstimate for CommitmentSchemeProof<H> {
    fn size_estimate(&self) -> usize {
        let Self {
            commitments,
            sampled_values,
            decommitments,
            queried_values,
            proof_of_work,
            fri_proof,
            config,
        } = self;
        commitments.size_estimate()
            + sampled_values.size_estimate()
            + decommitments.size_estimate()
            + queried_values.size_estimate()
            + mem::size_of_val(proof_of_work)
            + fri_proof.size_estimate()
            + mem::size_of_val(config)
    }
}

impl<H: MerkleHasherLifted> SizeEstimate for StarkProof<H> {
    fn size_estimate(&self) -> usize {
        let Self(commitment_scheme_proof) = self;
        commitment_scheme_proof.size_estimate()
    }
}

#[cfg(test)]
mod tests {
    use num_traits::One;

    use crate::core::fields::m31::BaseField;
    use crate::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
    use crate::core::proof::SizeEstimate;

    #[test]
    fn test_base_field_size_estimate() {
        assert_eq!(BaseField::one().size_estimate(), 4);
    }

    #[test]
    fn test_secure_field_size_estimate() {
        assert_eq!(
            SecureField::one().size_estimate(),
            4 * SECURE_EXTENSION_DEGREE
        );
    }
}
