//! NOTE: retained from the original stwo-metal project; only [`MetalLineEvaluation`] is
//! currently consumed. The commitment/decommitment helpers await integration with the
//! current FRI prover and are kept for the follow-up.
#![allow(dead_code)]

use std::array;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SecureField, QM31};
use stwo::core::fri::{ExtendedFriLayerProof, FriLayerProof, FriLayerProofAux};
use stwo::core::poly::circle::CircleDomain;
use stwo::core::poly::line::LineDomain;
use stwo::core::queries::Queries;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::vcs_lifted::verifier::{
    ExtendedMerkleDecommitmentLifted, MerkleDecommitmentLifted, MerkleDecommitmentLiftedAux,
};

use super::fri;
use crate::columns::base_field_vec::BaseFieldVec;
use crate::columns::secure_field_vec::SecureFieldVec;

type LineIfftFactorCache =
    Mutex<BTreeMap<(usize, usize, u32), Arc<stwo_backend_metal_sys::metal::U32Buffer>>>;

fn line_ifft_factor_cache() -> &'static LineIfftFactorCache {
    static CACHE: OnceLock<LineIfftFactorCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn cached_line_ifft_inverse_factors(
    domain: LineDomain,
) -> Arc<stwo_backend_metal_sys::metal::U32Buffer> {
    let coset = domain.coset();
    let key = (coset.initial_index.0, coset.step_size.0, domain.log_size());
    if let Some(factors) = line_ifft_factor_cache()
        .lock()
        .expect("line IFFT factor cache mutex should not be poisoned")
        .get(&key)
        .cloned()
    {
        return factors;
    }

    let mut stage_domain = domain;
    let mut factors = Vec::with_capacity(domain.size().saturating_sub(1));
    while stage_domain.size() > 1 {
        factors.extend(
            stage_domain
                .iter()
                .take(stage_domain.size() / 2)
                .map(|x| x.inverse().0),
        );
        stage_domain = stage_domain.double();
    }

    let factors = Arc::new(
        stwo_backend_metal_sys::metal::U32Buffer::from_slice(&factors)
            .expect("Metal line IFFT factor upload should initialize"),
    );
    line_ifft_factor_cache()
        .lock()
        .expect("line IFFT factor cache mutex should not be poisoned")
        .insert(key, factors.clone());
    factors
}

pub fn interpolate_line_polynomial(
    evaluation: &MetalLineEvaluation,
) -> stwo::core::poly::line::LinePoly {
    let domain = evaluation.domain();
    let len = evaluation.len();

    if len == 1 {
        return stwo::core::poly::line::LinePoly::new(vec![evaluation.values().get_data(0)]);
    }

    let inverse_line_factors = cached_line_ifft_inverse_factors(domain);
    let scale_factor = BaseField::from_u32_unchecked(
        len.try_into()
            .expect("line IFFT scale length should fit in u32"),
    )
    .inverse()
    .0;

    let mut coords = evaluation.values().to_base_coords();
    for coord in &mut coords {
        coord.bit_reverse();
        coord
            .buffer
            .ifft_line_interpolate_in_place(inverse_line_factors.as_ref(), scale_factor)
            .expect("Metal line IFFT interpolation should complete through the native lane");
    }

    let coord_slices = coords.each_ref().map(BaseFieldVec::host_slice);
    let coeffs = (0..len)
        .map(|index| {
            SecureField::from_u32_unchecked(
                coord_slices[0][index].0,
                coord_slices[1][index].0,
                coord_slices[2][index].0,
                coord_slices[3][index].0,
            )
        })
        .collect();
    stwo::core::poly::line::LinePoly::new(coeffs)
}

#[derive(Clone, Debug)]
pub struct MetalLineEvaluation {
    values: SecureFieldVec,
    domain: LineDomain,
}

impl MetalLineEvaluation {
    pub fn new(domain: LineDomain, values: SecureFieldVec) -> Self {
        assert_eq!(
            values.len(),
            domain.size(),
            "Metal line evaluation requires one secure-field value per line-domain point"
        );
        Self { values, domain }
    }

    pub fn from_first_circle_fold(
        src: &SecureFieldVec,
        domain: CircleDomain,
        alpha: SecureField,
    ) -> Self {
        Self::new(
            LineDomain::new(domain.half_coset),
            fri::fold_circle_into_line_first_layer(src, domain, alpha),
        )
    }

    pub fn fold(&self, alpha: SecureField, fold_step: u32) -> Self {
        Self::new(
            self.domain.repeated_double(fold_step),
            fri::fold_line(&self.values, self.domain, alpha, fold_step),
        )
    }

    pub fn domain(&self) -> LineDomain {
        self.domain
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn values(&self) -> &SecureFieldVec {
        &self.values
    }

    pub fn commitment<H: MerkleHasherLifted>(&self) -> MetalLineCommitment<H> {
        MetalLineCommitment::from_line_evaluation(self)
    }
}

#[derive(Clone, Debug)]
pub struct MetalLineCommitment<H: MerkleHasherLifted> {
    layers: Vec<Vec<H::Hash>>,
}

#[derive(Clone, Debug)]
pub struct MetalFriLayerDecommitment<H: MerkleHasherLifted> {
    pub decommitment_positions: Vec<usize>,
    pub proof: ExtendedFriLayerProof<H>,
}

impl<H: MerkleHasherLifted> MetalLineCommitment<H> {
    pub fn root(&self) -> H::Hash {
        self.layers[0][0]
    }

    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    pub fn decommit_fri_layer(
        &self,
        evaluation: &MetalLineEvaluation,
        queries: &Queries,
        fold_step: u32,
    ) -> MetalFriLayerDecommitment<H> {
        assert_eq!(
            queries.log_domain_size,
            evaluation.domain.log_size(),
            "FRI layer decommit queries must target the line-evaluation domain"
        );
        let (decommitment_positions, fri_witness, value_map) =
            compute_decommitment_positions_and_witness_evals(
                evaluation,
                &queries.positions,
                fold_step,
            );
        let decommitment = self.decommit_merkle(&decommitment_positions);

        MetalFriLayerDecommitment {
            decommitment_positions,
            proof: ExtendedFriLayerProof {
                proof: FriLayerProof {
                    fri_witness,
                    decommitment: decommitment.decommitment,
                    commitment: self.root(),
                },
                aux: FriLayerProofAux {
                    all_values: vec![value_map],
                    decommitment: decommitment.aux,
                },
            },
        }
    }

    fn from_line_evaluation(evaluation: &MetalLineEvaluation) -> Self {
        let mut layer = build_line_merkle_leaves::<H>(&evaluation.values);
        let mut layers = vec![layer.clone()];
        while layer.len() > 1 {
            layer = layer
                .chunks_exact(2)
                .map(|chunk| H::hash_children((chunk[0], chunk[1])))
                .collect();
            layers.push(layer.clone());
        }
        layers.reverse();
        Self { layers }
    }

    fn decommit_merkle(&self, query_positions: &[usize]) -> ExtendedMerkleDecommitmentLifted<H> {
        assert!(
            query_positions.is_sorted(),
            "Merkle decommitment requires sorted query positions"
        );
        let mut decommitment = MerkleDecommitmentLifted::default();
        let mut all_node_values = Vec::new();
        let mut prev_layer_queries = query_positions.to_vec();
        prev_layer_queries.dedup();

        for layer_log_size in (0..self.layers.len() - 1).rev() {
            let prev_layer_hashes = &self.layers[layer_log_size + 1];
            let mut curr_layer_queries = Vec::new();
            let mut all_node_values_for_layer = BTreeMap::new();

            for queries_chunk in prev_layer_queries.as_slice().chunk_by(|a, b| a ^ 1 == *b) {
                let first = queries_chunk[0];
                let curr_index = first >> 1;
                if queries_chunk.len() == 1 {
                    decommitment.hash_witness.push(prev_layer_hashes[first ^ 1]);
                }
                all_node_values_for_layer.insert(2 * curr_index, prev_layer_hashes[2 * curr_index]);
                all_node_values_for_layer
                    .insert(2 * curr_index + 1, prev_layer_hashes[2 * curr_index + 1]);
                curr_layer_queries.push(curr_index);
            }

            prev_layer_queries = curr_layer_queries;
            all_node_values.push(all_node_values_for_layer);
        }

        ExtendedMerkleDecommitmentLifted {
            decommitment,
            aux: MerkleDecommitmentLiftedAux { all_node_values },
        }
    }
}

fn build_line_merkle_leaves<H: MerkleHasherLifted>(values: &SecureFieldVec) -> Vec<H::Hash> {
    assert!(
        values.len().is_power_of_two() && values.len() >= 2,
        "Metal line commitment requires a power-of-two line evaluation of length at least two"
    );

    values
        .to_vec()
        .into_iter()
        .map(|value| {
            let coords = value.to_m31_array();
            let mut hasher = H::default();
            let base_coords: [BaseField; 4] =
                array::from_fn(|i| BaseField::from_u32_unchecked(coords[i].0));
            hasher.update_leaf(&base_coords);
            hasher.finalize()
        })
        .collect()
}

fn compute_decommitment_positions_and_witness_evals(
    evaluation: &MetalLineEvaluation,
    query_positions: &[usize],
    fold_step: u32,
) -> (Vec<usize>, Vec<SecureField>, BTreeMap<usize, QM31>) {
    assert!(
        query_positions.is_sorted(),
        "FRI layer decommitment requires sorted query positions"
    );
    assert!(
        query_positions
            .iter()
            .all(|position| *position < evaluation.len()),
        "FRI layer decommitment query is out of bounds"
    );

    let mut decommitment_positions = Vec::new();
    let mut fri_witness = Vec::new();
    let mut value_map = BTreeMap::new();

    for subset_queries in query_positions.chunk_by(|a, b| a >> fold_step == b >> fold_step) {
        let subset_start = (subset_queries[0] >> fold_step) << fold_step;
        let subset_decommitment_positions = subset_start..subset_start + (1 << fold_step);
        let mut subset_queries_iter = subset_queries.iter().peekable();

        for position in subset_decommitment_positions {
            decommitment_positions.push(position);

            let eval = evaluation.values.get_data(position);
            value_map.insert(position, eval);

            if subset_queries_iter.next_if_eq(&&position).is_none() {
                fri_witness.push(eval);
            }
        }
    }

    (decommitment_positions, fri_witness, value_map)
}
