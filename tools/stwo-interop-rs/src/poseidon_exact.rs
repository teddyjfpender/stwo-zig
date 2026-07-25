use anyhow::{anyhow, bail, Result};
use stwo::core::air::{Component, Components};
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Backend, BackendForChannel, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{CommitmentSchemeProver, ComponentProver, ComponentProvers};
use stwo_constraint_framework::TraceLocationAllocator;
use stwo_examples::poseidon::{
    gen_interaction_trace, gen_trace, PoseidonComponent, PoseidonElements, PoseidonEval,
};

use crate::model::ProveMode;

const LOG_INSTANCES_PER_ROW: u32 = 3;
const MAIN_COLUMNS: usize = 1264;
const INTERACTION_COLUMNS: usize = 32;
const COMPOSITION_LOG_SPLIT: u32 = 2;
const COMPOSITION_CHUNKS: usize = 1 << COMPOSITION_LOG_SPLIT;
const COMPOSITION_COLUMNS: usize = COMPOSITION_CHUNKS * SECURE_EXTENSION_DEGREE;
// Match the repository's standard committed-cell admission. The pinned
// Poseidon witness builders allocate infallibly, and the backend conversion
// temporarily retains both representations, so proving must reject before
// either allocation can turn an untrusted request into a process abort.
const MAX_ORACLE_TRACE_CELLS: u64 = 33_554_432;
pub(crate) const PROTOCOL_NAME: &str = "raw-stwo-poseidon-logup-split2-v1";

pub(crate) fn prove_exact<B>(
    config: PcsConfig,
    log_n_instances: u32,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(SecureField, StarkProof<Blake2sMerkleHasher>)>
where
    B: Backend + BackendForChannel<Blake2sMerkleChannel>,
    PoseidonComponent: ComponentProver<B>,
{
    let log_n_rows = validate_prove_geometry(log_n_instances)?;

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);
    let twiddles = B::precompute_twiddles(
        CanonicCoset::new(log_n_rows + COMPOSITION_LOG_SPLIT + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let mut scheme = CommitmentSchemeProver::<B, Blake2sMerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    scheme.tree_builder().commit(&mut channel);

    // The pinned example's witness generator is SIMD-specific. Converting its
    // exact evaluations permits both pinned CPU backends to prove the same AIR.
    let (main_trace, lookup_data) = gen_trace(log_n_rows);
    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        main_trace
            .into_iter()
            .map(convert_simd_evaluation::<B>)
            .collect(),
    );
    builder.commit(&mut channel);

    let lookup_elements = PoseidonElements::draw(&mut channel);
    let (interaction_trace, claimed_sum) =
        gen_interaction_trace(log_n_rows, lookup_data, &lookup_elements);
    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        interaction_trace
            .into_iter()
            .map(convert_simd_evaluation::<B>)
            .collect(),
    );
    builder.commit(&mut channel);

    let component = PoseidonComponent::new(
        &mut TraceLocationAllocator::default(),
        PoseidonEval {
            log_n_rows,
            lookup_elements,
            claimed_sum,
        },
        claimed_sum,
    );
    let proof = prove_pinned_a8fcf4b_split2::<B>(
        &component,
        &mut channel,
        scheme,
        prove_mode == ProveMode::ProveEx && include_all_preprocessed_columns,
    )?;
    Ok((claimed_sum, proof))
}

fn validate_prove_geometry(log_n_instances: u32) -> Result<u32> {
    if !(7..34).contains(&log_n_instances) {
        bail!("invalid exact Poseidon log_n_instances");
    }
    let log_n_rows = log_n_instances - LOG_INSTANCES_PER_ROW;
    let rows = 1u64
        .checked_shl(log_n_rows)
        .ok_or_else(|| anyhow!("exact Poseidon row count overflow"))?;
    let trace_cells = rows
        .checked_mul((MAIN_COLUMNS + INTERACTION_COLUMNS) as u64)
        .ok_or_else(|| anyhow!("exact Poseidon trace-cell count overflow"))?;
    if trace_cells > MAX_ORACLE_TRACE_CELLS {
        bail!(
            "exact Poseidon oracle resource cap exceeded: \
             {trace_cells} trace cells > {MAX_ORACLE_TRACE_CELLS}"
        );
    }
    Ok(log_n_rows)
}

fn convert_simd_evaluation<B>(
    evaluation: CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>,
) -> CircleEvaluation<B, BaseField, BitReversedOrder>
where
    B: Backend,
{
    CircleEvaluation::new(
        evaluation.domain,
        evaluation.values.to_cpu().into_iter().collect(),
    )
}

pub(crate) fn verify_exact(
    config: PcsConfig,
    log_n_instances: u32,
    claimed_sum: SecureField,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    if !(7..34).contains(&log_n_instances) {
        bail!("invalid exact Poseidon log_n_instances");
    }
    if proof.0.commitments.len() != 4 {
        bail!("invalid proof shape: expected 3 trace commitments and 1 composition commitment");
    }
    let log_n_rows = log_n_instances - LOG_INSTANCES_PER_ROW;

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);
    let mut scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    scheme.commit(proof.0.commitments[0], &[], &mut channel);
    scheme.commit(
        proof.0.commitments[1],
        &vec![log_n_rows; MAIN_COLUMNS],
        &mut channel,
    );
    let lookup_elements = PoseidonElements::draw(&mut channel);
    scheme.commit(
        proof.0.commitments[2],
        &vec![log_n_rows; INTERACTION_COLUMNS],
        &mut channel,
    );

    let component = PoseidonComponent::new(
        &mut TraceLocationAllocator::default(),
        PoseidonEval {
            log_n_rows,
            lookup_elements,
            claimed_sum,
        },
        claimed_sum,
    );
    verify_pinned_a8fcf4b_split2(&component, &mut channel, &mut scheme, proof)
}

/// Minimal split-depth-2 derivative of pinned Stwo `a8fcf4b` proving.
///
/// This is the pinned `prove_ex` transaction with the composition polynomial
/// recursively split into four chunks instead of two. All other transcript,
/// PCS, FRI, Merkle, and proof-encoding operations remain upstream.
fn prove_pinned_a8fcf4b_split2<B>(
    component: &PoseidonComponent,
    channel: &mut Blake2sChannel,
    mut scheme: CommitmentSchemeProver<'_, B, Blake2sMerkleChannel>,
    include_all_preprocessed_columns: bool,
) -> Result<StarkProof<Blake2sMerkleHasher>>
where
    B: Backend + BackendForChannel<Blake2sMerkleChannel>,
    PoseidonComponent: ComponentProver<B>,
{
    let component_ref: &dyn ComponentProver<B> = component;
    let component_provers = ComponentProvers {
        components: vec![component_ref],
        n_preprocessed_columns: scheme
            .trees
            .first()
            .ok_or_else(|| anyhow!("missing preprocessed commitment"))?
            .polynomials
            .len(),
    };
    let random_coeff = channel.draw_secure_felt();
    let composition_poly =
        component_provers.compute_composition_polynomial(random_coeff, &scheme.trace());
    let composition_log_size = composition_poly.log_size();
    if composition_log_size <= COMPOSITION_LOG_SPLIT {
        bail!("invalid split-depth-2 composition geometry");
    }

    let (left, right) = composition_poly.split_at_mid();
    let (left_left, left_right) = left.split_at_mid();
    let (right_left, right_right) = right.split_at_mid();
    let mut builder = scheme.tree_builder();
    for chunk in [left_left, left_right, right_left, right_right] {
        builder.extend_polys(chunk.into_coordinate_polys());
    }
    builder.commit(channel);

    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);
    let max_log_degree_bound = composition_log_size - COMPOSITION_LOG_SPLIT;
    let components = component_provers.components();
    let mut sample_points = components.mask_points(
        oods_point,
        max_log_degree_bound,
        include_all_preprocessed_columns,
    );
    sample_points.push(vec![vec![oods_point]; COMPOSITION_COLUMNS]);

    let commitment_proof = scheme.prove_values(sample_points, channel);
    let proof = StarkProof(commitment_proof.proof);
    let actual = extract_split2_composition_oods_eval(&proof, oods_point, composition_log_size)?;
    let expected = components.eval_composition_polynomial_at_point(
        oods_point,
        &proof.sampled_values,
        random_coeff,
        max_log_degree_bound,
    );
    if actual != expected {
        bail!("exact Poseidon split-depth-2 constraints are not satisfied");
    }
    Ok(proof)
}

/// Minimal split-depth-2 derivative of pinned Stwo `a8fcf4b` verification.
///
/// The unmodified upstream verifier hardcodes a split depth of one. This local
/// derivative changes only composition commitment geometry and recursive OODS
/// reconstruction; AIR evaluation, FRI, Merkle verification, and the transcript
/// remain the pinned upstream implementation.
fn verify_pinned_a8fcf4b_split2(
    component: &PoseidonComponent,
    channel: &mut Blake2sChannel,
    commitment_scheme: &mut CommitmentSchemeVerifier<Blake2sMerkleChannel>,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    let n_preprocessed_columns = commitment_scheme
        .trees
        .first()
        .ok_or_else(|| anyhow!("missing preprocessed commitment"))?
        .column_log_sizes
        .len();
    let component_ref: &dyn Component = component;
    let components = Components {
        components: vec![component_ref],
        n_preprocessed_columns,
    };
    let composition_log_size = components.composition_log_degree_bound();
    if composition_log_size <= COMPOSITION_LOG_SPLIT {
        bail!("invalid split-depth-2 composition geometry");
    }
    let random_coeff = channel.draw_secure_felt();

    let composition_commitment = *proof
        .commitments
        .last()
        .ok_or_else(|| anyhow!("missing composition commitment"))?;
    commitment_scheme.commit(
        composition_commitment,
        &[composition_log_size - COMPOSITION_LOG_SPLIT; COMPOSITION_COLUMNS],
        channel,
    );

    let oods_point = CirclePoint::<SecureField>::get_random_point(channel);
    let max_log_degree_bound = composition_log_size - COMPOSITION_LOG_SPLIT;
    let mut sample_points = components.mask_points(oods_point, max_log_degree_bound, false);
    sample_points.push(vec![vec![oods_point]; COMPOSITION_COLUMNS]);

    let composition_oods_eval =
        extract_split2_composition_oods_eval(&proof, oods_point, composition_log_size)?;
    let expected = components.eval_composition_polynomial_at_point(
        oods_point,
        &proof.sampled_values,
        random_coeff,
        max_log_degree_bound,
    );
    if composition_oods_eval != expected {
        bail!("exact Poseidon split-depth-2 OODS evaluation does not match");
    }

    commitment_scheme
        .verify_values(sample_points, proof.0, channel)
        .map_err(|err| anyhow!("exact Poseidon split-depth-2 verify failed: {err}"))
}

fn extract_split2_composition_oods_eval(
    proof: &StarkProof<Blake2sMerkleHasher>,
    oods_point: CirclePoint<SecureField>,
    composition_log_size: u32,
) -> Result<SecureField> {
    let composition_mask = proof
        .sampled_values
        .last()
        .ok_or_else(|| anyhow!("missing composition sampled-values tree"))?;
    if composition_mask.len() != COMPOSITION_COLUMNS {
        bail!(
            "invalid composition sampled-values width: expected {COMPOSITION_COLUMNS}, got {}",
            composition_mask.len()
        );
    }

    let mut chunk_evals = Vec::with_capacity(COMPOSITION_CHUNKS);
    for coordinate_columns in composition_mask.chunks_exact(SECURE_EXTENSION_DEGREE) {
        let coordinates: [SecureField; SECURE_EXTENSION_DEGREE] = coordinate_columns
            .iter()
            .map(|column| {
                let [value] = column.as_slice() else {
                    bail!("composition coordinate must contain exactly one OODS value");
                };
                Ok(*value)
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow!("invalid composition coordinate count"))?;
        chunk_evals.push(SecureField::from_partial_evals(coordinates));
    }
    let [chunk0, chunk1, chunk2, chunk3] = chunk_evals.as_slice() else {
        bail!("invalid split-depth-2 composition chunk count");
    };

    const FIRST_PARENT_OFFSET: u32 = COMPOSITION_LOG_SPLIT + 1;
    let first_factor = oods_point
        .repeated_double(composition_log_size - FIRST_PARENT_OFFSET)
        .x;
    let left = *chunk0 + first_factor * *chunk1;
    let right = *chunk2 + first_factor * *chunk3;
    let root_factor = oods_point.repeated_double(composition_log_size - 2).x;
    Ok(left + root_factor * right)
}

#[cfg(test)]
mod tests {
    use super::{validate_prove_geometry, MAX_ORACLE_TRACE_CELLS};

    #[test]
    fn proving_geometry_fails_before_infallible_witness_allocation() {
        assert_eq!(validate_prove_geometry(7).unwrap(), 4);
        assert_eq!(validate_prove_geometry(17).unwrap(), 14);

        let error = validate_prove_geometry(18).unwrap_err().to_string();
        assert!(error.contains("resource cap exceeded"));
        assert!(error.contains(&MAX_ORACLE_TRACE_CELLS.to_string()));
        assert!(validate_prove_geometry(6).is_err());
        assert!(validate_prove_geometry(34).is_err());
    }
}
