use anyhow::{anyhow, bail, Result};
use stwo::core::air::{Component, Components};
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_constraint_framework::TraceLocationAllocator;
use stwo_examples::poseidon::{PoseidonComponent, PoseidonElements, PoseidonEval};

const LOG_INSTANCES_PER_ROW: u32 = 3;
const MAIN_COLUMNS: usize = 1264;
const INTERACTION_COLUMNS: usize = 32;
const COMPOSITION_LOG_SPLIT: u32 = 2;
const COMPOSITION_CHUNKS: usize = 1 << COMPOSITION_LOG_SPLIT;
const COMPOSITION_COLUMNS: usize = COMPOSITION_CHUNKS * SECURE_EXTENSION_DEGREE;

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
