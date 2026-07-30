use anyhow::{anyhow, bail, Result};
use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeSubspan};
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::verifier::verify;
use stwo_constraint_framework::TraceLocationAllocator;
use stwo_examples::plonk::{PlonkComponent, PlonkEval, PlonkLookupElements};

pub(crate) fn verify_exact(
    config: PcsConfig,
    log_n_rows: u32,
    claimed_sum: SecureField,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    if !(4..31).contains(&log_n_rows) {
        bail!("invalid plonk_logup log_n_rows");
    }
    if proof.0.commitments.len() != 4 {
        bail!("invalid proof shape: expected 3 trace commitments and 1 composition commitment");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let four_logs = [log_n_rows; 4];
    commitment_scheme.commit(proof.0.commitments[0], &four_logs, &mut channel);
    commitment_scheme.commit(proof.0.commitments[1], &four_logs, &mut channel);

    let lookup_elements = PlonkLookupElements::draw(&mut channel);
    let eight_logs = [log_n_rows; 8];
    commitment_scheme.commit(proof.0.commitments[2], &eight_logs, &mut channel);

    let component = PlonkComponent::new(
        &mut TraceLocationAllocator::default(),
        PlonkEval {
            log_n_rows,
            lookup_elements,
            claimed_sum,
            constants_trace_location: TreeSubspan {
                tree_index: 0,
                col_start: 0,
                col_end: 4,
            },
            base_trace_location: TreeSubspan {
                tree_index: 1,
                col_start: 0,
                col_end: 4,
            },
            interaction_trace_location: TreeSubspan {
                tree_index: 2,
                col_start: 0,
                col_end: 8,
            },
        },
        claimed_sum,
    );

    verify(&[&component], &mut channel, &mut commitment_scheme, proof)
        .map_err(|err| anyhow!("plonk_logup verify failed: {err}"))
}
