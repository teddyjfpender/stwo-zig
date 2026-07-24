//! Pinned-Rust oracle implementation of the repo-defined Native XOR lookup AIR.

use crate::model::{ProveMode, XorComponent, XorLookupElements, XorStatement};
use crate::statements::{mix_xor_statement, xor_combine};
use crate::traces::{backend_eval, gen_xor_lookup_trace, xor_storage_index};
use anyhow::{anyhow, bail, Result};
use num_traits::Zero;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::batch_inverse;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::{Backend, BackendForChannel};
use stwo::prover::{prove, prove_ex, CommitmentSchemeProver};

pub(crate) fn xor_prove<B>(
    config: PcsConfig,
    mut statement: XorStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(XorStatement, StarkProof<Blake2sMerkleHasher>)>
where
    B: Backend + BackendForChannel<Blake2sMerkleChannel>,
{
    validate_statement(statement)?;

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);
    let twiddles = B::precompute_twiddles(
        CanonicCoset::new(statement.log_size + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme = CommitmentSchemeProver::<B, Blake2sMerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    let (preprocessed, main) = gen_xor_lookup_trace(statement)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        preprocessed
            .iter()
            .cloned()
            .map(|column| backend_eval::<B>(statement.log_size, column))
            .collect(),
    );
    builder.commit(&mut channel);

    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        main.iter()
            .cloned()
            .map(|column| backend_eval::<B>(statement.log_size, column))
            .collect(),
    );
    builder.commit(&mut channel);

    let lookup_elements = draw_lookup_elements(&mut channel);
    let (interaction, claimed_sum) =
        gen_xor_interaction(statement, &preprocessed, &main, lookup_elements)?;
    if !claimed_sum.is_zero() {
        bail!("xor lookup interaction does not close");
    }
    statement.claimed_sum = claimed_sum;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        interaction
            .into_iter()
            .map(|column| backend_eval::<B>(statement.log_size, column))
            .collect(),
    );
    builder.commit(&mut channel);

    mix_xor_statement(&mut channel, statement);
    let component = XorComponent {
        statement,
        lookup_elements,
    };
    let proof = match prove_mode {
        ProveMode::Prove => prove::<B, Blake2sMerkleChannel>(&[&component], &mut channel, scheme)?,
        ProveMode::ProveEx => {
            prove_ex::<B, Blake2sMerkleChannel>(
                &[&component],
                &mut channel,
                scheme,
                include_all_preprocessed_columns,
            )?
            .proof
        }
    };
    Ok((statement, proof))
}

pub(crate) fn xor_verify(
    config: PcsConfig,
    statement: XorStatement,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    validate_statement(statement)?;
    if proof.0.commitments.len() < 3 {
        bail!("invalid proof shape: expected at least 3 commitments");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);
    let [c0, c1, c2] = [
        proof.0.commitments[0],
        proof.0.commitments[1],
        proof.0.commitments[2],
    ];
    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    commitment_scheme.commit(c0, &[statement.log_size; 7], &mut channel);
    commitment_scheme.commit(c1, &[statement.log_size; 4], &mut channel);
    let lookup_elements = draw_lookup_elements(&mut channel);
    commitment_scheme.commit(c2, &[statement.log_size; 4], &mut channel);

    mix_xor_statement(&mut channel, statement);
    let component = XorComponent {
        statement,
        lookup_elements,
    };
    verify(&[&component], &mut channel, &mut commitment_scheme, proof)
        .map_err(|err| anyhow!("xor verify failed: {err}"))
}

fn validate_statement(statement: XorStatement) -> Result<()> {
    if statement.log_size < 2 {
        bail!("invalid xor log_size");
    }
    if statement.log_step > statement.log_size {
        bail!("invalid xor log_step");
    }
    if !statement.claimed_sum.is_zero() {
        bail!("invalid xor claimed_sum");
    }
    Ok(())
}

fn draw_lookup_elements(channel: &mut Blake2sChannel) -> XorLookupElements {
    let challenges = channel.draw_secure_felts(2);
    XorLookupElements {
        z: challenges[0],
        alpha: challenges[1],
    }
}

fn gen_xor_interaction(
    statement: XorStatement,
    preprocessed: &[Vec<M31>],
    main: &[Vec<M31>],
    elements: XorLookupElements,
) -> Result<(Vec<Vec<M31>>, SecureField)> {
    if preprocessed.len() != 7 || main.len() != 4 {
        bail!("invalid xor trace geometry");
    }
    let n = 1usize << statement.log_size;
    if preprocessed.iter().any(|column| column.len() != n)
        || main.iter().any(|column| column.len() != n)
    {
        bail!("invalid xor trace geometry");
    }

    let mut denominators = Vec::with_capacity(n);
    let mut numerators = Vec::with_capacity(n);
    for storage in 0..n {
        let table_denominator = xor_combine(
            elements,
            preprocessed[4][storage].into(),
            preprocessed[5][storage].into(),
            preprocessed[6][storage].into(),
        );
        let execution_denominator = xor_combine(
            elements,
            main[0][storage].into(),
            main[1][storage].into(),
            main[2][storage].into(),
        );
        denominators.push(table_denominator * execution_denominator);
        numerators
            .push(SecureField::from(main[3][storage]) * execution_denominator - table_denominator);
    }
    let inverses = batch_inverse(&denominators);
    let mut secure_values = vec![SecureField::zero(); n];
    let mut claimed_sum = SecureField::zero();
    for row in 0..n {
        let storage = xor_storage_index(row, statement.log_size);
        claimed_sum += numerators[storage] * inverses[storage];
        secure_values[storage] = claimed_sum;
    }

    let mut columns = vec![vec![M31::zero(); n]; 4];
    for (storage, value) in secure_values.into_iter().enumerate() {
        for (coordinate, limb) in value.to_m31_array().into_iter().enumerate() {
            columns[coordinate][storage] = limb;
        }
    }
    Ok((columns, claimed_sum))
}
