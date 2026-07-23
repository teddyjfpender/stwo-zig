use crate::model::{
    BenchProofMetrics, BlakeComponent, BlakeStatement, Cli, Example, ExampleStatement,
    PlonkComponent, PlonkStatement, PoseidonComponent, PoseidonStatement, ProveMode, StageNode,
    StateMachineComponent, StateMachineElements, StateMachineStatement, WideFibonacciComponent,
    WideFibonacciStatement, XorComponent, XorStatement, POSEIDON_COLUMNS,
};
use crate::profile::time_stage;
use crate::statements::{
    mix_blake_statement, mix_plonk_statement, mix_poseidon_statement,
    mix_state_machine_public_input, mix_state_machine_stmt0, mix_state_machine_stmt1,
    mix_wide_fibonacci_statement, mix_xor_statement, prepare_state_machine_statement,
    verify_state_machine_statement,
};
use crate::traces::{
    backend_eval, blake_n_columns, blake_validate_statement, gen_blake_trace, gen_is_first,
    gen_is_step_with_offset, gen_plonk_trace, gen_poseidon_trace, gen_trace,
    gen_wide_fibonacci_trace, gen_xor_main, poseidon_log_n_rows,
};
use crate::wire::{checked_m31, proof_to_wire};
use anyhow::{anyhow, bail, Result};
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::M31;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::{Backend, BackendForChannel};
use stwo::prover::{prove, prove_ex, CommitmentSchemeProver};

pub(crate) fn prove_example<B>(
    config: PcsConfig,
    example: Example,
    cli: &Cli,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(ExampleStatement, StarkProof<Blake2sMerkleHasher>)>
where
    B: Backend + BackendForChannel<Blake2sMerkleChannel>,
{
    match example {
        Example::Blake => {
            let statement = BlakeStatement {
                log_n_rows: cli.blake_log_n_rows,
                n_rounds: cli.blake_n_rounds,
            };
            let (statement, proof) = blake_prove::<B>(
                config,
                statement,
                prove_mode,
                include_all_preprocessed_columns,
            )?;
            Ok((ExampleStatement::Blake(statement), proof))
        }
        Example::Plonk => {
            let statement = PlonkStatement {
                log_n_rows: cli.plonk_log_n_rows,
            };
            let (statement, proof) = plonk_prove::<B>(
                config,
                statement,
                prove_mode,
                include_all_preprocessed_columns,
            )?;
            Ok((ExampleStatement::Plonk(statement), proof))
        }
        Example::Poseidon => {
            let statement = PoseidonStatement {
                log_n_instances: cli.poseidon_log_n_instances,
            };
            let (statement, proof) = poseidon_prove::<B>(
                config,
                statement,
                prove_mode,
                include_all_preprocessed_columns,
            )?;
            Ok((ExampleStatement::Poseidon(statement), proof))
        }
        Example::StateMachine => {
            let initial_state = [
                checked_m31(cli.sm_initial_0)?,
                checked_m31(cli.sm_initial_1)?,
            ];
            let (statement, proof) = state_machine_prove::<B>(
                config,
                cli.sm_log_n_rows,
                initial_state,
                prove_mode,
                include_all_preprocessed_columns,
            )?;
            Ok((ExampleStatement::StateMachine(statement), proof))
        }
        Example::WideFibonacci => {
            let statement = WideFibonacciStatement {
                log_n_rows: cli.wf_log_n_rows,
                sequence_len: cli.wf_sequence_len,
            };
            let (statement, proof) = wide_fibonacci_prove::<B>(
                config,
                statement,
                prove_mode,
                include_all_preprocessed_columns,
            )?;
            Ok((ExampleStatement::WideFibonacci(statement), proof))
        }
        Example::Xor => {
            let statement = XorStatement {
                log_size: cli.xor_log_size,
                log_step: cli.xor_log_step,
                offset: cli.xor_offset,
            };
            let (statement, proof) = xor_prove::<B>(
                config,
                statement,
                prove_mode,
                include_all_preprocessed_columns,
            )?;
            Ok((ExampleStatement::Xor(statement), proof))
        }
    }
}

pub(crate) fn verify_example(
    config: PcsConfig,
    statement: ExampleStatement,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    match statement {
        ExampleStatement::Blake(s) => blake_verify(config, s, proof),
        ExampleStatement::Plonk(s) => plonk_verify(config, s, proof),
        ExampleStatement::Poseidon(s) => poseidon_verify(config, s, proof),
        ExampleStatement::StateMachine(s) => state_machine_verify(config, s, proof),
        ExampleStatement::WideFibonacci(s) => wide_fibonacci_verify(config, s, proof),
        ExampleStatement::Xor(s) => xor_verify(config, s, proof),
    }
}

pub(crate) fn proof_metrics_from_proof(
    proof: &StarkProof<Blake2sMerkleHasher>,
) -> Result<BenchProofMetrics> {
    let wire = proof_to_wire(proof)?;
    let proof_wire_bytes = serde_json::to_vec(&wire)?.len();
    let trace_decommit_hashes: usize = wire
        .decommitments
        .iter()
        .map(|decommitment| decommitment.hash_witness.len())
        .sum();
    let fri_decommit_hashes_total = wire.fri_proof.first_layer.decommitment.hash_witness.len()
        + wire
            .fri_proof
            .inner_layers
            .iter()
            .map(|layer| layer.decommitment.hash_witness.len())
            .sum::<usize>();

    Ok(BenchProofMetrics {
        proof_wire_bytes,
        commitments_count: wire.commitments.len(),
        decommitments_count: wire.decommitments.len(),
        trace_decommit_hashes,
        fri_inner_layers_count: wire.fri_proof.inner_layers.len(),
        fri_first_layer_witness_len: wire.fri_proof.first_layer.fri_witness.len(),
        fri_last_layer_poly_len: wire.fri_proof.last_layer_poly.len(),
        fri_decommit_hashes_total,
    })
}

pub(crate) fn state_machine_prove<B>(
    config: PcsConfig,
    log_n_rows: u32,
    initial_state: [M31; 2],
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(StateMachineStatement, StarkProof<Blake2sMerkleHasher>)>
where
    B: Backend + BackendForChannel<Blake2sMerkleChannel>,
{
    if log_n_rows == 0 || log_n_rows >= 31 {
        bail!("invalid log_n_rows {log_n_rows}");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = B::precompute_twiddles(
        CanonicCoset::new(log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme = CommitmentSchemeProver::<B, Blake2sMerkleChannel>::new(config, &twiddles);

    let preprocessed = gen_is_first(log_n_rows)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![backend_eval::<B>(log_n_rows, preprocessed)]);
    builder.commit(&mut channel);

    let [trace0, trace1] = gen_trace(log_n_rows, initial_state, 0)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![
        backend_eval::<B>(log_n_rows, trace0),
        backend_eval::<B>(log_n_rows, trace1),
    ]);
    builder.commit(&mut channel);

    let stmt0_n = log_n_rows;
    let stmt0_m = log_n_rows - 1;
    mix_state_machine_stmt0(&mut channel, stmt0_n, stmt0_m);

    let elements = StateMachineElements {
        z: channel.draw_secure_felt(),
        alpha: channel.draw_secure_felt(),
    };

    let statement = prepare_state_machine_statement(log_n_rows, initial_state, elements)?;
    mix_state_machine_public_input(&mut channel, &statement.public_input);
    mix_state_machine_stmt1(
        &mut channel,
        statement.stmt1_x_axis_claimed_sum,
        statement.stmt1_y_axis_claimed_sum,
    );

    let component = StateMachineComponent {
        trace_log_size: log_n_rows,
        composition_eval: statement.stmt1_x_axis_claimed_sum + statement.stmt1_y_axis_claimed_sum,
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

pub(crate) fn state_machine_verify(
    config: PcsConfig,
    statement: StateMachineStatement,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    if statement.stmt0_n == 0 || statement.stmt0_n >= 31 {
        bail!("invalid statement n");
    }
    if statement.stmt0_m != statement.stmt0_n - 1 {
        bail!("invalid statement m");
    }
    if proof.0.commitments.len() < 2 {
        bail!("invalid proof shape: expected at least 2 commitments");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let c0 = proof.0.commitments[0];
    let c1 = proof.0.commitments[1];

    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    commitment_scheme.commit(c0, &[statement.stmt0_n], &mut channel);
    commitment_scheme.commit(c1, &[statement.stmt0_n, statement.stmt0_n], &mut channel);

    mix_state_machine_stmt0(&mut channel, statement.stmt0_n, statement.stmt0_m);
    let elements = StateMachineElements {
        z: channel.draw_secure_felt(),
        alpha: channel.draw_secure_felt(),
    };
    verify_state_machine_statement(statement, elements)?;
    mix_state_machine_public_input(&mut channel, &statement.public_input);
    mix_state_machine_stmt1(
        &mut channel,
        statement.stmt1_x_axis_claimed_sum,
        statement.stmt1_y_axis_claimed_sum,
    );

    let component = StateMachineComponent {
        trace_log_size: statement.stmt0_n,
        composition_eval: statement.stmt1_x_axis_claimed_sum + statement.stmt1_y_axis_claimed_sum,
    };

    verify(&[&component], &mut channel, &mut commitment_scheme, proof)
        .map_err(|err| anyhow!("state_machine verify failed: {err}"))
}

pub(crate) fn wide_fibonacci_prove<B>(
    config: PcsConfig,
    statement: WideFibonacciStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(WideFibonacciStatement, StarkProof<Blake2sMerkleHasher>)>
where
    B: Backend + BackendForChannel<Blake2sMerkleChannel>,
{
    if statement.log_n_rows == 0 || statement.log_n_rows >= 31 {
        bail!("invalid wide_fibonacci log_n_rows");
    }
    if statement.sequence_len < 2 {
        bail!("invalid wide_fibonacci sequence_len");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = B::precompute_twiddles(
        CanonicCoset::new(statement.log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme = CommitmentSchemeProver::<B, Blake2sMerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();

    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![]);
    builder.commit(&mut channel);

    let trace = gen_wide_fibonacci_trace(statement.log_n_rows, statement.sequence_len)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        trace
            .into_iter()
            .map(|col| backend_eval::<B>(statement.log_n_rows, col))
            .collect(),
    );
    builder.commit(&mut channel);

    mix_wide_fibonacci_statement(&mut channel, statement);

    let component = WideFibonacciComponent { statement };
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

pub(crate) fn wide_fibonacci_prove_profiled<B>(
    config: PcsConfig,
    statement: WideFibonacciStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(
    (WideFibonacciStatement, StarkProof<Blake2sMerkleHasher>),
    Vec<StageNode>,
)>
where
    B: Backend + BackendForChannel<Blake2sMerkleChannel>,
{
    if statement.log_n_rows == 0 || statement.log_n_rows >= 31 {
        bail!("invalid wide_fibonacci log_n_rows");
    }
    if statement.sequence_len < 2 {
        bail!("invalid wide_fibonacci sequence_len");
    }

    let mut stages = Vec::with_capacity(6);
    let init_start = std::time::Instant::now();
    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);
    let twiddles = B::precompute_twiddles(
        CanonicCoset::new(statement.log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme = CommitmentSchemeProver::<B, Blake2sMerkleChannel>::new(config, &twiddles);
    scheme.set_store_polynomials_coefficients();
    stages.push(StageNode {
        id: "channel_and_scheme_init".to_string(),
        label: "Channel and scheme init".to_string(),
        seconds: init_start.elapsed().as_secs_f64(),
        children: None,
    });

    let (_preprocessed_done, preprocessed_stage) =
        time_stage("preprocessed_commit", "Preprocessed commit", || {
            let mut builder = scheme.tree_builder();
            builder.extend_evals(vec![]);
            builder.commit(&mut channel);
            Ok(())
        })?;
    stages.push(preprocessed_stage);

    let (trace, trace_stage) = time_stage("trace_generation", "Trace generation", || {
        gen_wide_fibonacci_trace(statement.log_n_rows, statement.sequence_len)
    })?;
    stages.push(trace_stage);

    let (_main_trace_done, main_trace_stage) =
        time_stage("main_trace_commit", "Main trace commit", || {
            let mut builder = scheme.tree_builder();
            builder.extend_evals(
                trace
                    .into_iter()
                    .map(|col| backend_eval::<B>(statement.log_n_rows, col))
                    .collect(),
            );
            builder.commit(&mut channel);
            Ok(())
        })?;
    stages.push(main_trace_stage);

    let (_statement_mix_done, statement_mix_stage) =
        time_stage("statement_mix", "Statement mix", || {
            mix_wide_fibonacci_statement(&mut channel, statement);
            Ok(())
        })?;
    stages.push(statement_mix_stage);

    let component = WideFibonacciComponent { statement };
    let (proof, core_prove_stage) = time_stage("core_prove", "Core prove", || match prove_mode {
        ProveMode::Prove => prove::<B, Blake2sMerkleChannel>(&[&component], &mut channel, scheme)
            .map_err(Into::into),
        ProveMode::ProveEx => prove_ex::<B, Blake2sMerkleChannel>(
            &[&component],
            &mut channel,
            scheme,
            include_all_preprocessed_columns,
        )
        .map(|extended| extended.proof)
        .map_err(Into::into),
    })?;
    stages.push(core_prove_stage);

    Ok(((statement, proof), stages))
}

pub(crate) fn wide_fibonacci_verify(
    config: PcsConfig,
    statement: WideFibonacciStatement,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    if statement.log_n_rows == 0 || statement.log_n_rows >= 31 {
        bail!("invalid wide_fibonacci log_n_rows");
    }
    if statement.sequence_len < 2 {
        bail!("invalid wide_fibonacci sequence_len");
    }
    if proof.0.commitments.len() < 2 {
        bail!("invalid proof shape: expected at least 2 commitments");
    }
    let main_sampled_columns = proof
        .0
        .sampled_values
        .0
        .get(1)
        .ok_or_else(|| anyhow!("invalid proof shape: missing wide_fibonacci main samples"))?;
    if main_sampled_columns.len() != statement.sequence_len as usize {
        bail!("invalid proof shape: wide_fibonacci statement/sample width mismatch");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let c0 = proof.0.commitments[0];
    let c1 = proof.0.commitments[1];

    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    commitment_scheme.commit(c0, &[], &mut channel);
    let main_log_sizes = vec![statement.log_n_rows; statement.sequence_len as usize];
    commitment_scheme.commit(c1, &main_log_sizes, &mut channel);

    mix_wide_fibonacci_statement(&mut channel, statement);

    let component = WideFibonacciComponent { statement };
    verify(&[&component], &mut channel, &mut commitment_scheme, proof)
        .map_err(|err| anyhow!("wide_fibonacci verify failed: {err}"))
}

pub(crate) fn plonk_prove<B>(
    config: PcsConfig,
    statement: PlonkStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(PlonkStatement, StarkProof<Blake2sMerkleHasher>)>
where
    B: Backend + BackendForChannel<Blake2sMerkleChannel>,
{
    if statement.log_n_rows == 0 || statement.log_n_rows >= 31 {
        bail!("invalid plonk log_n_rows");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = B::precompute_twiddles(
        CanonicCoset::new(statement.log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme = CommitmentSchemeProver::<B, Blake2sMerkleChannel>::new(config, &twiddles);

    let (preprocessed, main) = gen_plonk_trace(statement.log_n_rows)?;

    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        preprocessed
            .into_iter()
            .map(|col| backend_eval::<B>(statement.log_n_rows, col))
            .collect(),
    );
    builder.commit(&mut channel);

    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        main.into_iter()
            .map(|col| backend_eval::<B>(statement.log_n_rows, col))
            .collect(),
    );
    builder.commit(&mut channel);

    mix_plonk_statement(&mut channel, statement);

    let component = PlonkComponent { statement };
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

pub(crate) fn plonk_verify(
    config: PcsConfig,
    statement: PlonkStatement,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    if statement.log_n_rows == 0 || statement.log_n_rows >= 31 {
        bail!("invalid plonk log_n_rows");
    }
    if proof.0.commitments.len() < 2 {
        bail!("invalid proof shape: expected at least 2 commitments");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let c0 = proof.0.commitments[0];
    let c1 = proof.0.commitments[1];

    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let log_sizes = [statement.log_n_rows; 4];
    commitment_scheme.commit(c0, &log_sizes, &mut channel);
    commitment_scheme.commit(c1, &log_sizes, &mut channel);

    mix_plonk_statement(&mut channel, statement);

    let component = PlonkComponent { statement };
    verify(&[&component], &mut channel, &mut commitment_scheme, proof)
        .map_err(|err| anyhow!("plonk verify failed: {err}"))
}

pub(crate) fn poseidon_prove<B>(
    config: PcsConfig,
    statement: PoseidonStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(PoseidonStatement, StarkProof<Blake2sMerkleHasher>)>
where
    B: Backend + BackendForChannel<Blake2sMerkleChannel>,
{
    let log_n_rows = poseidon_log_n_rows(statement)?;

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = B::precompute_twiddles(
        CanonicCoset::new(log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme = CommitmentSchemeProver::<B, Blake2sMerkleChannel>::new(config, &twiddles);

    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![]);
    builder.commit(&mut channel);

    let trace = gen_poseidon_trace(log_n_rows)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        trace
            .into_iter()
            .map(|col| backend_eval::<B>(log_n_rows, col))
            .collect(),
    );
    builder.commit(&mut channel);

    mix_poseidon_statement(&mut channel, statement);

    let component = PoseidonComponent { statement };
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

pub(crate) fn poseidon_verify(
    config: PcsConfig,
    statement: PoseidonStatement,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    let log_n_rows = poseidon_log_n_rows(statement)?;
    if proof.0.commitments.len() < 2 {
        bail!("invalid proof shape: expected at least 2 commitments");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let c0 = proof.0.commitments[0];
    let c1 = proof.0.commitments[1];

    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    commitment_scheme.commit(c0, &[], &mut channel);
    let main_log_sizes = vec![log_n_rows; POSEIDON_COLUMNS];
    commitment_scheme.commit(c1, &main_log_sizes, &mut channel);

    mix_poseidon_statement(&mut channel, statement);

    let component = PoseidonComponent { statement };
    verify(&[&component], &mut channel, &mut commitment_scheme, proof)
        .map_err(|err| anyhow!("poseidon verify failed: {err}"))
}

pub(crate) fn blake_prove<B>(
    config: PcsConfig,
    statement: BlakeStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(BlakeStatement, StarkProof<Blake2sMerkleHasher>)>
where
    B: Backend + BackendForChannel<Blake2sMerkleChannel>,
{
    blake_validate_statement(statement)?;
    let n_columns = blake_n_columns(statement)?;

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = B::precompute_twiddles(
        CanonicCoset::new(statement.log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme = CommitmentSchemeProver::<B, Blake2sMerkleChannel>::new(config, &twiddles);

    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![]);
    builder.commit(&mut channel);

    let trace = gen_blake_trace(statement)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        trace
            .into_iter()
            .map(|col| backend_eval::<B>(statement.log_n_rows, col))
            .collect(),
    );
    builder.commit(&mut channel);

    mix_blake_statement(&mut channel, statement);

    let component = BlakeComponent { statement };
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

    let _ = n_columns;
    Ok((statement, proof))
}

pub(crate) fn blake_verify(
    config: PcsConfig,
    statement: BlakeStatement,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<()> {
    blake_validate_statement(statement)?;
    let n_columns = blake_n_columns(statement)?;
    if proof.0.commitments.len() < 2 {
        bail!("invalid proof shape: expected at least 2 commitments");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let c0 = proof.0.commitments[0];
    let c1 = proof.0.commitments[1];

    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    commitment_scheme.commit(c0, &[], &mut channel);
    let main_log_sizes = vec![statement.log_n_rows; n_columns];
    commitment_scheme.commit(c1, &main_log_sizes, &mut channel);

    mix_blake_statement(&mut channel, statement);

    let component = BlakeComponent { statement };
    verify(&[&component], &mut channel, &mut commitment_scheme, proof)
        .map_err(|err| anyhow!("blake verify failed: {err}"))
}

pub(crate) fn xor_prove<B>(
    config: PcsConfig,
    statement: XorStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(XorStatement, StarkProof<Blake2sMerkleHasher>)>
where
    B: Backend + BackendForChannel<Blake2sMerkleChannel>,
{
    if statement.log_size == 0 {
        bail!("invalid xor log_size");
    }
    if statement.log_step > statement.log_size {
        bail!("invalid xor log_step");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = B::precompute_twiddles(
        CanonicCoset::new(statement.log_size + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme = CommitmentSchemeProver::<B, Blake2sMerkleChannel>::new(config, &twiddles);

    let is_first = gen_is_first(statement.log_size)?;
    let is_step =
        gen_is_step_with_offset(statement.log_size, statement.log_step, statement.offset)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![
        backend_eval::<B>(statement.log_size, is_first),
        backend_eval::<B>(statement.log_size, is_step),
    ]);
    builder.commit(&mut channel);

    let main = gen_xor_main(statement.log_size)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![backend_eval::<B>(statement.log_size, main)]);
    builder.commit(&mut channel);

    mix_xor_statement(&mut channel, statement);

    let component = XorComponent { statement };
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
    if statement.log_size == 0 {
        bail!("invalid xor log_size");
    }
    if statement.log_step > statement.log_size {
        bail!("invalid xor log_step");
    }
    if proof.0.commitments.len() < 2 {
        bail!("invalid proof shape: expected at least 2 commitments");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let c0 = proof.0.commitments[0];
    let c1 = proof.0.commitments[1];

    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    commitment_scheme.commit(c0, &[statement.log_size, statement.log_size], &mut channel);
    commitment_scheme.commit(c1, &[statement.log_size], &mut channel);

    mix_xor_statement(&mut channel, statement);

    let component = XorComponent { statement };
    verify(&[&component], &mut channel, &mut commitment_scheme, proof)
        .map_err(|err| anyhow!("xor verify failed: {err}"))
}
