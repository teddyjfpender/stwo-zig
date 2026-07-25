use crate::cli::{
    pcs_config_from_cli, pcs_config_from_wire, pcs_config_to_wire, prove_mode_from_str,
    prove_mode_to_str,
};
use crate::model::{
    BenchExecutionProfile, BenchReport, BenchTiming, Cli, Example, ExampleStatement,
    InteropArtifact, PlonkStatement, PoseidonStatement, ProofWire, ProverBackend,
    WideFibonacciStatement, XorStatement, EXCHANGE_MODE, SCHEMA_VERSION,
};
use crate::plonk_logup::verify_exact as plonk_logup_verify;
use crate::profile::{time_stage, write_stage_profile};
use crate::proving::{
    plonk_prove, plonk_verify, poseidon_prove, poseidon_verify, proof_metrics_from_proof,
    prove_example, state_machine_prove, state_machine_verify, verify_example, wide_fibonacci_prove,
    wide_fibonacci_prove_profiled, wide_fibonacci_verify, xor_prove, xor_verify,
};
use crate::wire::{
    blake_statement_from_wire, blake_statement_to_wire, checked_m31, plonk_statement_from_wire,
    plonk_statement_to_wire, poseidon_statement_from_wire, poseidon_statement_to_wire,
    proof_to_wire, state_machine_statement_from_wire, state_machine_statement_to_wire,
    wide_fibonacci_statement_from_wire, wide_fibonacci_statement_to_wire, wire_to_proof,
    xor_statement_from_wire, xor_statement_to_wire,
};
use crate::UPSTREAM_COMMIT;
use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use stwo::core::pcs::PcsConfig;
use stwo::prover::backend::cpu::CpuBackend;
use stwo::prover::backend::simd::SimdBackend;

macro_rules! selected_backend {
    ($cli:expr, $function:ident ( $($argument:expr),* $(,)? )) => {
        match $cli.backend {
            crate::model::ProverBackend::Scalar => $function::<CpuBackend>($($argument),*),
            crate::model::ProverBackend::Simd => $function::<SimdBackend>($($argument),*),
        }
    };
}

fn pcs_configs_match(expected: PcsConfig, actual: PcsConfig) -> bool {
    expected.pow_bits == actual.pow_bits
        && expected.fri_config.log_blowup_factor == actual.fri_config.log_blowup_factor
        && expected.fri_config.log_last_layer_degree_bound
            == actual.fri_config.log_last_layer_degree_bound
        && expected.fri_config.n_queries == actual.fri_config.n_queries
}

fn validate_statement_shape(artifact: &InteropArtifact) -> Result<()> {
    let present = [
        ("blake", artifact.blake_statement.is_some()),
        ("plonk", artifact.plonk_statement.is_some()),
        ("plonk_logup", artifact.plonk_logup_statement.is_some()),
        ("poseidon", artifact.poseidon_statement.is_some()),
        ("state_machine", artifact.state_machine_statement.is_some()),
        (
            "wide_fibonacci",
            artifact.wide_fibonacci_statement.is_some(),
        ),
        ("xor", artifact.xor_statement.is_some()),
    ];
    if present.iter().filter(|(_, is_present)| *is_present).count() != 1 {
        bail!("invalid statement shape: expected exactly one statement");
    }
    if !present
        .iter()
        .any(|(example, is_present)| *is_present && *example == artifact.example)
    {
        bail!("invalid statement shape: statement does not match example");
    }
    Ok(())
}

pub(crate) fn run_generate(cli: &Cli) -> Result<()> {
    let example = cli
        .example
        .ok_or_else(|| anyhow!("--example is required for generate mode"))?;
    if cli.stage_profile_out.is_some() && example != Example::WideFibonacci {
        bail!("--stage-profile-out is only supported for wide_fibonacci generate runs");
    }
    let config = pcs_config_from_cli(cli)?;

    let artifact = match example {
        Example::Blake => {
            let (statement, proof) = crate::exact_blake::prove(
                config,
                cli.blake_log_n_rows,
                cli.blake_n_rounds,
                cli.prove_mode,
                cli.include_all_preprocessed_columns,
            )?;
            let proof_bytes = serde_json::to_vec(&proof_to_wire(&proof)?)?;
            InteropArtifact {
                schema_version: SCHEMA_VERSION,
                upstream_commit: UPSTREAM_COMMIT.to_string(),
                exchange_mode: EXCHANGE_MODE.to_string(),
                generator: "rust".to_string(),
                example: "blake".to_string(),
                prove_mode: Some(prove_mode_to_str(cli.prove_mode).to_string()),
                pcs_config: pcs_config_to_wire(config),
                blake_statement: Some(blake_statement_to_wire(statement)),
                plonk_statement: None,
                plonk_logup_statement: None,
                poseidon_statement: None,
                state_machine_statement: None,
                wide_fibonacci_statement: None,
                xor_statement: None,
                proof_bytes_hex: hex::encode(proof_bytes),
            }
        }
        Example::Plonk => {
            let statement = PlonkStatement {
                log_n_rows: cli.plonk_log_n_rows,
            };
            let (statement, proof) = selected_backend!(
                cli,
                plonk_prove(
                    config,
                    statement,
                    cli.prove_mode,
                    cli.include_all_preprocessed_columns,
                )
            )?;
            let proof_bytes = serde_json::to_vec(&proof_to_wire(&proof)?)?;
            InteropArtifact {
                schema_version: SCHEMA_VERSION,
                upstream_commit: UPSTREAM_COMMIT.to_string(),
                exchange_mode: EXCHANGE_MODE.to_string(),
                generator: "rust".to_string(),
                example: "plonk".to_string(),
                prove_mode: Some(prove_mode_to_str(cli.prove_mode).to_string()),
                pcs_config: pcs_config_to_wire(config),
                blake_statement: None,
                plonk_statement: Some(plonk_statement_to_wire(statement)),
                plonk_logup_statement: None,
                poseidon_statement: None,
                state_machine_statement: None,
                wide_fibonacci_statement: None,
                xor_statement: None,
                proof_bytes_hex: hex::encode(proof_bytes),
            }
        }
        Example::Poseidon => {
            let statement = PoseidonStatement {
                log_n_instances: cli.poseidon_log_n_instances,
                claimed_sum: Default::default(),
            };
            let (statement, proof) = selected_backend!(
                cli,
                poseidon_prove(
                    config,
                    statement,
                    cli.prove_mode,
                    cli.include_all_preprocessed_columns,
                )
            )?;
            let proof_bytes = serde_json::to_vec(&proof_to_wire(&proof)?)?;
            InteropArtifact {
                schema_version: SCHEMA_VERSION,
                upstream_commit: UPSTREAM_COMMIT.to_string(),
                exchange_mode: EXCHANGE_MODE.to_string(),
                generator: "rust".to_string(),
                example: "poseidon".to_string(),
                prove_mode: Some(prove_mode_to_str(cli.prove_mode).to_string()),
                pcs_config: pcs_config_to_wire(config),
                blake_statement: None,
                plonk_statement: None,
                plonk_logup_statement: None,
                poseidon_statement: Some(poseidon_statement_to_wire(statement)),
                state_machine_statement: None,
                wide_fibonacci_statement: None,
                xor_statement: None,
                proof_bytes_hex: hex::encode(proof_bytes),
            }
        }
        Example::StateMachine => {
            let initial_state = [
                checked_m31(cli.sm_initial_0)?,
                checked_m31(cli.sm_initial_1)?,
            ];
            let (statement, proof) = state_machine_prove(
                config,
                cli.sm_log_n_rows,
                initial_state,
                cli.prove_mode,
                cli.include_all_preprocessed_columns,
            )?;
            let proof_bytes = serde_json::to_vec(&proof_to_wire(&proof)?)?;
            InteropArtifact {
                schema_version: SCHEMA_VERSION,
                upstream_commit: UPSTREAM_COMMIT.to_string(),
                exchange_mode: EXCHANGE_MODE.to_string(),
                generator: "rust".to_string(),
                example: "state_machine".to_string(),
                prove_mode: Some(prove_mode_to_str(cli.prove_mode).to_string()),
                pcs_config: pcs_config_to_wire(config),
                blake_statement: None,
                plonk_statement: None,
                plonk_logup_statement: None,
                poseidon_statement: None,
                state_machine_statement: Some(state_machine_statement_to_wire(statement)),
                wide_fibonacci_statement: None,
                xor_statement: None,
                proof_bytes_hex: hex::encode(proof_bytes),
            }
        }
        Example::WideFibonacci => {
            let statement = WideFibonacciStatement {
                log_n_rows: cli.wf_log_n_rows,
                sequence_len: cli.wf_sequence_len,
            };
            if let Some(stage_profile_out) = &cli.stage_profile_out {
                let (proved, mut stages) = selected_backend!(
                    cli,
                    wide_fibonacci_prove_profiled(
                        config,
                        statement,
                        cli.prove_mode,
                        cli.include_all_preprocessed_columns,
                    )
                )?;
                let (proof_bytes, proof_encode_stage) =
                    time_stage("proof_wire_encode", "Proof wire encode", || {
                        serde_json::to_vec(&proof_to_wire(&proved.1)?).map_err(Into::into)
                    })?;
                stages.push(proof_encode_stage);
                let artifact = InteropArtifact {
                    schema_version: SCHEMA_VERSION,
                    upstream_commit: UPSTREAM_COMMIT.to_string(),
                    exchange_mode: EXCHANGE_MODE.to_string(),
                    generator: "rust".to_string(),
                    example: "wide_fibonacci".to_string(),
                    prove_mode: Some(prove_mode_to_str(cli.prove_mode).to_string()),
                    pcs_config: pcs_config_to_wire(config),
                    blake_statement: None,
                    plonk_statement: None,
                    plonk_logup_statement: None,
                    poseidon_statement: None,
                    state_machine_statement: None,
                    wide_fibonacci_statement: Some(wide_fibonacci_statement_to_wire(proved.0)),
                    xor_statement: None,
                    proof_bytes_hex: hex::encode(proof_bytes),
                };
                let (_unit, artifact_write_stage) =
                    time_stage("artifact_write", "Artifact write", || {
                        let rendered = serde_json::to_string_pretty(&artifact)?;
                        fs::write(&cli.artifact, format!("{rendered}\n"))
                            .with_context(|| format!("failed writing artifact {}", cli.artifact))?;
                        Ok(())
                    })?;
                stages.push(artifact_write_stage);
                write_stage_profile(stage_profile_out, stages)?;
                return Ok(());
            }

            let (statement, proof) = selected_backend!(
                cli,
                wide_fibonacci_prove(
                    config,
                    statement,
                    cli.prove_mode,
                    cli.include_all_preprocessed_columns,
                )
            )?;
            let proof_bytes = serde_json::to_vec(&proof_to_wire(&proof)?)?;
            InteropArtifact {
                schema_version: SCHEMA_VERSION,
                upstream_commit: UPSTREAM_COMMIT.to_string(),
                exchange_mode: EXCHANGE_MODE.to_string(),
                generator: "rust".to_string(),
                example: "wide_fibonacci".to_string(),
                prove_mode: Some(prove_mode_to_str(cli.prove_mode).to_string()),
                pcs_config: pcs_config_to_wire(config),
                blake_statement: None,
                plonk_statement: None,
                plonk_logup_statement: None,
                poseidon_statement: None,
                state_machine_statement: None,
                wide_fibonacci_statement: Some(wide_fibonacci_statement_to_wire(statement)),
                xor_statement: None,
                proof_bytes_hex: hex::encode(proof_bytes),
            }
        }
        Example::Xor => {
            let statement = XorStatement {
                log_size: cli.xor_log_size,
                log_step: cli.xor_log_step,
                offset: cli.xor_offset,
                claimed_sum: Default::default(),
            };
            let (statement, proof) = selected_backend!(
                cli,
                xor_prove(
                    config,
                    statement,
                    cli.prove_mode,
                    cli.include_all_preprocessed_columns,
                )
            )?;
            let proof_bytes = serde_json::to_vec(&proof_to_wire(&proof)?)?;
            InteropArtifact {
                schema_version: SCHEMA_VERSION,
                upstream_commit: UPSTREAM_COMMIT.to_string(),
                exchange_mode: EXCHANGE_MODE.to_string(),
                generator: "rust".to_string(),
                example: "xor".to_string(),
                prove_mode: Some(prove_mode_to_str(cli.prove_mode).to_string()),
                pcs_config: pcs_config_to_wire(config),
                blake_statement: None,
                plonk_statement: None,
                plonk_logup_statement: None,
                poseidon_statement: None,
                state_machine_statement: None,
                wide_fibonacci_statement: None,
                xor_statement: Some(xor_statement_to_wire(statement)?),
                proof_bytes_hex: hex::encode(proof_bytes),
            }
        }
    };

    let rendered = serde_json::to_string_pretty(&artifact)?;
    fs::write(&cli.artifact, format!("{rendered}\n"))
        .with_context(|| format!("failed writing artifact {}", cli.artifact))?;
    Ok(())
}

pub(crate) fn run_verify(cli: &Cli) -> Result<()> {
    let raw = fs::read_to_string(&cli.artifact)
        .with_context(|| format!("failed reading artifact {}", cli.artifact))?;
    let artifact: InteropArtifact = serde_json::from_str(&raw)?;

    if artifact.schema_version != SCHEMA_VERSION {
        bail!("unsupported schema version {}", artifact.schema_version);
    }
    if artifact.exchange_mode != EXCHANGE_MODE {
        bail!("unsupported exchange mode {}", artifact.exchange_mode);
    }
    if artifact.upstream_commit != UPSTREAM_COMMIT {
        bail!("unsupported upstream commit {}", artifact.upstream_commit);
    }
    if artifact.generator != "rust" && artifact.generator != "zig" {
        bail!("unsupported generator {}", artifact.generator);
    }
    if let Some(mode) = &artifact.prove_mode {
        if prove_mode_from_str(mode).is_none() {
            bail!("unsupported prove mode {}", mode);
        }
    }
    validate_statement_shape(&artifact)?;

    let config = pcs_config_from_wire(&artifact.pcs_config)?;
    let proof_bytes = hex::decode(&artifact.proof_bytes_hex)?;
    let proof_wire: ProofWire = serde_json::from_slice(&proof_bytes)?;
    let proof = wire_to_proof(proof_wire)?;
    if !pcs_configs_match(config, proof.0.config) {
        bail!("proof PCS config does not match artifact PCS config");
    }

    match artifact.example.as_str() {
        "blake" => {
            let statement_wire = artifact
                .blake_statement
                .as_ref()
                .ok_or_else(|| anyhow!("missing blake_statement"))?;
            let statement = blake_statement_from_wire(statement_wire)?;
            crate::exact_blake::verify(config, statement, proof)?;
        }
        "plonk" => {
            let statement_wire = artifact
                .plonk_statement
                .as_ref()
                .ok_or_else(|| anyhow!("missing plonk_statement"))?;
            let statement = plonk_statement_from_wire(statement_wire)?;
            plonk_verify(config, statement, proof)?;
        }
        "plonk_logup" => {
            let statement = artifact
                .plonk_logup_statement
                .as_ref()
                .ok_or_else(|| anyhow!("missing plonk_logup_statement"))?;
            plonk_logup_verify(
                config,
                statement.log_n_rows,
                crate::wire::qm31_from_wire(statement.claimed_sum)?,
                proof,
            )?;
        }
        "poseidon" => {
            let statement_wire = artifact
                .poseidon_statement
                .as_ref()
                .ok_or_else(|| anyhow!("missing poseidon_statement"))?;
            let statement = poseidon_statement_from_wire(statement_wire)?;
            poseidon_verify(config, statement, proof)?;
        }
        "state_machine" => {
            let statement_wire = artifact
                .state_machine_statement
                .as_ref()
                .ok_or_else(|| anyhow!("missing state_machine_statement"))?;
            let statement = state_machine_statement_from_wire(statement_wire)?;
            state_machine_verify(config, statement, proof)?;
        }
        "wide_fibonacci" => {
            let statement_wire = artifact
                .wide_fibonacci_statement
                .as_ref()
                .ok_or_else(|| anyhow!("missing wide_fibonacci_statement"))?;
            let statement = wide_fibonacci_statement_from_wire(statement_wire)?;
            wide_fibonacci_verify(config, statement, proof)?;
        }
        "xor" => {
            let statement_wire = artifact
                .xor_statement
                .as_ref()
                .ok_or_else(|| anyhow!("missing xor_statement"))?;
            let statement = xor_statement_from_wire(statement_wire)?;
            xor_verify(config, statement, proof)?;
        }
        other => bail!("unknown example {other}"),
    }

    Ok(())
}

pub(crate) fn run_bench(cli: &Cli) -> Result<()> {
    let example = cli
        .example
        .ok_or_else(|| anyhow!("--example is required for bench mode"))?;
    if cli.bench_repeats == 0 {
        bail!("--bench-repeats must be positive");
    }
    let config = pcs_config_from_cli(cli)?;
    if example == Example::Blake {
        return run_exact_blake_bench(cli, config);
    }
    let total_runs = cli.bench_warmups + cli.bench_repeats;

    let mut prove_samples = Vec::with_capacity(cli.bench_repeats);
    for i in 0..total_runs {
        let start = std::time::Instant::now();
        let (_, proof) = selected_backend!(
            cli,
            prove_example(
                config,
                example,
                cli,
                cli.prove_mode,
                cli.include_all_preprocessed_columns,
            )
        )?;
        let _encoded = serde_json::to_vec(&proof_to_wire(&proof)?)?;
        let elapsed = start.elapsed().as_secs_f64();
        drop(proof);
        if i >= cli.bench_warmups {
            prove_samples.push(elapsed);
        }
    }

    let (statement, baseline_proof) = selected_backend!(
        cli,
        prove_example(
            config,
            example,
            cli,
            cli.prove_mode,
            cli.include_all_preprocessed_columns,
        )
    )?;
    let proof_metrics = proof_metrics_from_proof(&baseline_proof)?;
    let baseline_wire = proof_to_wire(&baseline_proof)?;
    let baseline_wire_bytes = serde_json::to_vec(&baseline_wire)?;

    let mut verify_samples = Vec::with_capacity(cli.bench_repeats);
    for i in 0..total_runs {
        let start = std::time::Instant::now();
        let decoded_wire: ProofWire = serde_json::from_slice(&baseline_wire_bytes)?;
        let decoded_proof = wire_to_proof(decoded_wire)?;
        verify_example(config, statement, decoded_proof)?;
        let elapsed = start.elapsed().as_secs_f64();
        if i >= cli.bench_warmups {
            verify_samples.push(elapsed);
        }
    }

    let report = BenchReport {
        runtime: "rust".to_string(),
        backend: cli.backend.name().to_string(),
        backend_type: cli.backend.rust_type().to_string(),
        execution_profile: bench_execution_profile(example, cli.backend),
        example: match example {
            Example::Blake => "blake",
            Example::Plonk => "plonk",
            Example::Poseidon => "poseidon",
            Example::StateMachine => "state_machine",
            Example::WideFibonacci => "wide_fibonacci",
            Example::Xor => "xor",
        }
        .to_string(),
        prove_mode: prove_mode_to_str(cli.prove_mode).to_string(),
        include_all_preprocessed_columns: cli.include_all_preprocessed_columns,
        prove: summarize_timing(cli.bench_warmups, cli.bench_repeats, prove_samples)?,
        verify: summarize_timing(cli.bench_warmups, cli.bench_repeats, verify_samples)?,
        proof_metrics,
    };

    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn bench_execution_profile(
    example: Example,
    proof_backend: ProverBackend,
) -> Option<BenchExecutionProfile> {
    let simd_backend = ProverBackend::Simd.rust_type();
    match example {
        Example::Blake => Some(BenchExecutionProfile {
            proof_backend_type: simd_backend.to_string(),
            witness_generation_backend_type: simd_backend.to_string(),
            interaction_generation_backend_type: simd_backend.to_string(),
            backend_homogeneous: true,
            pure_backend_promotion_eligible: true,
            promotion_ineligibility_reason: None,
        }),
        Example::Poseidon => {
            let backend_homogeneous = proof_backend == ProverBackend::Simd;
            Some(BenchExecutionProfile {
                proof_backend_type: proof_backend.rust_type().to_string(),
                witness_generation_backend_type: simd_backend.to_string(),
                interaction_generation_backend_type: simd_backend.to_string(),
                backend_homogeneous,
                pure_backend_promotion_eligible: backend_homogeneous,
                promotion_ineligibility_reason: (!backend_homogeneous).then(|| {
                    "exact Poseidon witness and interaction generation use the pinned SIMD generator"
                        .to_string()
                }),
            })
        }
        _ => None,
    }
}

fn run_exact_blake_bench(cli: &Cli, config: PcsConfig) -> Result<()> {
    let total_runs = cli.bench_warmups + cli.bench_repeats;
    let mut prove_samples = Vec::with_capacity(cli.bench_repeats);
    for index in 0..total_runs {
        let start = std::time::Instant::now();
        let (_, proof) = crate::exact_blake::prove(
            config,
            cli.blake_log_n_rows,
            cli.blake_n_rounds,
            cli.prove_mode,
            cli.include_all_preprocessed_columns,
        )?;
        let _encoded = serde_json::to_vec(&proof_to_wire(&proof)?)?;
        let elapsed = start.elapsed().as_secs_f64();
        if index >= cli.bench_warmups {
            prove_samples.push(elapsed);
        }
    }

    let (statement, baseline_proof) = crate::exact_blake::prove(
        config,
        cli.blake_log_n_rows,
        cli.blake_n_rounds,
        cli.prove_mode,
        cli.include_all_preprocessed_columns,
    )?;
    let proof_metrics = proof_metrics_from_proof(&baseline_proof)?;
    let baseline_wire = serde_json::to_vec(&proof_to_wire(&baseline_proof)?)?;
    let mut verify_samples = Vec::with_capacity(cli.bench_repeats);
    for index in 0..total_runs {
        let start = std::time::Instant::now();
        let decoded = wire_to_proof(serde_json::from_slice(&baseline_wire)?)?;
        verify_example(config, ExampleStatement::Blake(statement), decoded)?;
        let elapsed = start.elapsed().as_secs_f64();
        if index >= cli.bench_warmups {
            verify_samples.push(elapsed);
        }
    }

    let report = BenchReport {
        runtime: "rust".to_string(),
        backend: "simd".to_string(),
        backend_type: "stwo::prover::backend::simd::SimdBackend".to_string(),
        execution_profile: bench_execution_profile(Example::Blake, ProverBackend::Simd),
        example: "blake".to_string(),
        prove_mode: prove_mode_to_str(cli.prove_mode).to_string(),
        include_all_preprocessed_columns: cli.include_all_preprocessed_columns,
        prove: summarize_timing(cli.bench_warmups, cli.bench_repeats, prove_samples)?,
        verify: summarize_timing(cli.bench_warmups, cli.bench_repeats, verify_samples)?,
        proof_metrics,
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{bench_execution_profile, pcs_configs_match};
    use crate::model::{Example, ProverBackend};
    use stwo::core::fri::FriConfig;
    use stwo::core::pcs::PcsConfig;

    fn config() -> PcsConfig {
        PcsConfig {
            pow_bits: 3,
            fri_config: FriConfig::new(1, 2, 5),
        }
    }

    #[test]
    fn proof_and_artifact_configs_require_exact_equality() {
        let expected = config();
        assert!(pcs_configs_match(expected, expected));

        let mut fields = [config(), config(), config(), config()];
        fields[0].pow_bits += 1;
        fields[1].fri_config.log_blowup_factor += 1;
        fields[2].fri_config.log_last_layer_degree_bound += 1;
        fields[3].fri_config.n_queries += 1;
        for actual in fields {
            assert!(!pcs_configs_match(expected, actual));
        }
    }

    #[test]
    fn scalar_poseidon_benchmark_discloses_mixed_execution_and_is_not_promotable() {
        let profile = bench_execution_profile(Example::Poseidon, ProverBackend::Scalar).unwrap();

        assert_eq!(
            profile.proof_backend_type,
            "stwo::prover::backend::cpu::CpuBackend"
        );
        assert_eq!(
            profile.witness_generation_backend_type,
            "stwo::prover::backend::simd::SimdBackend"
        );
        assert_eq!(
            profile.interaction_generation_backend_type,
            "stwo::prover::backend::simd::SimdBackend"
        );
        assert!(!profile.backend_homogeneous);
        assert!(!profile.pure_backend_promotion_eligible);
        assert!(profile.promotion_ineligibility_reason.is_some());
    }

    #[test]
    fn simd_poseidon_benchmark_is_homogeneous_and_promotable() {
        let profile = bench_execution_profile(Example::Poseidon, ProverBackend::Simd).unwrap();

        assert!(profile.backend_homogeneous);
        assert!(profile.pure_backend_promotion_eligible);
        assert!(profile.promotion_ineligibility_reason.is_none());
    }

    #[test]
    fn unrelated_benchmarks_do_not_claim_an_unclassified_execution_profile() {
        assert!(bench_execution_profile(Example::WideFibonacci, ProverBackend::Scalar).is_none());
    }
}

pub(crate) fn summarize_timing(
    warmups: usize,
    repeats: usize,
    samples: Vec<f64>,
) -> Result<BenchTiming> {
    if samples.is_empty() {
        bail!("benchmark samples are empty");
    }
    let mut min_seconds = samples[0];
    let mut max_seconds = samples[0];
    let mut total = 0.0f64;
    for sample in &samples {
        min_seconds = min_seconds.min(*sample);
        max_seconds = max_seconds.max(*sample);
        total += *sample;
    }
    Ok(BenchTiming {
        warmups,
        repeats,
        avg_seconds: total / samples.len() as f64,
        min_seconds,
        max_seconds,
        samples_seconds: samples,
    })
}
