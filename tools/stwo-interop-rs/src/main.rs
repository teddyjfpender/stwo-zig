use anyhow::{anyhow, bail, Context, Result};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use stwo::core::air::accumulation::PointEvaluationAccumulator;
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::{SecureField, QM31};
use stwo::core::fields::FieldExpOps;
use stwo::core::fri::{FriConfig, FriLayerProof, FriProof};
use stwo::core::pcs::quotients::CommitmentSchemeProof;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::LinePoly;
use stwo::core::proof::StarkProof;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::vcs_lifted::verifier::MerkleDecommitmentLifted;
use stwo::core::verifier::verify;
use stwo::prover::backend::cpu::{CpuBackend, CpuCircleEvaluation};
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{
    prove, prove_ex, CommitmentSchemeProver, ComponentProver, DomainEvaluationAccumulator, Trace,
};

const SCHEMA_VERSION: u32 = 1;
const UPSTREAM_COMMIT: &str = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";
const EXCHANGE_MODE: &str = "proof_exchange_json_wire_v1";
const POSEIDON_LOG_INSTANCES_PER_ROW: u32 = 3;
const POSEIDON_INSTANCES_PER_ROW: usize = 1 << POSEIDON_LOG_INSTANCES_PER_ROW;
const POSEIDON_STATE: usize = 16;
const POSEIDON_PARTIAL_ROUNDS: usize = 14;
const POSEIDON_HALF_FULL_ROUNDS: usize = 4;
const POSEIDON_FULL_ROUNDS: usize = POSEIDON_HALF_FULL_ROUNDS * 2;
const POSEIDON_COLUMNS_PER_REP: usize =
    POSEIDON_STATE * (1 + POSEIDON_FULL_ROUNDS) + POSEIDON_PARTIAL_ROUNDS;
const POSEIDON_COLUMNS: usize = POSEIDON_COLUMNS_PER_REP * POSEIDON_INSTANCES_PER_ROW;
const BLAKE_STATE: usize = 16;
const BLAKE_MESSAGE_WORDS: usize = 16;
const BLAKE_FELTS_IN_U32: usize = 2;
const BLAKE_ROUND_INPUT_FELTS: usize =
    (BLAKE_STATE + BLAKE_STATE + BLAKE_MESSAGE_WORDS) * BLAKE_FELTS_IN_U32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Generate,
    Verify,
    Bench,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Example {
    Blake,
    Plonk,
    Poseidon,
    StateMachine,
    WideFibonacci,
    Xor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProveMode {
    Prove,
    ProveEx,
}

#[derive(Debug, Clone)]
struct Cli {
    mode: Mode,
    example: Option<Example>,
    artifact: String,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,

    pow_bits: u32,
    fri_log_blowup: u32,
    fri_log_last_layer: u32,
    fri_n_queries: usize,

    sm_log_n_rows: u32,
    sm_initial_0: u32,
    sm_initial_1: u32,

    blake_log_n_rows: u32,
    blake_n_rounds: u32,

    plonk_log_n_rows: u32,

    poseidon_log_n_instances: u32,

    wf_log_n_rows: u32,
    wf_sequence_len: u32,

    xor_log_size: u32,
    xor_log_step: u32,
    xor_offset: usize,

    bench_warmups: usize,
    bench_repeats: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FriConfigWire {
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PcsConfigWire {
    pow_bits: u32,
    fri_config: FriConfigWire,
}

type HashWire = [u8; 32];
type Qm31Wire = [u32; 4];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MerkleDecommitmentWire {
    hash_witness: Vec<HashWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FriLayerWire {
    fri_witness: Vec<Qm31Wire>,
    decommitment: MerkleDecommitmentWire,
    commitment: HashWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FriProofWire {
    first_layer: FriLayerWire,
    inner_layers: Vec<FriLayerWire>,
    last_layer_poly: Vec<Qm31Wire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProofWire {
    config: PcsConfigWire,
    commitments: Vec<HashWire>,
    sampled_values: Vec<Vec<Vec<Qm31Wire>>>,
    decommitments: Vec<MerkleDecommitmentWire>,
    queried_values: Vec<Vec<Vec<u32>>>,
    proof_of_work: u64,
    fri_proof: FriProofWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateMachineStatementWire {
    public_input: [[u32; 2]; 2],
    stmt0: StateMachineStmt0Wire,
    stmt1: StateMachineStmt1Wire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateMachineStmt0Wire {
    n: u32,
    m: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateMachineStmt1Wire {
    x_axis_claimed_sum: Qm31Wire,
    y_axis_claimed_sum: Qm31Wire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct XorStatementWire {
    log_size: u32,
    log_step: u32,
    offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlonkStatementWire {
    log_n_rows: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoseidonStatementWire {
    log_n_instances: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlakeStatementWire {
    log_n_rows: u32,
    n_rounds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WideFibonacciStatementWire {
    log_n_rows: u32,
    sequence_len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InteropArtifact {
    schema_version: u32,
    upstream_commit: String,
    exchange_mode: String,
    generator: String,
    example: String,
    prove_mode: Option<String>,
    pcs_config: PcsConfigWire,
    blake_statement: Option<BlakeStatementWire>,
    plonk_statement: Option<PlonkStatementWire>,
    poseidon_statement: Option<PoseidonStatementWire>,
    state_machine_statement: Option<StateMachineStatementWire>,
    wide_fibonacci_statement: Option<WideFibonacciStatementWire>,
    xor_statement: Option<XorStatementWire>,
    proof_bytes_hex: String,
}

#[derive(Debug, Clone, Serialize)]
struct BenchTiming {
    warmups: usize,
    repeats: usize,
    samples_seconds: Vec<f64>,
    min_seconds: f64,
    max_seconds: f64,
    avg_seconds: f64,
}

#[derive(Debug, Clone, Serialize)]
struct BenchProofMetrics {
    proof_wire_bytes: usize,
    commitments_count: usize,
    decommitments_count: usize,
    trace_decommit_hashes: usize,
    fri_inner_layers_count: usize,
    fri_first_layer_witness_len: usize,
    fri_last_layer_poly_len: usize,
    fri_decommit_hashes_total: usize,
}

#[derive(Debug, Clone, Serialize)]
struct BenchReport {
    runtime: String,
    example: String,
    prove_mode: String,
    include_all_preprocessed_columns: bool,
    prove: BenchTiming,
    verify: BenchTiming,
    proof_metrics: BenchProofMetrics,
}

#[derive(Debug, Clone, Copy)]
enum ExampleStatement {
    Blake(BlakeStatement),
    Plonk(PlonkStatement),
    Poseidon(PoseidonStatement),
    StateMachine(StateMachineStatement),
    WideFibonacci(WideFibonacciStatement),
    Xor(XorStatement),
}

#[derive(Debug, Clone, Copy)]
struct StateMachineElements {
    z: SecureField,
    alpha: SecureField,
}

#[derive(Debug, Clone, Copy)]
struct StateMachineStatement {
    public_input: [[M31; 2]; 2],
    stmt0_n: u32,
    stmt0_m: u32,
    stmt1_x_axis_claimed_sum: SecureField,
    stmt1_y_axis_claimed_sum: SecureField,
}

#[derive(Debug, Clone, Copy)]
struct XorStatement {
    log_size: u32,
    log_step: u32,
    offset: usize,
}

#[derive(Debug, Clone, Copy)]
struct WideFibonacciStatement {
    log_n_rows: u32,
    sequence_len: u32,
}

#[derive(Debug, Clone, Copy)]
struct PlonkStatement {
    log_n_rows: u32,
}

#[derive(Debug, Clone, Copy)]
struct PoseidonStatement {
    log_n_instances: u32,
}

#[derive(Debug, Clone, Copy)]
struct BlakeStatement {
    log_n_rows: u32,
    n_rounds: u32,
}

#[derive(Debug, Clone, Copy)]
struct StateMachineComponent {
    trace_log_size: u32,
    composition_eval: SecureField,
}

#[derive(Debug, Clone, Copy)]
struct XorComponent {
    statement: XorStatement,
}

#[derive(Debug, Clone, Copy)]
struct WideFibonacciComponent {
    statement: WideFibonacciStatement,
}

#[derive(Debug, Clone, Copy)]
struct PlonkComponent {
    statement: PlonkStatement,
}

#[derive(Debug, Clone, Copy)]
struct PoseidonComponent {
    statement: PoseidonStatement,
}

#[derive(Debug, Clone, Copy)]
struct BlakeComponent {
    statement: BlakeStatement,
}

fn main() -> Result<()> {
    let cli = parse_cli(env::args().collect())?;
    match cli.mode {
        Mode::Generate => run_generate(&cli),
        Mode::Verify => run_verify(&cli),
        Mode::Bench => run_bench(&cli),
    }
}

fn run_generate(cli: &Cli) -> Result<()> {
    let example = cli
        .example
        .ok_or_else(|| anyhow!("--example is required for generate mode"))?;
    let config = pcs_config_from_cli(cli)?;

    let artifact = match example {
        Example::Blake => {
            let statement = BlakeStatement {
                log_n_rows: cli.blake_log_n_rows,
                n_rounds: cli.blake_n_rounds,
            };
            let (statement, proof) = blake_prove(
                config,
                statement,
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
            let (statement, proof) = plonk_prove(
                config,
                statement,
                cli.prove_mode,
                cli.include_all_preprocessed_columns,
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
            };
            let (statement, proof) = poseidon_prove(
                config,
                statement,
                cli.prove_mode,
                cli.include_all_preprocessed_columns,
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
            let (statement, proof) = wide_fibonacci_prove(
                config,
                statement,
                cli.prove_mode,
                cli.include_all_preprocessed_columns,
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
            };
            let (statement, proof) = xor_prove(
                config,
                statement,
                cli.prove_mode,
                cli.include_all_preprocessed_columns,
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

fn run_verify(cli: &Cli) -> Result<()> {
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

    let config = pcs_config_from_wire(&artifact.pcs_config)?;
    let proof_bytes = hex::decode(&artifact.proof_bytes_hex)?;
    let proof_wire: ProofWire = serde_json::from_slice(&proof_bytes)?;
    let proof = wire_to_proof(proof_wire)?;

    match artifact.example.as_str() {
        "blake" => {
            let statement_wire = artifact
                .blake_statement
                .as_ref()
                .ok_or_else(|| anyhow!("missing blake_statement"))?;
            let statement = blake_statement_from_wire(statement_wire)?;
            blake_verify(config, statement, proof)?;
        }
        "plonk" => {
            let statement_wire = artifact
                .plonk_statement
                .as_ref()
                .ok_or_else(|| anyhow!("missing plonk_statement"))?;
            let statement = plonk_statement_from_wire(statement_wire)?;
            plonk_verify(config, statement, proof)?;
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

fn run_bench(cli: &Cli) -> Result<()> {
    let example = cli
        .example
        .ok_or_else(|| anyhow!("--example is required for bench mode"))?;
    if cli.bench_repeats == 0 {
        bail!("--bench-repeats must be positive");
    }
    let config = pcs_config_from_cli(cli)?;
    let total_runs = cli.bench_warmups + cli.bench_repeats;

    let mut prove_samples = Vec::with_capacity(cli.bench_repeats);
    for i in 0..total_runs {
        let start = std::time::Instant::now();
        let (_, proof) = prove_example(
            config,
            example,
            cli,
            cli.prove_mode,
            cli.include_all_preprocessed_columns,
        )?;
        let _encoded = serde_json::to_vec(&proof_to_wire(&proof)?)?;
        let elapsed = start.elapsed().as_secs_f64();
        drop(proof);
        if i >= cli.bench_warmups {
            prove_samples.push(elapsed);
        }
    }

    let (statement, baseline_proof) = prove_example(
        config,
        example,
        cli,
        cli.prove_mode,
        cli.include_all_preprocessed_columns,
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

fn prove_mode_to_str(mode: ProveMode) -> &'static str {
    match mode {
        ProveMode::Prove => "prove",
        ProveMode::ProveEx => "prove_ex",
    }
}

fn prove_mode_from_str(value: &str) -> Option<ProveMode> {
    match value {
        "prove" => Some(ProveMode::Prove),
        "prove_ex" => Some(ProveMode::ProveEx),
        _ => None,
    }
}

fn summarize_timing(warmups: usize, repeats: usize, samples: Vec<f64>) -> Result<BenchTiming> {
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

fn parse_cli(args: Vec<String>) -> Result<Cli> {
    let mut mode: Option<Mode> = None;
    let mut example: Option<Example> = None;
    let mut artifact: Option<String> = None;
    let mut prove_mode = ProveMode::Prove;
    let mut include_all_preprocessed_columns = false;

    let mut pow_bits = 0u32;
    let mut fri_log_blowup = 1u32;
    let mut fri_log_last_layer = 0u32;
    let mut fri_n_queries = 3usize;

    let mut sm_log_n_rows = 5u32;
    let mut sm_initial_0 = 9u32;
    let mut sm_initial_1 = 3u32;

    let mut blake_log_n_rows = 5u32;
    let mut blake_n_rounds = 10u32;

    let mut plonk_log_n_rows = 5u32;

    let mut poseidon_log_n_instances = 8u32;

    let mut wf_log_n_rows = 5u32;
    let mut wf_sequence_len = 16u32;

    let mut xor_log_size = 5u32;
    let mut xor_log_step = 2u32;
    let mut xor_offset = 3usize;

    let mut bench_warmups = 1usize;
    let mut bench_repeats = 5usize;

    let mut i = 1usize;
    while i < args.len() {
        let flag = &args[i];
        if !flag.starts_with("--") {
            bail!("invalid argument {flag}");
        }
        if i + 1 >= args.len() {
            bail!("missing value for {flag}");
        }
        let value = &args[i + 1];
        i += 2;

        match flag.as_str() {
            "--mode" => {
                mode = match value.as_str() {
                    "generate" => Some(Mode::Generate),
                    "verify" => Some(Mode::Verify),
                    "bench" => Some(Mode::Bench),
                    _ => bail!("invalid mode {value}"),
                }
            }
            "--example" => {
                example = match value.as_str() {
                    "blake" => Some(Example::Blake),
                    "plonk" => Some(Example::Plonk),
                    "poseidon" => Some(Example::Poseidon),
                    "state_machine" => Some(Example::StateMachine),
                    "wide_fibonacci" => Some(Example::WideFibonacci),
                    "xor" => Some(Example::Xor),
                    _ => bail!("invalid example {value}"),
                }
            }
            "--artifact" => artifact = Some(value.clone()),
            "--prove-mode" => {
                prove_mode = prove_mode_from_str(value)
                    .ok_or_else(|| anyhow!("invalid prove mode {value}"))?
            }
            "--include-all-preprocessed-columns" => {
                include_all_preprocessed_columns = match value.as_str() {
                    "0" | "false" => false,
                    "1" | "true" => true,
                    _ => bail!(
                        "invalid boolean value for --include-all-preprocessed-columns: {value}"
                    ),
                };
            }
            "--pow-bits" => pow_bits = value.parse()?,
            "--fri-log-blowup" => fri_log_blowup = value.parse()?,
            "--fri-log-last-layer" => fri_log_last_layer = value.parse()?,
            "--fri-n-queries" => fri_n_queries = value.parse()?,
            "--sm-log-n-rows" => sm_log_n_rows = value.parse()?,
            "--sm-initial-0" => sm_initial_0 = value.parse()?,
            "--sm-initial-1" => sm_initial_1 = value.parse()?,
            "--blake-log-n-rows" => blake_log_n_rows = value.parse()?,
            "--blake-n-rounds" => blake_n_rounds = value.parse()?,
            "--plonk-log-n-rows" => plonk_log_n_rows = value.parse()?,
            "--poseidon-log-n-instances" => poseidon_log_n_instances = value.parse()?,
            "--wf-log-n-rows" => wf_log_n_rows = value.parse()?,
            "--wf-sequence-len" => wf_sequence_len = value.parse()?,
            "--xor-log-size" => xor_log_size = value.parse()?,
            "--xor-log-step" => xor_log_step = value.parse()?,
            "--xor-offset" => xor_offset = value.parse()?,
            "--bench-warmups" => bench_warmups = value.parse()?,
            "--bench-repeats" => bench_repeats = value.parse()?,
            _ => bail!("unknown flag {flag}"),
        }
    }

    Ok(Cli {
        mode: mode.ok_or_else(|| anyhow!("--mode is required"))?,
        example,
        artifact: artifact.ok_or_else(|| anyhow!("--artifact is required"))?,
        prove_mode,
        include_all_preprocessed_columns,
        pow_bits,
        fri_log_blowup,
        fri_log_last_layer,
        fri_n_queries,
        sm_log_n_rows,
        sm_initial_0,
        sm_initial_1,
        blake_log_n_rows,
        blake_n_rounds,
        plonk_log_n_rows,
        poseidon_log_n_instances,
        wf_log_n_rows,
        wf_sequence_len,
        xor_log_size,
        xor_log_step,
        xor_offset,
        bench_warmups,
        bench_repeats,
    })
}

fn pcs_config_from_cli(cli: &Cli) -> Result<PcsConfig> {
    Ok(PcsConfig {
        pow_bits: cli.pow_bits,
        fri_config: FriConfig::new(
            cli.fri_log_last_layer,
            cli.fri_log_blowup,
            cli.fri_n_queries,
        ),
    })
}

fn pcs_config_to_wire(config: PcsConfig) -> PcsConfigWire {
    PcsConfigWire {
        pow_bits: config.pow_bits,
        fri_config: FriConfigWire {
            log_blowup_factor: config.fri_config.log_blowup_factor,
            log_last_layer_degree_bound: config.fri_config.log_last_layer_degree_bound,
            n_queries: config.fri_config.n_queries as u64,
        },
    }
}

fn pcs_config_from_wire(wire: &PcsConfigWire) -> Result<PcsConfig> {
    let n_queries: usize = wire
        .fri_config
        .n_queries
        .try_into()
        .map_err(|_| anyhow!("fri n_queries out of range"))?;
    Ok(PcsConfig {
        pow_bits: wire.pow_bits,
        fri_config: FriConfig::new(
            wire.fri_config.log_last_layer_degree_bound,
            wire.fri_config.log_blowup_factor,
            n_queries,
        ),
    })
}

fn checked_m31(value: u32) -> Result<M31> {
    if value >= P {
        bail!("non-canonical m31 value {value}");
    }
    Ok(M31::from_u32_unchecked(value))
}

fn qm31_to_wire(value: SecureField) -> Qm31Wire {
    let arr = value.to_m31_array();
    [arr[0].0, arr[1].0, arr[2].0, arr[3].0]
}

fn qm31_from_wire(value: Qm31Wire) -> Result<SecureField> {
    Ok(QM31::from_m31(
        checked_m31(value[0])?,
        checked_m31(value[1])?,
        checked_m31(value[2])?,
        checked_m31(value[3])?,
    ))
}

fn proof_to_wire(proof: &StarkProof<Blake2sMerkleHasher>) -> Result<ProofWire> {
    let pcs_proof = &proof.0;

    let commitments = pcs_proof
        .commitments
        .iter()
        .map(|hash| hash.0)
        .collect::<Vec<_>>();

    let sampled_values = pcs_proof
        .sampled_values
        .0
        .iter()
        .map(|tree| {
            tree.iter()
                .map(|col| col.iter().copied().map(qm31_to_wire).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let decommitments = pcs_proof
        .decommitments
        .0
        .iter()
        .map(|decommitment| MerkleDecommitmentWire {
            hash_witness: decommitment
                .hash_witness
                .iter()
                .map(|hash| hash.0)
                .collect(),
        })
        .collect::<Vec<_>>();

    let queried_values = pcs_proof
        .queried_values
        .0
        .iter()
        .map(|tree| {
            tree.iter()
                .map(|col| col.iter().map(|value| value.0).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let first_layer = fri_layer_to_wire(&pcs_proof.fri_proof.first_layer);
    let inner_layers = pcs_proof
        .fri_proof
        .inner_layers
        .iter()
        .map(fri_layer_to_wire)
        .collect::<Vec<_>>();
    let last_layer_poly = pcs_proof
        .fri_proof
        .last_layer_poly
        .iter()
        .copied()
        .map(qm31_to_wire)
        .collect::<Vec<_>>();

    Ok(ProofWire {
        config: pcs_config_to_wire(pcs_proof.config),
        commitments,
        sampled_values,
        decommitments,
        queried_values,
        proof_of_work: pcs_proof.proof_of_work,
        fri_proof: FriProofWire {
            first_layer,
            inner_layers,
            last_layer_poly,
        },
    })
}

fn wire_to_proof(wire: ProofWire) -> Result<StarkProof<Blake2sMerkleHasher>> {
    let config = pcs_config_from_wire(&wire.config)?;

    let commitments = wire
        .commitments
        .into_iter()
        .map(Blake2sHash)
        .collect::<Vec<_>>();

    let sampled_values = wire
        .sampled_values
        .into_iter()
        .map(|tree| {
            tree.into_iter()
                .map(|col| {
                    col.into_iter()
                        .map(qm31_from_wire)
                        .collect::<Result<Vec<_>>>()
                })
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;

    let decommitments = wire
        .decommitments
        .into_iter()
        .map(
            |decommitment| MerkleDecommitmentLifted::<Blake2sMerkleHasher> {
                hash_witness: decommitment
                    .hash_witness
                    .into_iter()
                    .map(Blake2sHash)
                    .collect(),
            },
        )
        .collect::<Vec<_>>();

    let queried_values = wire
        .queried_values
        .into_iter()
        .map(|tree| {
            tree.into_iter()
                .map(|col| col.into_iter().map(checked_m31).collect::<Result<Vec<_>>>())
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;

    let fri_proof = FriProof {
        first_layer: wire_to_fri_layer(wire.fri_proof.first_layer)?,
        inner_layers: wire
            .fri_proof
            .inner_layers
            .into_iter()
            .map(wire_to_fri_layer)
            .collect::<Result<Vec<_>>>()?,
        last_layer_poly: LinePoly::new(
            wire.fri_proof
                .last_layer_poly
                .into_iter()
                .map(qm31_from_wire)
                .collect::<Result<Vec<_>>>()?,
        ),
    };

    Ok(StarkProof(CommitmentSchemeProof {
        config,
        commitments: TreeVec::new(commitments),
        sampled_values: TreeVec::new(sampled_values),
        decommitments: TreeVec::new(decommitments),
        queried_values: TreeVec::new(queried_values),
        proof_of_work: wire.proof_of_work,
        fri_proof,
    }))
}

fn fri_layer_to_wire(layer: &FriLayerProof<Blake2sMerkleHasher>) -> FriLayerWire {
    FriLayerWire {
        fri_witness: layer
            .fri_witness
            .iter()
            .copied()
            .map(qm31_to_wire)
            .collect(),
        decommitment: MerkleDecommitmentWire {
            hash_witness: layer
                .decommitment
                .hash_witness
                .iter()
                .map(|hash| hash.0)
                .collect(),
        },
        commitment: layer.commitment.0,
    }
}

fn wire_to_fri_layer(layer: FriLayerWire) -> Result<FriLayerProof<Blake2sMerkleHasher>> {
    Ok(FriLayerProof {
        fri_witness: layer
            .fri_witness
            .into_iter()
            .map(qm31_from_wire)
            .collect::<Result<Vec<_>>>()?,
        decommitment: MerkleDecommitmentLifted::<Blake2sMerkleHasher> {
            hash_witness: layer
                .decommitment
                .hash_witness
                .into_iter()
                .map(Blake2sHash)
                .collect(),
        },
        commitment: Blake2sHash(layer.commitment),
    })
}

fn state_machine_statement_to_wire(statement: StateMachineStatement) -> StateMachineStatementWire {
    StateMachineStatementWire {
        public_input: [
            [
                statement.public_input[0][0].0,
                statement.public_input[0][1].0,
            ],
            [
                statement.public_input[1][0].0,
                statement.public_input[1][1].0,
            ],
        ],
        stmt0: StateMachineStmt0Wire {
            n: statement.stmt0_n,
            m: statement.stmt0_m,
        },
        stmt1: StateMachineStmt1Wire {
            x_axis_claimed_sum: qm31_to_wire(statement.stmt1_x_axis_claimed_sum),
            y_axis_claimed_sum: qm31_to_wire(statement.stmt1_y_axis_claimed_sum),
        },
    }
}

fn state_machine_statement_from_wire(
    wire: &StateMachineStatementWire,
) -> Result<StateMachineStatement> {
    Ok(StateMachineStatement {
        public_input: [
            [
                checked_m31(wire.public_input[0][0])?,
                checked_m31(wire.public_input[0][1])?,
            ],
            [
                checked_m31(wire.public_input[1][0])?,
                checked_m31(wire.public_input[1][1])?,
            ],
        ],
        stmt0_n: wire.stmt0.n,
        stmt0_m: wire.stmt0.m,
        stmt1_x_axis_claimed_sum: qm31_from_wire(wire.stmt1.x_axis_claimed_sum)?,
        stmt1_y_axis_claimed_sum: qm31_from_wire(wire.stmt1.y_axis_claimed_sum)?,
    })
}

fn xor_statement_to_wire(statement: XorStatement) -> Result<XorStatementWire> {
    Ok(XorStatementWire {
        log_size: statement.log_size,
        log_step: statement.log_step,
        offset: statement.offset as u64,
    })
}

fn xor_statement_from_wire(wire: &XorStatementWire) -> Result<XorStatement> {
    let offset: usize = wire
        .offset
        .try_into()
        .map_err(|_| anyhow!("xor offset out of range"))?;
    Ok(XorStatement {
        log_size: wire.log_size,
        log_step: wire.log_step,
        offset,
    })
}

fn wide_fibonacci_statement_to_wire(
    statement: WideFibonacciStatement,
) -> WideFibonacciStatementWire {
    WideFibonacciStatementWire {
        log_n_rows: statement.log_n_rows,
        sequence_len: statement.sequence_len,
    }
}

fn wide_fibonacci_statement_from_wire(
    wire: &WideFibonacciStatementWire,
) -> Result<WideFibonacciStatement> {
    Ok(WideFibonacciStatement {
        log_n_rows: wire.log_n_rows,
        sequence_len: wire.sequence_len,
    })
}

fn plonk_statement_to_wire(statement: PlonkStatement) -> PlonkStatementWire {
    PlonkStatementWire {
        log_n_rows: statement.log_n_rows,
    }
}

fn plonk_statement_from_wire(wire: &PlonkStatementWire) -> Result<PlonkStatement> {
    Ok(PlonkStatement {
        log_n_rows: wire.log_n_rows,
    })
}

fn poseidon_statement_to_wire(statement: PoseidonStatement) -> PoseidonStatementWire {
    PoseidonStatementWire {
        log_n_instances: statement.log_n_instances,
    }
}

fn poseidon_statement_from_wire(wire: &PoseidonStatementWire) -> Result<PoseidonStatement> {
    Ok(PoseidonStatement {
        log_n_instances: wire.log_n_instances,
    })
}

fn blake_statement_to_wire(statement: BlakeStatement) -> BlakeStatementWire {
    BlakeStatementWire {
        log_n_rows: statement.log_n_rows,
        n_rounds: statement.n_rounds,
    }
}

fn blake_statement_from_wire(wire: &BlakeStatementWire) -> Result<BlakeStatement> {
    Ok(BlakeStatement {
        log_n_rows: wire.log_n_rows,
        n_rounds: wire.n_rounds,
    })
}

fn prove_example(
    config: PcsConfig,
    example: Example,
    cli: &Cli,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(ExampleStatement, StarkProof<Blake2sMerkleHasher>)> {
    match example {
        Example::Blake => {
            let statement = BlakeStatement {
                log_n_rows: cli.blake_log_n_rows,
                n_rounds: cli.blake_n_rounds,
            };
            let (statement, proof) = blake_prove(
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
            let (statement, proof) = plonk_prove(
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
            let (statement, proof) = poseidon_prove(
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
            let (statement, proof) = state_machine_prove(
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
            let (statement, proof) = wide_fibonacci_prove(
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
            let (statement, proof) = xor_prove(
                config,
                statement,
                prove_mode,
                include_all_preprocessed_columns,
            )?;
            Ok((ExampleStatement::Xor(statement), proof))
        }
    }
}

fn verify_example(
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

fn proof_metrics_from_proof(proof: &StarkProof<Blake2sMerkleHasher>) -> Result<BenchProofMetrics> {
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

fn state_machine_prove(
    config: PcsConfig,
    log_n_rows: u32,
    initial_state: [M31; 2],
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(StateMachineStatement, StarkProof<Blake2sMerkleHasher>)> {
    if log_n_rows == 0 || log_n_rows >= 31 {
        bail!("invalid log_n_rows {log_n_rows}");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    let preprocessed = gen_is_first(log_n_rows)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![cpu_eval(log_n_rows, preprocessed)]);
    builder.commit(&mut channel);

    let [trace0, trace1] = gen_trace(log_n_rows, initial_state, 0)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![
        cpu_eval(log_n_rows, trace0),
        cpu_eval(log_n_rows, trace1),
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
        ProveMode::Prove => {
            prove::<CpuBackend, Blake2sMerkleChannel>(&[&component], &mut channel, scheme)?
        }
        ProveMode::ProveEx => {
            prove_ex::<CpuBackend, Blake2sMerkleChannel>(
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

fn state_machine_verify(
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

fn wide_fibonacci_prove(
    config: PcsConfig,
    statement: WideFibonacciStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(WideFibonacciStatement, StarkProof<Blake2sMerkleHasher>)> {
    if statement.log_n_rows == 0 || statement.log_n_rows >= 31 {
        bail!("invalid wide_fibonacci log_n_rows");
    }
    if statement.sequence_len < 2 {
        bail!("invalid wide_fibonacci sequence_len");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(statement.log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![]);
    builder.commit(&mut channel);

    let trace = gen_wide_fibonacci_trace(statement.log_n_rows, statement.sequence_len)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        trace
            .into_iter()
            .map(|col| cpu_eval(statement.log_n_rows, col))
            .collect(),
    );
    builder.commit(&mut channel);

    mix_wide_fibonacci_statement(&mut channel, statement);

    let component = WideFibonacciComponent { statement };
    let proof = match prove_mode {
        ProveMode::Prove => {
            prove::<CpuBackend, Blake2sMerkleChannel>(&[&component], &mut channel, scheme)?
        }
        ProveMode::ProveEx => {
            prove_ex::<CpuBackend, Blake2sMerkleChannel>(
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

fn wide_fibonacci_verify(
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

fn plonk_prove(
    config: PcsConfig,
    statement: PlonkStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(PlonkStatement, StarkProof<Blake2sMerkleHasher>)> {
    if statement.log_n_rows == 0 || statement.log_n_rows >= 31 {
        bail!("invalid plonk log_n_rows");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(statement.log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    let (preprocessed, main) = gen_plonk_trace(statement.log_n_rows)?;

    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        preprocessed
            .into_iter()
            .map(|col| cpu_eval(statement.log_n_rows, col))
            .collect(),
    );
    builder.commit(&mut channel);

    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        main.into_iter()
            .map(|col| cpu_eval(statement.log_n_rows, col))
            .collect(),
    );
    builder.commit(&mut channel);

    mix_plonk_statement(&mut channel, statement);

    let component = PlonkComponent { statement };
    let proof = match prove_mode {
        ProveMode::Prove => {
            prove::<CpuBackend, Blake2sMerkleChannel>(&[&component], &mut channel, scheme)?
        }
        ProveMode::ProveEx => {
            prove_ex::<CpuBackend, Blake2sMerkleChannel>(
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

fn plonk_verify(
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

fn poseidon_prove(
    config: PcsConfig,
    statement: PoseidonStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(PoseidonStatement, StarkProof<Blake2sMerkleHasher>)> {
    let log_n_rows = poseidon_log_n_rows(statement)?;

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![]);
    builder.commit(&mut channel);

    let trace = gen_poseidon_trace(log_n_rows)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        trace
            .into_iter()
            .map(|col| cpu_eval(log_n_rows, col))
            .collect(),
    );
    builder.commit(&mut channel);

    mix_poseidon_statement(&mut channel, statement);

    let component = PoseidonComponent { statement };
    let proof = match prove_mode {
        ProveMode::Prove => {
            prove::<CpuBackend, Blake2sMerkleChannel>(&[&component], &mut channel, scheme)?
        }
        ProveMode::ProveEx => {
            prove_ex::<CpuBackend, Blake2sMerkleChannel>(
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

fn poseidon_verify(
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

fn blake_prove(
    config: PcsConfig,
    statement: BlakeStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(BlakeStatement, StarkProof<Blake2sMerkleHasher>)> {
    blake_validate_statement(statement)?;
    let n_columns = blake_n_columns(statement)?;

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(statement.log_n_rows + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![]);
    builder.commit(&mut channel);

    let trace = gen_blake_trace(statement)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(
        trace
            .into_iter()
            .map(|col| cpu_eval(statement.log_n_rows, col))
            .collect(),
    );
    builder.commit(&mut channel);

    mix_blake_statement(&mut channel, statement);

    let component = BlakeComponent { statement };
    let proof = match prove_mode {
        ProveMode::Prove => {
            prove::<CpuBackend, Blake2sMerkleChannel>(&[&component], &mut channel, scheme)?
        }
        ProveMode::ProveEx => {
            prove_ex::<CpuBackend, Blake2sMerkleChannel>(
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

fn blake_verify(
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

fn xor_prove(
    config: PcsConfig,
    statement: XorStatement,
    prove_mode: ProveMode,
    include_all_preprocessed_columns: bool,
) -> Result<(XorStatement, StarkProof<Blake2sMerkleHasher>)> {
    if statement.log_size == 0 {
        bail!("invalid xor log_size");
    }
    if statement.log_step > statement.log_size {
        bail!("invalid xor log_step");
    }

    let mut channel = Blake2sChannel::default();
    config.mix_into(&mut channel);

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(statement.log_size + config.fri_config.log_blowup_factor + 1)
            .circle_domain()
            .half_coset,
    );
    let mut scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    let is_first = gen_is_first(statement.log_size)?;
    let is_step =
        gen_is_step_with_offset(statement.log_size, statement.log_step, statement.offset)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![
        cpu_eval(statement.log_size, is_first),
        cpu_eval(statement.log_size, is_step),
    ]);
    builder.commit(&mut channel);

    let main = gen_xor_main(statement.log_size)?;
    let mut builder = scheme.tree_builder();
    builder.extend_evals(vec![cpu_eval(statement.log_size, main)]);
    builder.commit(&mut channel);

    mix_xor_statement(&mut channel, statement);

    let component = XorComponent { statement };
    let proof = match prove_mode {
        ProveMode::Prove => {
            prove::<CpuBackend, Blake2sMerkleChannel>(&[&component], &mut channel, scheme)?
        }
        ProveMode::ProveEx => {
            prove_ex::<CpuBackend, Blake2sMerkleChannel>(
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

fn xor_verify(
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

fn cpu_eval(log_size: u32, values: Vec<M31>) -> CpuCircleEvaluation<M31, BitReversedOrder> {
    CpuCircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), values)
}

fn checked_pow2(log_size: u32) -> Result<usize> {
    if log_size >= usize::BITS {
        bail!("invalid log_size {log_size}");
    }
    Ok(1usize << log_size)
}

fn gen_is_first(log_size: u32) -> Result<Vec<M31>> {
    let n = checked_pow2(log_size)?;
    let mut values = vec![M31::zero(); n];
    values[0] = M31::one();
    Ok(values)
}

fn gen_trace(log_size: u32, initial_state: [M31; 2], inc_index: usize) -> Result<[Vec<M31>; 2]> {
    if inc_index >= 2 {
        bail!("invalid inc_index {inc_index}");
    }
    let n = checked_pow2(log_size)?;

    let mut col0 = vec![M31::zero(); n];
    let mut col1 = vec![M31::zero(); n];

    let mut curr_state = initial_state;
    for i in 0..n {
        let bit_rev_index =
            bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size);
        col0[bit_rev_index] = curr_state[0];
        col1[bit_rev_index] = curr_state[1];
        curr_state[inc_index] += M31::one();
    }

    Ok([col0, col1])
}

fn gen_wide_fibonacci_trace(log_n_rows: u32, sequence_len: u32) -> Result<Vec<Vec<M31>>> {
    if log_n_rows == 0 || log_n_rows >= 31 {
        bail!("invalid log_n_rows");
    }
    if sequence_len < 2 {
        bail!("invalid sequence_len");
    }

    let n = checked_pow2(log_n_rows)?;
    let n_cols = sequence_len as usize;
    let mut trace = vec![vec![M31::zero(); n]; n_cols];

    for row in 0..n {
        let bit_rev_index = bit_reverse_index(
            coset_index_to_circle_domain_index(row, log_n_rows),
            log_n_rows,
        );
        let mut a = M31::one();
        let mut b = M31::from(row as u32);
        trace[0][bit_rev_index] = a;
        trace[1][bit_rev_index] = b;
        for col in trace.iter_mut().skip(2) {
            let c = a.square() + b.square();
            col[bit_rev_index] = c;
            a = b;
            b = c;
        }
    }

    Ok(trace)
}

fn gen_is_step_with_offset(log_size: u32, log_step: u32, offset: usize) -> Result<Vec<M31>> {
    if log_step > log_size {
        bail!("invalid step");
    }
    let n = checked_pow2(log_size)?;
    let step = checked_pow2(log_step)?;

    let mut values = vec![M31::zero(); n];
    let mut i = offset % step;
    while i < n {
        let circle_domain_index = coset_index_to_circle_domain_index(i, log_size);
        let bit_rev_index = bit_reverse_index(circle_domain_index, log_size);
        values[bit_rev_index] = M31::one();
        i += step;
    }

    Ok(values)
}

fn gen_xor_main(log_size: u32) -> Result<Vec<M31>> {
    let n = checked_pow2(log_size)?;
    let mut values = vec![M31::zero(); n];
    for i in 0..n {
        let circle_domain_index = coset_index_to_circle_domain_index(i, log_size);
        let bit_rev_index = bit_reverse_index(circle_domain_index, log_size);
        values[bit_rev_index] = if (i & 1) == 0 {
            M31::one()
        } else {
            M31::zero()
        };
    }
    Ok(values)
}

fn gen_plonk_trace(log_n_rows: u32) -> Result<([Vec<M31>; 4], [Vec<M31>; 4])> {
    if log_n_rows == 0 || log_n_rows >= 31 {
        bail!("invalid plonk log_n_rows");
    }
    let n = checked_pow2(log_n_rows)?;

    let mut preprocessed = std::array::from_fn(|_| vec![M31::zero(); n]);
    let mut main = std::array::from_fn(|_| vec![M31::zero(); n]);

    let mut fib = vec![M31::zero(); n + 2];
    fib[0] = M31::one();
    fib[1] = M31::one();
    for i in 2..fib.len() {
        fib[i] = fib[i - 1] + fib[i - 2];
    }

    for i in 0..n {
        preprocessed[0][i] = M31::from(i as u32);
        preprocessed[1][i] = M31::from((i + 1) as u32);
        preprocessed[2][i] = M31::from((i + 2) as u32);
        preprocessed[3][i] = M31::one();

        main[0][i] = M31::one();
        main[1][i] = fib[i];
        main[2][i] = fib[i + 1];
        main[3][i] = fib[i + 2];
    }

    if n >= 2 {
        main[0][n - 1] = M31::zero();
        main[0][n - 2] = M31::one();
    }

    Ok((preprocessed, main))
}

fn poseidon_log_n_rows(statement: PoseidonStatement) -> Result<u32> {
    if statement.log_n_instances < POSEIDON_LOG_INSTANCES_PER_ROW {
        bail!("invalid poseidon log_n_instances");
    }
    let log_n_rows = statement.log_n_instances - POSEIDON_LOG_INSTANCES_PER_ROW;
    if log_n_rows >= 31 {
        bail!("invalid poseidon log_n_rows");
    }
    Ok(log_n_rows)
}

fn poseidon_external_round_const(round: usize, state_i: usize) -> M31 {
    M31::from(((1234u64 + (round as u64 * 37) + state_i as u64) % P as u64) as u32)
}

fn poseidon_internal_round_const(round: usize) -> M31 {
    M31::from(((9876u64 + (round as u64 * 17)) % P as u64) as u32)
}

fn poseidon_pow5(x: M31) -> M31 {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

fn poseidon_apply_m4(x: [M31; 4]) -> [M31; 4] {
    let t0 = x[0] + x[1];
    let t02 = t0 + t0;
    let t1 = x[2] + x[3];
    let t12 = t1 + t1;
    let t2 = x[1] + x[1] + t1;
    let t3 = x[3] + x[3] + t0;
    let t4 = t12 + t12 + t3;
    let t5 = t02 + t02 + t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    [t6, t5, t7, t4]
}

fn poseidon_apply_external_round_matrix(state: &mut [M31; POSEIDON_STATE]) {
    for i in 0..4 {
        let offset = i * 4;
        let mixed = poseidon_apply_m4([
            state[offset],
            state[offset + 1],
            state[offset + 2],
            state[offset + 3],
        ]);
        state[offset] = mixed[0];
        state[offset + 1] = mixed[1];
        state[offset + 2] = mixed[2];
        state[offset + 3] = mixed[3];
    }

    for j in 0..4 {
        let s = state[j] + state[j + 4] + state[j + 8] + state[j + 12];
        for i in 0..4 {
            let idx = i * 4 + j;
            state[idx] += s;
        }
    }
}

fn poseidon_apply_internal_round_matrix(state: &mut [M31; POSEIDON_STATE]) {
    let sum = state
        .iter()
        .copied()
        .fold(M31::zero(), |acc, item| acc + item);
    for (i, value) in state.iter_mut().enumerate() {
        let coeff = M31::from_u32_unchecked(1u32 << ((i + 1) as u32));
        *value = *value * coeff + sum;
    }
}

fn gen_poseidon_trace(log_n_rows: u32) -> Result<Vec<Vec<M31>>> {
    if log_n_rows >= 31 {
        bail!("invalid poseidon log_n_rows");
    }
    let n = checked_pow2(log_n_rows)?;
    let mut trace = vec![vec![M31::zero(); n]; POSEIDON_COLUMNS];

    for row in 0..n {
        let mut col_index = 0usize;
        for rep_i in 0..POSEIDON_INSTANCES_PER_ROW {
            let mut state = std::array::from_fn(|state_i| {
                M31::from(((row * POSEIDON_STATE + state_i + rep_i) % P as usize) as u32)
            });

            for value in state {
                trace[col_index][row] = value;
                col_index += 1;
            }

            for round in 0..POSEIDON_HALF_FULL_ROUNDS {
                for (state_i, value) in state.iter_mut().enumerate() {
                    *value += poseidon_external_round_const(round, state_i);
                }
                poseidon_apply_external_round_matrix(&mut state);
                for value in state.iter_mut() {
                    *value = poseidon_pow5(*value);
                    trace[col_index][row] = *value;
                    col_index += 1;
                }
            }

            for round in 0..POSEIDON_PARTIAL_ROUNDS {
                state[0] += poseidon_internal_round_const(round);
                poseidon_apply_internal_round_matrix(&mut state);
                state[0] = poseidon_pow5(state[0]);
                trace[col_index][row] = state[0];
                col_index += 1;
            }

            for half_round in 0..POSEIDON_HALF_FULL_ROUNDS {
                let round = half_round + POSEIDON_HALF_FULL_ROUNDS;
                for (state_i, value) in state.iter_mut().enumerate() {
                    *value += poseidon_external_round_const(round, state_i);
                }
                poseidon_apply_external_round_matrix(&mut state);
                for value in state.iter_mut() {
                    *value = poseidon_pow5(*value);
                    trace[col_index][row] = *value;
                    col_index += 1;
                }
            }
        }
        debug_assert_eq!(col_index, POSEIDON_COLUMNS);
    }

    Ok(trace)
}

fn blake_validate_statement(statement: BlakeStatement) -> Result<()> {
    if statement.log_n_rows == 0 || statement.log_n_rows >= 31 {
        bail!("invalid blake log_n_rows");
    }
    if statement.n_rounds == 0 {
        bail!("invalid blake n_rounds");
    }
    let _ = blake_n_columns(statement)?;
    Ok(())
}

fn blake_n_columns(statement: BlakeStatement) -> Result<usize> {
    (statement.n_rounds as usize)
        .checked_mul(BLAKE_ROUND_INPUT_FELTS)
        .ok_or_else(|| anyhow!("blake column count overflow"))
}

fn blake_next_seed(seed: u64) -> u64 {
    let mut x = seed;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

fn gen_blake_trace(statement: BlakeStatement) -> Result<Vec<Vec<M31>>> {
    blake_validate_statement(statement)?;
    let n = checked_pow2(statement.log_n_rows)?;
    let n_columns = blake_n_columns(statement)?;
    let mut trace = vec![vec![M31::zero(); n]; n_columns];

    for row in 0..n {
        let mut col_index = 0usize;
        let mut seed = row as u64 + 1;
        for round in 0..statement.n_rounds as usize {
            for cell in 0..BLAKE_ROUND_INPUT_FELTS {
                seed = blake_next_seed(seed);
                let mixed = seed
                    ^ ((round as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
                    ^ (((cell + 1) as u64).wrapping_mul(0x517c_c1b7_2722_0a95));
                trace[col_index][row] = M31::from((mixed % P as u64) as u32);
                col_index += 1;
            }
        }
        debug_assert_eq!(col_index, n_columns);
    }

    Ok(trace)
}

fn state_machine_combine(elements: StateMachineElements, state: [M31; 2]) -> SecureField {
    SecureField::from(state[0]) + elements.alpha * SecureField::from(state[1]) - elements.z
}

fn transition_states(log_n_rows: u32, initial_state: [M31; 2]) -> Result<([M31; 2], [M31; 2])> {
    if log_n_rows == 0 || log_n_rows >= 31 {
        bail!("invalid log_n_rows");
    }
    let mut intermediate = initial_state;
    intermediate[0] += M31::from_u32_unchecked(1 << log_n_rows);

    let mut final_state = intermediate;
    final_state[1] += M31::from_u32_unchecked(1 << (log_n_rows - 1));

    Ok((intermediate, final_state))
}

fn claimed_sum_telescoping(
    log_size: u32,
    initial_state: [M31; 2],
    inc_index: usize,
    elements: StateMachineElements,
) -> Result<SecureField> {
    if inc_index >= 2 {
        bail!("invalid inc_index");
    }
    let n = checked_pow2(log_size)?;

    let first = state_machine_combine(elements, initial_state);

    let mut last_state = initial_state;
    last_state[inc_index] += M31::from(n);
    let last = state_machine_combine(elements, last_state);

    if first.is_zero() || last.is_zero() {
        bail!("degenerate denominator");
    }

    Ok(first.inverse() - last.inverse())
}

fn prepare_state_machine_statement(
    log_n_rows: u32,
    initial_state: [M31; 2],
    elements: StateMachineElements,
) -> Result<StateMachineStatement> {
    let (intermediate, final_state) = transition_states(log_n_rows, initial_state)?;
    let x_axis_claimed_sum = claimed_sum_telescoping(log_n_rows, initial_state, 0, elements)?;
    let y_axis_claimed_sum = claimed_sum_telescoping(log_n_rows - 1, intermediate, 1, elements)?;

    Ok(StateMachineStatement {
        public_input: [initial_state, final_state],
        stmt0_n: log_n_rows,
        stmt0_m: log_n_rows - 1,
        stmt1_x_axis_claimed_sum: x_axis_claimed_sum,
        stmt1_y_axis_claimed_sum: y_axis_claimed_sum,
    })
}

fn verify_state_machine_statement(
    statement: StateMachineStatement,
    elements: StateMachineElements,
) -> Result<()> {
    let initial_comb = state_machine_combine(elements, statement.public_input[0]);
    let final_comb = state_machine_combine(elements, statement.public_input[1]);
    if initial_comb.is_zero() || final_comb.is_zero() {
        bail!("degenerate denominator");
    }

    let lhs = (statement.stmt1_x_axis_claimed_sum + statement.stmt1_y_axis_claimed_sum)
        * initial_comb
        * final_comb;
    let rhs = final_comb - initial_comb;
    if lhs != rhs {
        bail!("state_machine statement not satisfied");
    }
    Ok(())
}

fn mix_state_machine_stmt0(channel: &mut Blake2sChannel, n: u32, m: u32) {
    channel.mix_u32s(&[n, m]);
}

fn mix_state_machine_public_input(channel: &mut Blake2sChannel, public_input: &[[M31; 2]; 2]) {
    channel.mix_u32s(&[
        public_input[0][0].0,
        public_input[0][1].0,
        public_input[1][0].0,
        public_input[1][1].0,
    ]);
}

fn mix_state_machine_stmt1(
    channel: &mut Blake2sChannel,
    x_claim: SecureField,
    y_claim: SecureField,
) {
    channel.mix_felts(&[x_claim, y_claim]);
}

fn wide_fibonacci_composition_eval(statement: WideFibonacciStatement) -> SecureField {
    SecureField::from_m31(
        M31::from(statement.log_n_rows),
        M31::from(statement.sequence_len),
        M31::zero(),
        M31::one(),
    )
}

fn mix_wide_fibonacci_statement(channel: &mut Blake2sChannel, statement: WideFibonacciStatement) {
    channel.mix_u32s(&[statement.log_n_rows, statement.sequence_len]);
}

fn plonk_composition_eval(statement: PlonkStatement) -> SecureField {
    SecureField::from_m31(
        M31::from(statement.log_n_rows),
        M31::from(4u32),
        M31::from(1u32),
        M31::one(),
    )
}

fn mix_plonk_statement(channel: &mut Blake2sChannel, statement: PlonkStatement) {
    channel.mix_u32s(&[statement.log_n_rows]);
}

fn poseidon_composition_eval(statement: PoseidonStatement) -> SecureField {
    SecureField::from_m31(
        M31::from(statement.log_n_instances),
        M31::from(POSEIDON_COLUMNS_PER_REP as u32),
        M31::from(POSEIDON_COLUMNS as u32),
        M31::one(),
    )
}

fn mix_poseidon_statement(channel: &mut Blake2sChannel, statement: PoseidonStatement) {
    channel.mix_u32s(&[statement.log_n_instances]);
}

fn blake_composition_eval(statement: BlakeStatement) -> SecureField {
    SecureField::from_m31(
        M31::from(statement.log_n_rows),
        M31::from(statement.n_rounds),
        M31::from(blake_n_columns(statement).unwrap_or(0) as u32),
        M31::one(),
    )
}

fn mix_blake_statement(channel: &mut Blake2sChannel, statement: BlakeStatement) {
    channel.mix_u32s(&[statement.log_n_rows, statement.n_rounds]);
}

fn xor_composition_eval(statement: XorStatement) -> SecureField {
    SecureField::from_m31(
        M31::from(statement.log_size),
        M31::from(statement.log_step),
        M31::from(statement.offset),
        M31::one(),
    )
}

fn mix_xor_statement(channel: &mut Blake2sChannel, statement: XorStatement) {
    channel.mix_u32s(&[statement.log_size, statement.log_step]);
    channel.mix_u64(statement.offset as u64);
}

impl Component for StateMachineComponent {
    fn n_constraints(&self) -> usize {
        1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.trace_log_size + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        TreeVec::new(vec![
            vec![self.trace_log_size],
            vec![self.trace_log_size, self.trace_log_size],
        ])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        TreeVec::new(vec![vec![vec![]], vec![vec![point], vec![point]]])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![0]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        evaluation_accumulator.accumulate(self.composition_eval);
    }
}

impl ComponentProver<CpuBackend> for StateMachineComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, CpuBackend>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<CpuBackend>,
    ) {
        let [mut col] = evaluation_accumulator.columns([(self.trace_log_size + 1, 1)]);
        let domain_size = 1usize << (self.trace_log_size + 1);
        for i in 0..domain_size {
            col.accumulate(i, self.composition_eval);
        }
    }
}

impl Component for WideFibonacciComponent {
    fn n_constraints(&self) -> usize {
        1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.statement.log_n_rows + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        TreeVec::new(vec![
            vec![],
            vec![self.statement.log_n_rows; self.statement.sequence_len as usize],
        ])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        TreeVec::new(vec![
            vec![],
            vec![vec![point]; self.statement.sequence_len as usize],
        ])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        evaluation_accumulator.accumulate(wide_fibonacci_composition_eval(self.statement));
    }
}

impl ComponentProver<CpuBackend> for WideFibonacciComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, CpuBackend>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<CpuBackend>,
    ) {
        let composition_eval = wide_fibonacci_composition_eval(self.statement);
        let [mut col] = evaluation_accumulator.columns([(self.statement.log_n_rows + 1, 1)]);
        let domain_size = 1usize << (self.statement.log_n_rows + 1);
        for i in 0..domain_size {
            col.accumulate(i, composition_eval);
        }
    }
}

impl Component for PlonkComponent {
    fn n_constraints(&self) -> usize {
        1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.statement.log_n_rows + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        TreeVec::new(vec![
            vec![self.statement.log_n_rows; 4],
            vec![self.statement.log_n_rows; 4],
        ])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        TreeVec::new(vec![vec![vec![point]; 4], vec![vec![point]; 4]])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![0, 1, 2, 3]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        evaluation_accumulator.accumulate(plonk_composition_eval(self.statement));
    }
}

impl ComponentProver<CpuBackend> for PlonkComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, CpuBackend>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<CpuBackend>,
    ) {
        let composition_eval = plonk_composition_eval(self.statement);
        let [mut col] = evaluation_accumulator.columns([(self.statement.log_n_rows + 1, 1)]);
        let domain_size = 1usize << (self.statement.log_n_rows + 1);
        for i in 0..domain_size {
            col.accumulate(i, composition_eval);
        }
    }
}

impl Component for PoseidonComponent {
    fn n_constraints(&self) -> usize {
        1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        poseidon_log_n_rows(self.statement).unwrap_or(0) + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        let log_n_rows = poseidon_log_n_rows(self.statement).unwrap_or(0);
        TreeVec::new(vec![vec![], vec![log_n_rows; POSEIDON_COLUMNS]])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        TreeVec::new(vec![vec![], vec![vec![point]; POSEIDON_COLUMNS]])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        evaluation_accumulator.accumulate(poseidon_composition_eval(self.statement));
    }
}

impl ComponentProver<CpuBackend> for PoseidonComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, CpuBackend>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<CpuBackend>,
    ) {
        let log_n_rows = poseidon_log_n_rows(self.statement).unwrap_or(0);
        let composition_eval = poseidon_composition_eval(self.statement);
        let [mut col] = evaluation_accumulator.columns([(log_n_rows + 1, 1)]);
        let domain_size = 1usize << (log_n_rows + 1);
        for i in 0..domain_size {
            col.accumulate(i, composition_eval);
        }
    }
}

impl Component for BlakeComponent {
    fn n_constraints(&self) -> usize {
        1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.statement.log_n_rows + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        let n_columns = blake_n_columns(self.statement).unwrap_or(0);
        TreeVec::new(vec![vec![], vec![self.statement.log_n_rows; n_columns]])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        let n_columns = blake_n_columns(self.statement).unwrap_or(0);
        TreeVec::new(vec![vec![], vec![vec![point]; n_columns]])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        evaluation_accumulator.accumulate(blake_composition_eval(self.statement));
    }
}

impl ComponentProver<CpuBackend> for BlakeComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, CpuBackend>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<CpuBackend>,
    ) {
        let composition_eval = blake_composition_eval(self.statement);
        let [mut col] = evaluation_accumulator.columns([(self.statement.log_n_rows + 1, 1)]);
        let domain_size = 1usize << (self.statement.log_n_rows + 1);
        for i in 0..domain_size {
            col.accumulate(i, composition_eval);
        }
    }
}

impl Component for XorComponent {
    fn n_constraints(&self) -> usize {
        1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.statement.log_size + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        TreeVec::new(vec![
            vec![self.statement.log_size, self.statement.log_size],
            vec![self.statement.log_size],
        ])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        TreeVec::new(vec![vec![vec![], vec![]], vec![vec![point]]])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![0, 1]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        evaluation_accumulator.accumulate(xor_composition_eval(self.statement));
    }
}

impl ComponentProver<CpuBackend> for XorComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, CpuBackend>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<CpuBackend>,
    ) {
        let composition_eval = xor_composition_eval(self.statement);
        let [mut col] = evaluation_accumulator.columns([(self.statement.log_size + 1, 1)]);
        let domain_size = 1usize << (self.statement.log_size + 1);
        for i in 0..domain_size {
            col.accumulate(i, composition_eval);
        }
    }
}
