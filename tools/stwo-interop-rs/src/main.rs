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
    prove, CommitmentSchemeProver, ComponentProver, DomainEvaluationAccumulator, Trace,
};

const SCHEMA_VERSION: u32 = 1;
const UPSTREAM_COMMIT: &str = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";
const EXCHANGE_MODE: &str = "proof_exchange_json_wire_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Generate,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Example {
    StateMachine,
    Xor,
}

#[derive(Debug, Clone)]
struct Cli {
    mode: Mode,
    example: Option<Example>,
    artifact: String,

    pow_bits: u32,
    fri_log_blowup: u32,
    fri_log_last_layer: u32,
    fri_n_queries: usize,

    sm_log_n_rows: u32,
    sm_initial_0: u32,
    sm_initial_1: u32,

    xor_log_size: u32,
    xor_log_step: u32,
    xor_offset: usize,
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
struct InteropArtifact {
    schema_version: u32,
    upstream_commit: String,
    exchange_mode: String,
    generator: String,
    example: String,
    pcs_config: PcsConfigWire,
    state_machine_statement: Option<StateMachineStatementWire>,
    xor_statement: Option<XorStatementWire>,
    proof_bytes_hex: String,
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
struct StateMachineComponent {
    trace_log_size: u32,
    composition_eval: SecureField,
}

#[derive(Debug, Clone, Copy)]
struct XorComponent {
    statement: XorStatement,
}

fn main() -> Result<()> {
    let cli = parse_cli(env::args().collect())?;
    match cli.mode {
        Mode::Generate => run_generate(&cli),
        Mode::Verify => run_verify(&cli),
    }
}

fn run_generate(cli: &Cli) -> Result<()> {
    let example = cli
        .example
        .ok_or_else(|| anyhow!("--example is required for generate mode"))?;
    let config = pcs_config_from_cli(cli)?;

    let artifact = match example {
        Example::StateMachine => {
            let initial_state = [
                checked_m31(cli.sm_initial_0)?,
                checked_m31(cli.sm_initial_1)?,
            ];
            let (statement, proof) = state_machine_prove(config, cli.sm_log_n_rows, initial_state)?;
            let proof_bytes = serde_json::to_vec(&proof_to_wire(&proof)?)?;
            InteropArtifact {
                schema_version: SCHEMA_VERSION,
                upstream_commit: UPSTREAM_COMMIT.to_string(),
                exchange_mode: EXCHANGE_MODE.to_string(),
                generator: "rust".to_string(),
                example: "state_machine".to_string(),
                pcs_config: pcs_config_to_wire(config),
                state_machine_statement: Some(state_machine_statement_to_wire(statement)),
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
            let (statement, proof) = xor_prove(config, statement)?;
            let proof_bytes = serde_json::to_vec(&proof_to_wire(&proof)?)?;
            InteropArtifact {
                schema_version: SCHEMA_VERSION,
                upstream_commit: UPSTREAM_COMMIT.to_string(),
                exchange_mode: EXCHANGE_MODE.to_string(),
                generator: "rust".to_string(),
                example: "xor".to_string(),
                pcs_config: pcs_config_to_wire(config),
                state_machine_statement: None,
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

    let config = pcs_config_from_wire(&artifact.pcs_config)?;
    let proof_bytes = hex::decode(&artifact.proof_bytes_hex)?;
    let proof_wire: ProofWire = serde_json::from_slice(&proof_bytes)?;
    let proof = wire_to_proof(proof_wire)?;

    match artifact.example.as_str() {
        "state_machine" => {
            let statement_wire = artifact
                .state_machine_statement
                .as_ref()
                .ok_or_else(|| anyhow!("missing state_machine_statement"))?;
            let statement = state_machine_statement_from_wire(statement_wire)?;
            state_machine_verify(config, statement, proof)?;
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

fn parse_cli(args: Vec<String>) -> Result<Cli> {
    let mut mode: Option<Mode> = None;
    let mut example: Option<Example> = None;
    let mut artifact: Option<String> = None;

    let mut pow_bits = 0u32;
    let mut fri_log_blowup = 1u32;
    let mut fri_log_last_layer = 0u32;
    let mut fri_n_queries = 3usize;

    let mut sm_log_n_rows = 5u32;
    let mut sm_initial_0 = 9u32;
    let mut sm_initial_1 = 3u32;

    let mut xor_log_size = 5u32;
    let mut xor_log_step = 2u32;
    let mut xor_offset = 3usize;

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
                    _ => bail!("invalid mode {value}"),
                }
            }
            "--example" => {
                example = match value.as_str() {
                    "state_machine" => Some(Example::StateMachine),
                    "xor" => Some(Example::Xor),
                    _ => bail!("invalid example {value}"),
                }
            }
            "--artifact" => artifact = Some(value.clone()),
            "--pow-bits" => pow_bits = value.parse()?,
            "--fri-log-blowup" => fri_log_blowup = value.parse()?,
            "--fri-log-last-layer" => fri_log_last_layer = value.parse()?,
            "--fri-n-queries" => fri_n_queries = value.parse()?,
            "--sm-log-n-rows" => sm_log_n_rows = value.parse()?,
            "--sm-initial-0" => sm_initial_0 = value.parse()?,
            "--sm-initial-1" => sm_initial_1 = value.parse()?,
            "--xor-log-size" => xor_log_size = value.parse()?,
            "--xor-log-step" => xor_log_step = value.parse()?,
            "--xor-offset" => xor_offset = value.parse()?,
            _ => bail!("unknown flag {flag}"),
        }
    }

    Ok(Cli {
        mode: mode.ok_or_else(|| anyhow!("--mode is required"))?,
        example,
        artifact: artifact.ok_or_else(|| anyhow!("--artifact is required"))?,
        pow_bits,
        fri_log_blowup,
        fri_log_last_layer,
        fri_n_queries,
        sm_log_n_rows,
        sm_initial_0,
        sm_initial_1,
        xor_log_size,
        xor_log_step,
        xor_offset,
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

fn state_machine_prove(
    config: PcsConfig,
    log_n_rows: u32,
    initial_state: [M31; 2],
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
    let proof = prove::<CpuBackend, Blake2sMerkleChannel>(&[&component], &mut channel, scheme)?;

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

fn xor_prove(
    config: PcsConfig,
    statement: XorStatement,
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
    let proof = prove::<CpuBackend, Blake2sMerkleChannel>(&[&component], &mut channel, scheme)?;

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
