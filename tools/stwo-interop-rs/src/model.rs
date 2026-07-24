use serde::{Deserialize, Serialize};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;

pub(crate) const SCHEMA_VERSION: u32 = 1;
pub(crate) const EXCHANGE_MODE: &str = "proof_exchange_json_wire_v1";
pub(crate) const POSEIDON_LOG_INSTANCES_PER_ROW: u32 = 3;
pub(crate) const POSEIDON_INSTANCES_PER_ROW: usize = 1 << POSEIDON_LOG_INSTANCES_PER_ROW;
pub(crate) const POSEIDON_STATE: usize = 16;
pub(crate) const POSEIDON_PARTIAL_ROUNDS: usize = 14;
pub(crate) const POSEIDON_HALF_FULL_ROUNDS: usize = 4;
pub(crate) const POSEIDON_FULL_ROUNDS: usize = POSEIDON_HALF_FULL_ROUNDS * 2;
pub(crate) const POSEIDON_COLUMNS_PER_REP: usize =
    POSEIDON_STATE * (1 + POSEIDON_FULL_ROUNDS) + POSEIDON_PARTIAL_ROUNDS;
pub(crate) const POSEIDON_COLUMNS: usize = POSEIDON_COLUMNS_PER_REP * POSEIDON_INSTANCES_PER_ROW;
pub(crate) const BLAKE_STATE: usize = 16;
pub(crate) const BLAKE_MESSAGE_WORDS: usize = 16;
pub(crate) const BLAKE_FELTS_IN_U32: usize = 2;
pub(crate) const BLAKE_ROUND_INPUT_FELTS: usize =
    (BLAKE_STATE + BLAKE_STATE + BLAKE_MESSAGE_WORDS) * BLAKE_FELTS_IN_U32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Generate,
    Verify,
    Bench,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Example {
    Blake,
    Plonk,
    Poseidon,
    StateMachine,
    WideFibonacci,
    Xor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProveMode {
    Prove,
    ProveEx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProverBackend {
    Scalar,
    Simd,
}

impl ProverBackend {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Scalar => "cpu-scalar",
            Self::Simd => "simd",
        }
    }

    pub(crate) const fn rust_type(self) -> &'static str {
        match self {
            Self::Scalar => "stwo::prover::backend::cpu::CpuBackend",
            Self::Simd => "stwo::prover::backend::simd::SimdBackend",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Cli {
    pub(crate) mode: Mode,
    pub(crate) example: Option<Example>,
    pub(crate) artifact: String,
    pub(crate) stage_profile_out: Option<String>,
    pub(crate) prove_mode: ProveMode,
    pub(crate) include_all_preprocessed_columns: bool,
    pub(crate) backend: ProverBackend,

    pub(crate) pow_bits: u32,
    pub(crate) fri_log_blowup: u32,
    pub(crate) fri_log_last_layer: u32,
    pub(crate) fri_n_queries: usize,

    pub(crate) sm_log_n_rows: u32,
    pub(crate) sm_initial_0: u32,
    pub(crate) sm_initial_1: u32,

    pub(crate) blake_log_n_rows: u32,
    pub(crate) blake_n_rounds: u32,

    pub(crate) plonk_log_n_rows: u32,

    pub(crate) poseidon_log_n_instances: u32,

    pub(crate) wf_log_n_rows: u32,
    pub(crate) wf_sequence_len: u32,

    pub(crate) xor_log_size: u32,
    pub(crate) xor_log_step: u32,
    pub(crate) xor_offset: usize,

    pub(crate) bench_warmups: usize,
    pub(crate) bench_repeats: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FriConfigWire {
    pub(crate) log_blowup_factor: u32,
    pub(crate) log_last_layer_degree_bound: u32,
    pub(crate) n_queries: u64,
    #[serde(default = "default_fold_step")]
    pub(crate) fold_step: u32,
}

fn default_fold_step() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PcsConfigWire {
    pub(crate) pow_bits: u32,
    pub(crate) fri_config: FriConfigWire,
    #[serde(default)]
    pub(crate) lifting_log_size: Option<u32>,
}

pub(crate) type HashWire = [u8; 32];
pub(crate) type Qm31Wire = [u32; 4];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MerkleDecommitmentWire {
    pub(crate) hash_witness: Vec<HashWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FriLayerWire {
    pub(crate) fri_witness: Vec<Qm31Wire>,
    pub(crate) decommitment: MerkleDecommitmentWire,
    pub(crate) commitment: HashWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FriProofWire {
    pub(crate) first_layer: FriLayerWire,
    pub(crate) inner_layers: Vec<FriLayerWire>,
    pub(crate) last_layer_poly: Vec<Qm31Wire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProofWire {
    pub(crate) config: PcsConfigWire,
    pub(crate) commitments: Vec<HashWire>,
    pub(crate) sampled_values: Vec<Vec<Vec<Qm31Wire>>>,
    pub(crate) decommitments: Vec<MerkleDecommitmentWire>,
    pub(crate) queried_values: Vec<Vec<Vec<u32>>>,
    pub(crate) proof_of_work: u64,
    pub(crate) fri_proof: FriProofWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StateMachineStatementWire {
    pub(crate) public_input: [[u32; 2]; 2],
    pub(crate) stmt0: StateMachineStmt0Wire,
    pub(crate) stmt1: StateMachineStmt1Wire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StateMachineStmt0Wire {
    pub(crate) n: u32,
    pub(crate) m: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StateMachineStmt1Wire {
    pub(crate) x_axis_claimed_sum: Qm31Wire,
    pub(crate) y_axis_claimed_sum: Qm31Wire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct XorStatementWire {
    pub(crate) log_size: u32,
    pub(crate) log_step: u32,
    pub(crate) offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PlonkStatementWire {
    pub(crate) log_n_rows: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PlonkLogupStatementWire {
    pub(crate) log_n_rows: u32,
    pub(crate) claimed_sum: Qm31Wire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PoseidonStatementWire {
    pub(crate) log_n_instances: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BlakeStatementWire {
    pub(crate) log_n_rows: u32,
    pub(crate) n_rounds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WideFibonacciStatementWire {
    pub(crate) log_n_rows: u32,
    pub(crate) sequence_len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct InteropArtifact {
    pub(crate) schema_version: u32,
    pub(crate) upstream_commit: String,
    pub(crate) exchange_mode: String,
    pub(crate) generator: String,
    pub(crate) example: String,
    pub(crate) prove_mode: Option<String>,
    pub(crate) pcs_config: PcsConfigWire,
    pub(crate) blake_statement: Option<BlakeStatementWire>,
    pub(crate) plonk_statement: Option<PlonkStatementWire>,
    #[serde(default)]
    pub(crate) plonk_logup_statement: Option<PlonkLogupStatementWire>,
    pub(crate) poseidon_statement: Option<PoseidonStatementWire>,
    pub(crate) state_machine_statement: Option<StateMachineStatementWire>,
    pub(crate) wide_fibonacci_statement: Option<WideFibonacciStatementWire>,
    pub(crate) xor_statement: Option<XorStatementWire>,
    pub(crate) proof_bytes_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BenchTiming {
    pub(crate) warmups: usize,
    pub(crate) repeats: usize,
    pub(crate) samples_seconds: Vec<f64>,
    pub(crate) min_seconds: f64,
    pub(crate) max_seconds: f64,
    pub(crate) avg_seconds: f64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BenchProofMetrics {
    pub(crate) proof_wire_bytes: usize,
    pub(crate) commitments_count: usize,
    pub(crate) decommitments_count: usize,
    pub(crate) trace_decommit_hashes: usize,
    pub(crate) fri_inner_layers_count: usize,
    pub(crate) fri_first_layer_witness_len: usize,
    pub(crate) fri_last_layer_poly_len: usize,
    pub(crate) fri_decommit_hashes_total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BenchReport {
    pub(crate) runtime: String,
    pub(crate) backend: String,
    pub(crate) backend_type: String,
    pub(crate) example: String,
    pub(crate) prove_mode: String,
    pub(crate) include_all_preprocessed_columns: bool,
    pub(crate) prove: BenchTiming,
    pub(crate) verify: BenchTiming,
    pub(crate) proof_metrics: BenchProofMetrics,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StageNode {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) seconds: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) children: Option<Vec<StageNode>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StageProfile {
    pub(crate) schema_version: u32,
    pub(crate) runtime: String,
    pub(crate) example: String,
    pub(crate) stages: Vec<StageNode>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ExampleStatement {
    Blake(BlakeStatement),
    Plonk(PlonkStatement),
    Poseidon(PoseidonStatement),
    StateMachine(StateMachineStatement),
    WideFibonacci(WideFibonacciStatement),
    Xor(XorStatement),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StateMachineElements {
    pub(crate) z: SecureField,
    pub(crate) alpha: SecureField,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StateMachineStatement {
    pub(crate) public_input: [[M31; 2]; 2],
    pub(crate) stmt0_n: u32,
    pub(crate) stmt0_m: u32,
    pub(crate) stmt1_x_axis_claimed_sum: SecureField,
    pub(crate) stmt1_y_axis_claimed_sum: SecureField,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct XorStatement {
    pub(crate) log_size: u32,
    pub(crate) log_step: u32,
    pub(crate) offset: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WideFibonacciStatement {
    pub(crate) log_n_rows: u32,
    pub(crate) sequence_len: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PlonkStatement {
    pub(crate) log_n_rows: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PoseidonStatement {
    pub(crate) log_n_instances: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct BlakeStatement {
    pub(crate) log_n_rows: u32,
    pub(crate) n_rounds: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StateMachineComponent {
    pub(crate) trace_log_size: u32,
    pub(crate) composition_eval: SecureField,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct XorComponent {
    pub(crate) statement: XorStatement,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WideFibonacciComponent {
    pub(crate) statement: WideFibonacciStatement,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PlonkComponent {
    pub(crate) statement: PlonkStatement,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PoseidonComponent {
    pub(crate) statement: PoseidonStatement,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct BlakeComponent {
    pub(crate) statement: BlakeStatement,
}
