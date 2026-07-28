//! Stable JSON wire types for the Sail-authoritative RV32IM proof artifact.

pub const SCHEMA_VERSION: u32 = 4;
pub const ARTIFACT_KIND = "stwo_riscv_proof";
pub const EXCHANGE_MODE = "riscv_proof_json_wire_v4";
pub const LEGACY_EXCHANGE_MODE_V1 = "riscv_proof_json_wire_v1";
pub const LEGACY_EXCHANGE_MODE_V2 = "riscv_proof_json_wire_v2";
pub const LEGACY_EXCHANGE_MODE_V3 = "riscv_proof_json_wire_v3";
pub const EXCHANGE_MODE_PREFIX = "riscv_proof_json_wire_v";

pub const GENERATOR = "zig";
pub const AIR = "sail_rv32im_zkvm_v1";
pub const ORACLE_REPOSITORY = "https://github.com/riscv/sail-riscv";
pub const ORACLE_COMMIT = "8c7f2da58de0ba5e4457e4de07e0046f0439f35f";
pub const IMPLEMENTATION_REPOSITORY = "https://github.com/teddyjfpender/stwo-zig";

pub const MAX_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_IO_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_COMPONENTS: usize = 256;
pub const MAX_INFRA_COMPONENTS: usize = 512;
pub const MAX_TOTAL_STEPS: u32 = 10_000_000;
pub const MAX_DOMAIN_LOG_SIZE: u32 = 30;
pub const MAX_COMMITTED_CELLS: u64 = 1 << 32;
pub const ACCESS_CLOCK_STRIDE: u32 = 4;
pub const MAX_ACCESSES_PER_INSTRUCTION: u32 = 3;

pub fn maximumAccessClock(instruction_count: u32) u64 {
    if (instruction_count == 0) return 0;
    return (@as(u64, instruction_count) - 1) * ACCESS_CLOCK_STRIDE +
        MAX_ACCESSES_PER_INSTRUCTION;
}

pub fn isCanonicalAccessClock(clock: u32) bool {
    if (clock == 0) return false;
    return ((clock - 1) % ACCESS_CLOCK_STRIDE) < MAX_ACCESSES_PER_INSTRUCTION;
}

pub fn isAccessClockWithinExecution(
    clock: u32,
    instruction_count: u32,
    allow_zero: bool,
) bool {
    if (clock == 0) return allow_zero;
    return isCanonicalAccessClock(clock) and
        @as(u64, clock) <= maximumAccessClock(instruction_count);
}

pub const Qm31Wire = [4]u32;

pub const SecurityPolicy = enum { secure, functional, smoke };

pub const FriConfigWire = struct {
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: u64,
    fold_step: u32 = 1,
};

pub const PcsConfigWire = struct {
    pow_bits: u32,
    fri_config: FriConfigWire,
    lifting_log_size: ?u32 = null,
};

pub const SourceWire = struct {
    elf_sha256: []const u8,
    input_sha256: []const u8,
};

pub const ProvenanceWire = struct {
    oracle_repository: []const u8,
    oracle_commit: []const u8,
    implementation_repository: []const u8,
    implementation_commit: []const u8,
    implementation_dirty: bool,
    witness_layout_sha256: []const u8,
};

pub const OutputWordWire = struct {
    addr: u32,
    value: u32,
    clock: u32,
};

pub const CompletionKindWire = enum {
    halt_flag,
    unretired_self_loop,
};

pub const CompletionWire = struct {
    kind: CompletionKindWire,
    address: u32,
    value: u32,
    clock: u32,
};

pub const PublicDataWire = struct {
    initial_pc: u32,
    final_pc: u32,
    clock: u32,
    initial_regs: [32]u32,
    final_regs: [32]u32,
    reg_last_clock: [32]u32,
    program_root: ?u32,
    initial_rw_root: ?u32,
    final_rw_root: ?u32,
    completion: CompletionWire,
    input_start: u32,
    input_len: u32,
    input_words: []const u32,
    output_len: u32,
    output_len_addr: u32,
    output_data_addr: u32,
    output_words: []const OutputWordWire,
};

/// Exact identity and geometry of one opcode-family shard.
pub const ComponentWire = struct {
    index: u32,
    family: u8,
    family_shard_index: u32,
    family_shard_count: u32,
    row_offset: u32,
    log_size: u32,
    n_rows: u32,
    n_columns: u32,
    interaction_batch_count: u32,
};

/// Exact identity and claim width of one infrastructure component.
pub const InfraComponentWire = struct {
    index: u32,
    kind: u32,
    log_size: u32,
    n_rows: u32,
    n_columns: u32,
    claim_count: u32,
};

pub const StatementWire = struct {
    segment_ordinal: u32,
    segment_count: u32,
    initial_pc: u32,
    final_pc: u32,
    total_steps: u32,
    components: []const ComponentWire,
    infrastructure: []const InfraComponentWire,
    public_data: PublicDataWire,
};

pub const OpcodeClaimWire = struct {
    component_index: u32,
    claimed_sums: []const Qm31Wire,
};

pub const InfraClaimWire = struct {
    infrastructure_index: u32,
    claimed_sums: []const Qm31Wire,
};

pub const InteractionClaimWire = struct {
    interaction_pow: u64,
    opcode_claims: []const OpcodeClaimWire,
    infrastructure_claims: []const InfraClaimWire,
};

/// JSON envelope for Sail-profile RISC-V CPU proofs.
/// `proof_bytes_hex` is the canonical Stwo proof wire encoded as lowercase hex.
pub const Artifact = struct {
    artifact_kind: []const u8,
    schema_version: u32,
    exchange_mode: []const u8,
    release_status: []const u8,
    generator: []const u8,
    air: []const u8,
    backend: []const u8,
    protocol: []const u8,
    source: SourceWire,
    provenance: ProvenanceWire,
    pcs_config: PcsConfigWire,
    statement: StatementWire,
    interaction_claim: InteractionClaimWire,
    proof_bytes_hex: []const u8,
};
