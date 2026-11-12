//! Proof-facing primitives admitted only by guest-precompile profiles.

pub const relation_registry = @import("stwo_riscv_precompiles").air.relation_registry;
pub const relation_challenges = @import("stwo_riscv_precompiles").air.relation_challenges;
pub const relation_event = @import("stwo_riscv_precompiles").air.relation_event;
pub const component_registry = @import("stwo_riscv_rv32").air.guest_precompile.component_registry;
pub const manifest = @import("stwo_riscv_rv32").air.guest_precompile.manifest;
pub const statement = @import("stwo_riscv_rv32").air.guest_precompile.statement;
pub const main_trace = @import("stwo_riscv_rv32").air.guest_precompile.main_trace;
pub const direct_constraints = @import("stwo_riscv_rv32").air.guest_precompile.direct_constraints;
pub const interaction = @import("stwo_riscv_rv32").air.guest_precompile.interaction;
pub const caller_component = @import("stwo_riscv_rv32").air.guest_precompile.caller_component;
pub const provider_component = @import("stwo_riscv_rv32").air.guest_precompile.provider_component;
pub const lookup_registration = @import("stwo_riscv_rv32").air.guest_precompile.lookup_registration;
pub const proof_transcript = @import("stwo_riscv_rv32").air.guest_precompile.proof_transcript;
pub const proof_admission = @import("stwo_riscv_rv32").air.guest_precompile.proof_admission;
pub const program_commitment = @import("stwo_riscv_rv32").air.guest_precompile.program_commitment;
pub const artifact_identity = @import("stwo_riscv_rv32").air.guest_precompile.artifact_identity;
pub const ethereum_statement = @import("../../../../air/guest_precompile/ethereum_statement.zig");

/// Candidate Keccak-f profile authority. These modules are proof-complete but
/// remain outside the production profile switch until the caller relation and
/// guest ABI are activated together.
pub const keccakf_authority = @import("stwo_riscv_precompiles").air.keccakf_authority;
pub const keccakf_caller = @import("stwo_riscv_rv32").air.guest_precompile.keccakf_caller;
pub const keccakf_component = @import("stwo_riscv_rv32").air.guest_precompile.keccakf_component;
pub const keccakf_interaction = @import("stwo_riscv_rv32").air.guest_precompile.keccakf_interaction;
pub const keccakf_multiplicities = @import("stwo_riscv_precompiles").air.keccakf_multiplicities;
pub const keccakf_relations = @import("stwo_riscv_precompiles").air.keccakf_relations;
pub const keccakf_table_component = @import("stwo_riscv_precompiles").air.keccakf_table_component;
pub const keccakf_table_interaction = @import("stwo_riscv_precompiles").air.keccakf_table_interaction;
pub const keccakf_tables = @import("stwo_riscv_precompiles").air.keccakf_tables;
pub const keccakf_trace = @import("stwo_riscv_rv32").air.guest_precompile.keccakf_trace;

pub const secp256k1_affine = @import("stwo_riscv_precompiles").air.secp256k1_affine;
pub const secp256k1_ecdsa = @import("stwo_riscv_precompiles").air.secp256k1_ecdsa;
pub const secp256k1_relations = @import("stwo_riscv_precompiles").air.secp256k1_relations;
pub const secp256k1_component = @import("stwo_riscv_precompiles").air.secp256k1_component;
pub const secp256k1_component_bundle = @import("stwo_riscv_rv32").air.guest_precompile.secp256k1_component_bundle;
pub const secp256k1_component_config = @import("stwo_riscv_rv32").air.guest_precompile.secp256k1_component_config;
pub const secp256k1_component_interaction = @import("stwo_riscv_precompiles").air.secp256k1_component_interaction;
pub const secp256k1_component_trace = @import("stwo_riscv_precompiles").air.secp256k1_component_trace;
