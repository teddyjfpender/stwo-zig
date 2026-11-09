//! Proof-facing primitives admitted only by guest-precompile profiles.

pub const relation_registry = @import("relation_registry.zig");
pub const relation_challenges = @import("relation_challenges.zig");
pub const relation_event = @import("relation_event.zig");
pub const component_registry = @import("stwo_riscv_rv32").air_guest_precompile_component_registry;
pub const manifest = @import("stwo_riscv_rv32").air_guest_precompile_manifest;
pub const statement = @import("stwo_riscv_rv32").air_guest_precompile_statement;
pub const main_trace = @import("stwo_riscv_rv32").air_guest_precompile_main_trace;
pub const direct_constraints = @import("stwo_riscv_rv32").air_guest_precompile_direct_constraints;
pub const interaction = @import("stwo_riscv_rv32").air_guest_precompile_interaction;
pub const caller_component = @import("stwo_riscv_rv32").air_guest_precompile_caller_component;
pub const provider_component = @import("stwo_riscv_rv32").air_guest_precompile_provider_component;
pub const lookup_registration = @import("stwo_riscv_rv32").air_guest_precompile_lookup_registration;
pub const proof_transcript = @import("stwo_riscv_rv32").air_guest_precompile_proof_transcript;
pub const proof_admission = @import("stwo_riscv_rv32").air_guest_precompile_proof_admission;
pub const program_commitment = @import("stwo_riscv_rv32").air_guest_precompile_program_commitment;
pub const artifact_identity = @import("stwo_riscv_rv32").air_guest_precompile_artifact_identity;
pub const ethereum_statement = @import("stwo_riscv_frontend").modules.air_guest_precompile_ethereum_statement;

/// Candidate Keccak-f profile authority. These modules are proof-complete but
/// remain outside the production profile switch until the caller relation and
/// guest ABI are activated together.
pub const keccakf_authority = @import("keccakf_authority.zig");
pub const keccakf_caller = @import("stwo_riscv_rv32").air_guest_precompile_keccakf_caller;
pub const keccakf_component = @import("stwo_riscv_rv32").air_guest_precompile_keccakf_component;
pub const keccakf_interaction = @import("stwo_riscv_rv32").air_guest_precompile_keccakf_interaction;
pub const keccakf_multiplicities = @import("keccakf_multiplicities.zig");
pub const keccakf_relations = @import("keccakf_relations.zig");
pub const keccakf_table_component = @import("keccakf_table_component.zig");
pub const keccakf_table_interaction = @import("keccakf_table_interaction.zig");
pub const keccakf_tables = @import("keccakf_tables.zig");
pub const keccakf_trace = @import("stwo_riscv_rv32").air_guest_precompile_keccakf_trace;

pub const secp256k1_affine = @import("secp256k1_affine.zig");
pub const secp256k1_ecdsa = @import("secp256k1_ecdsa.zig");
pub const secp256k1_relations = @import("secp256k1_relations.zig");
pub const secp256k1_component = @import("secp256k1_component.zig");
pub const secp256k1_component_bundle = @import("stwo_riscv_rv32").air_guest_precompile_secp256k1_component_bundle;
pub const secp256k1_component_config = @import("stwo_riscv_rv32").air_guest_precompile_secp256k1_component_config;
pub const secp256k1_component_interaction = @import("secp256k1_component_interaction.zig");
pub const secp256k1_component_trace = @import("secp256k1_component_trace.zig");
