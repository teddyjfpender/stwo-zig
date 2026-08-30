//! Proof-facing primitives admitted only by guest-precompile profiles.

pub const relation_registry = @import("relation_registry.zig");
pub const relation_challenges = @import("relation_challenges.zig");
pub const relation_event = @import("relation_event.zig");
pub const component_registry = @import("component_registry.zig");
pub const manifest = @import("manifest.zig");
pub const statement = @import("statement.zig");
pub const main_trace = @import("main_trace.zig");
pub const direct_constraints = @import("direct_constraints.zig");
pub const interaction = @import("interaction.zig");
pub const caller_component = @import("caller_component.zig");
pub const provider_component = @import("provider_component.zig");
pub const lookup_registration = @import("lookup_registration.zig");
pub const proof_transcript = @import("proof_transcript.zig");
pub const proof_admission = @import("proof_admission.zig");
pub const program_commitment = @import("program_commitment.zig");
pub const artifact_identity = @import("artifact_identity.zig");
pub const production_adapter = @import("production_adapter.zig");

/// Candidate Keccak-f profile authority. These modules are proof-complete but
/// remain outside the production profile switch until the caller relation and
/// guest ABI are activated together.
pub const keccakf_authority = @import("keccakf_authority.zig");
pub const keccakf_caller = @import("keccakf_caller.zig");
pub const keccakf_component = @import("keccakf_component.zig");
pub const keccakf_interaction = @import("keccakf_interaction.zig");
pub const keccakf_multiplicities = @import("keccakf_multiplicities.zig");
pub const keccakf_relations = @import("keccakf_relations.zig");
pub const keccakf_table_component = @import("keccakf_table_component.zig");
pub const keccakf_table_interaction = @import("keccakf_table_interaction.zig");
pub const keccakf_tables = @import("keccakf_tables.zig");
pub const keccakf_trace = @import("keccakf_trace.zig");

/// Backend-neutral non-native secp256k1 arithmetic authority.  Point and
/// caller components compose this primitive rather than reimplementing wide
/// integer arithmetic per backend.
pub const secp256k1_field = @import("secp256k1_field.zig");
pub const secp256k1_mul_direct = @import("secp256k1_mul_direct.zig");
pub const secp256k1_linear_direct = @import("secp256k1_linear_direct.zig");
pub const secp256k1_affine = @import("secp256k1_affine.zig");
pub const secp256k1_ecdsa = @import("secp256k1_ecdsa.zig");
pub const secp256k1_ecdsa_direct = @import("secp256k1_ecdsa_direct.zig");
pub const secp256k1_relations = @import("secp256k1_relations.zig");
pub const secp256k1_point_direct = @import("secp256k1_point_direct.zig");
pub const secp256k1_split_direct = @import("secp256k1_split_direct.zig");
pub const secp256k1_scalar_direct = @import("secp256k1_scalar_direct.zig");
pub const secp256k1_table_direct = @import("secp256k1_table_direct.zig");
pub const secp256k1_component = @import("secp256k1_component.zig");
pub const secp256k1_component_bundle = @import("secp256k1_component_bundle.zig");
pub const secp256k1_component_config = @import("secp256k1_component_config.zig");
pub const secp256k1_component_interaction = @import("secp256k1_component_interaction.zig");
pub const secp256k1_component_trace = @import("secp256k1_component_trace.zig");
