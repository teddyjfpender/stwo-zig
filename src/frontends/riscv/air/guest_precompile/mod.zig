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
