//! Ethereum-specific adapters for the shared full-width extension pipeline.
const std = @import("std");
pub const admission = @import("blake3_ethereum_statement.zig");
pub const protocol = @import("blake3_ethereum_protocol.zig");
pub const Witness = @import("blake3_ethereum_witness.zig").Owner;
pub const ExtensionClaim = @import("guest_precompile/ethereum_types.zig").ExtensionClaim;
pub const Relations = @import("guest_precompile/ethereum_transcript.zig").Relations;
pub const Assembly = @import("guest_precompile/ethereum_assembly.zig").Assembly;
pub const PlacementDescriptor = @import("guest_precompile/ethereum_assembly.zig").PlacementDescriptor;
pub const ClaimWire = @import("guest_precompile/ethereum_proof_artifact_wire.zig");
pub const draw_count = 26;
pub const component_count = 14;
pub const receipt_domain = 0x42334852;
pub const artifact_magic = "B3EHART1";
pub const preprocessed = @import("guest_precompile/ethereum_preprocessed.zig").generateExtension;
pub const main = @import("guest_precompile/ethereum_main_columns.zig").generate;
pub fn externalCount(statement: *const admission.Statement) u32 {
    return statement.counts.external_retirements;
}
pub fn interactions(a: std.mem.Allocator, owner: *Witness, relations: *const Relations, pool: *@import("stwo_prover_engine").work_pool.WorkPool) !@import("guest_precompile/ethereum_interaction.zig").Generated {
    return @import("guest_precompile/ethereum_interaction.zig").generate(a, &owner.extension, relations, pool);
}

pub const ExtensionWire = @import("guest_precompile/ethereum_proof_artifact_wire.zig");
pub const manifest_magic = "B3EHADM1";
pub fn validateGeometry(statement: *const admission.Statement, steps: u32) !void {
    try statement.validateGeometry(steps);
}

pub const execution_profile: @import("../isa/execution_profile.zig").ExecutionProfile = .rv32im_zkvm_ethereum_v1;
