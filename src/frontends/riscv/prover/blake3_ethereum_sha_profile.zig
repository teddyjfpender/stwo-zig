//! Ethereum/SHA specialization of the shared typed extension pipeline.
const std = @import("std");
pub const admission = @import("blake3_ethereum_sha_statement.zig");
pub const protocol = @import("blake3_ethereum_sha_protocol.zig");
pub const Witness = @import("blake3_ethereum_witness.zig").ShaOwner;
pub const ExtensionClaim = @import("guest_precompile/ethereum_sha_types.zig").ExtensionClaim;
pub const Relations = @import("guest_precompile/ethereum_sha_relations.zig").Relations;
pub const Assembly = @import("guest_precompile/ethereum_sha_assembly.zig").Assembly;
pub const PlacementDescriptor = @import("guest_precompile/ethereum_sha_assembly.zig").PlacementDescriptor;
pub const ClaimWire = @import("guest_precompile/ethereum_sha_claim_wire.zig");
pub const ExtensionWire = @import("guest_precompile/ethereum_sha_statement_wire.zig");
pub const draw_count = @import("guest_precompile/ethereum_sha_relations.zig").draw_count;
pub const component_count = @import("guest_precompile/ethereum_sha_types.zig").component_count;
pub const receipt_domain = 0x42335352;
pub const artifact_magic = "B3SHART1";
pub const manifest_magic = "B3SHADM1";
pub const preprocessed = @import("guest_precompile/ethereum_sha_columns.zig").preprocessed;
pub const mainWitness = @import("guest_precompile/ethereum_sha_columns.zig").main;
pub const interactions = @import("guest_precompile/ethereum_sha_columns.zig").interactions;
pub const execution_profile: @import("../isa/execution_profile.zig").ExecutionProfile = .rv32im_zkvm_ethereum_sha_v1;
pub fn externalCount(statement: *const admission.Statement) u32 {
    return statement.ethereum.counts.external_retirements +| statement.sha.call_count;
}
pub fn validateGeometry(statement: *const admission.Statement, steps: u32) !void {
    try @import("blake3_ethereum_statement.zig").validateExtensionGeometry(&statement.ethereum, steps);
    try statement.sha.validate(steps);
    if (try std.math.add(u32, statement.ethereum.counts.external_retirements, statement.sha.call_count) > steps) return error.InvalidExternalRetirementCount;
}
pub fn fixedBounds(statement: *const admission.Statement) @TypeOf(statement.ethereum.admission.extended_fixed_table_bounds) {
    return statement.ethereum.admission.extended_fixed_table_bounds;
}
pub const Descriptor = struct { log_size: u32, preprocessed_columns: u32, main_columns: u32, interaction_columns: u32 };
pub fn descriptors(statement: *const admission.Statement) [component_count]Descriptor {
    var result: [component_count]Descriptor = undefined;
    for (statement.ethereum.components, 0..) |desc, i| result[i] = .{ .log_size = desc.log_size, .preprocessed_columns = desc.preprocessed_columns, .main_columns = desc.main_columns, .interaction_columns = desc.interaction_columns };
    for (statement.sha.descriptors, 14..) |desc, i| result[i] = .{ .log_size = desc.log_size, .preprocessed_columns = desc.preprocessed_columns, .main_columns = desc.main_columns, .interaction_columns = desc.interaction_columns };
    return result;
}
