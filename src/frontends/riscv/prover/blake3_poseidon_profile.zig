//! Guest Poseidon-specific adapters for the shared full-width extension pipeline.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Column = engine.pcs.ColumnEvaluation;
const guest_main = @import("../air/guest_precompile/main_trace.zig");
const guest_interaction = @import("../air/guest_precompile/interaction.zig");
pub const admission = @import("blake3_poseidon_statement.zig");
pub const protocol = @import("blake3_poseidon_protocol.zig");
pub const Witness = @import("blake3_poseidon_witness.zig").Owner;
pub const ExtensionClaim = @import("blake3_poseidon_claims.zig").ExtensionClaim;
pub const Relations = @import("../air/guest_precompile/relation_challenges.zig").Poseidon2V1Relations;
const assembly = @import("guest_precompile/component_assembly.zig");
pub const PlacementDescriptor = assembly.PlacementDescriptor;
pub const ClaimWire = @import("blake3_poseidon_claims.zig");
pub const draw_count = 2;
pub const component_count = 2;
pub const receipt_domain = 0x42335052;
pub const artifact_magic = "B3P2ART1";
pub fn Assembly(comptime mode: enum { prover, verifier }) type {
    return if (mode == .prover) assembly.ProverAssembly else assembly.VerifierAssembly;
}
pub fn externalCount(statement: *const admission.Statement) u32 {
    return statement.counts.n_guest;
}
/// Owned by the preparation arena, derived solely from admitted descriptors.
pub fn preprocessed(a: std.mem.Allocator, statement: *const admission.Statement) ![]Column {
    try statement.validateGeometry();
    var columns: std.ArrayList(Column) = .empty;
    const opcode = @import("opcode_trace.zig");
    for (statement.components) |descriptor| {
        try columns.append(a, .{ .log_size = descriptor.log_size, .values = try opcode.generateIsFirst(a, descriptor.log_size) });
        try columns.append(a, .{ .log_size = descriptor.log_size, .values = try opcode.generateIsActive(a, descriptor.log_size, descriptor.n_rows) });
    }
    return columns.toOwnedSlice(a);
}
pub const Main = struct {
    columns: []Column,
    pub fn deinit(self: *Main, a: std.mem.Allocator) void {
        a.free(self.columns);
        self.* = undefined;
    }
};
/// Only descriptors are allocated: values already occupy their final layout.
pub fn main(a: std.mem.Allocator, source: *const guest_main.Result) !Main {
    const columns = try a.alloc(Column, guest_main.main_column_count);
    for (columns[0..guest_main.caller_main_column_count], 0..) |*column, i| column.* = .{ .log_size = source.log_size, .values = source.callerMain(i) };
    for (columns[guest_main.caller_main_column_count..], 0..) |*column, i| column.* = .{ .log_size = source.log_size, .values = source.providerMain(i) };
    return .{ .columns = columns };
}
pub const Interaction = struct {
    storage: guest_interaction.Result,
    columns: []Column,
    claim: ExtensionClaim,
    pub fn deinit(self: *Interaction, a: std.mem.Allocator) void {
        a.free(self.columns);
        self.storage.deinit();
        self.* = undefined;
    }
};
pub fn interactions(a: std.mem.Allocator, owner: *Witness, relations: *const Relations, _: *engine.work_pool.WorkPool) !Interaction {
    var storage = try guest_interaction.generateBlake3(a, &owner.native.statement, try owner.admission(), owner.hashes.logs, &owner.statement, &owner.extension, relations);
    errdefer storage.deinit();
    const claim = try ExtensionClaim.canonical(&owner.statement, storage.caller_claims, storage.provider_claims);
    const columns = try a.alloc(Column, guest_interaction.total_column_count);
    for (columns[0..guest_interaction.caller_column_count], 0..) |*column, i| column.* = .{ .log_size = storage.log_size, .values = storage.callerColumn(i) };
    for (columns[guest_interaction.caller_column_count..], 0..) |*column, i| column.* = .{ .log_size = storage.log_size, .values = storage.providerColumn(i) };
    return .{ .storage = storage, .columns = columns, .claim = claim };
}

pub const ExtensionWire = @import("guest_precompile/proof_artifact_wire.zig");
pub const manifest_magic = "B3P2ADM1";
pub fn validateGeometry(statement: *const admission.Statement, steps: u32) !void {
    try statement.validateGeometry();
    if (statement.counts.n_guest > steps) return error.CallCountMismatch;
}

pub const execution_profile: @import("../isa/execution_profile.zig").ExecutionProfile = .rv32im_zkvm_poseidon2_v1;
