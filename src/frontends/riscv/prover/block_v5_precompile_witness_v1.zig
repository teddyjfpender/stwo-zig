//! Typed precompile witness without native columns or per-leaf hash custody.
const std = @import("std");
const core = @import("stwo_core");
const geometry = @import("../air/guest_precompile/ethereum_statement.zig");
const profile = @import("blake3_ethereum_sha_profile.zig");
const sha = @import("../air/guest_precompile/sha256_memory_rows.zig");
const tables = @import("../air/lookups/tables/schema.zig");
const protocol = @import("block_v5_precompile_protocol_v1.zig");
const Recipe = @import("block_v5_execution_recipe_v1.zig").Recipe;
pub const Witness = ForRecipe(protocol.execution_recipe);
pub fn ForRecipe(comptime recipe: Recipe) type {
    return struct {
        extension: @import("guest_precompile/ethereum_witness.zig").Witness,
        sha_rows: sha.RowsForRecipe(recipe == .local_zero_v1),
        statement: profile.admission.Statement,
        total_steps: u32,

        pub fn initSegment(a: std.mem.Allocator, segment: *const @import("../runner/mod.zig").EthereumShaSegmentResult) !@This() {
            if (segment.base.state_chain_tracker.x0_local_custody_version != recipe.nativeVersion()) return error.MixedV5ExecutionRecipe;
            const tapes = &segment.extension;
            const steps = std.math.cast(u32, segment.base.cycle_count) orelse return error.InvalidExecutionTrace;
            const keccak = tapes.keccakf_calls.records();
            const signer = tapes.signer_recovery_calls.records();
            const sha_calls = tapes.sha_calls.records();
            const external = try std.math.add(usize, try std.math.add(usize, keccak.len, signer.len), sha_calls.len);
            try segment.base.execution_trace.validateClockRange(0, steps, external);
            try disjoint(sha_calls, keccak);
            try disjoint(sha_calls, signer);
            var extension = try @import("guest_precompile/ethereum_witness.zig").Witness.initWithCircuitProfileV1(a, keccak, tapes.keccakf_execution_rows.rows(), signer, tapes.signer_recovery_execution_rows.rows(), steps, recipe.callerProfile());
            errdefer extension.deinit();
            var sha_rows = try sha.prepareForRecipe(recipe == .local_zero_v1, a, sha_calls, steps);
            errdefer sha_rows.deinit();
            const statement = try canonicalStatementForRecipe(recipe, a, @intCast(keccak.len), @intCast(signer.len), @intCast(sha_calls.len), extension.shapes());
            try recipe.requireCaller(&statement, steps);
            return .{ .extension = extension, .sha_rows = sha_rows, .statement = statement, .total_steps = steps };
        }
        pub fn deinit(self: *@This()) void {
            self.sha_rows.deinit();
            self.extension.deinit();
            self.* = undefined;
        }
    };
}
pub fn canonicalStatement(a: std.mem.Allocator, keccak: u32, signer: u32, sha_calls: u32, shapes: geometry.SecpShapes) !profile.admission.Statement {
    return canonicalStatementForRecipe(protocol.execution_recipe, a, keccak, signer, sha_calls, shapes);
}
pub fn canonicalStatementForRecipe(comptime recipe: Recipe, a: std.mem.Allocator, keccak: u32, signer: u32, sha_calls: u32, shapes: geometry.SecpShapes) !profile.admission.Statement {
    const admission = try standaloneAdmission(recipe, a, keccak, signer, sha_calls);
    return .{ .ethereum = try geometry.Statement.canonicalWithAdmissionForCircuitProfileV1(keccak, signer, shapes, admission, recipe.callerProfile()), .sha = try @import("../air/guest_precompile/sha256_component_profile.zig").Profile.canonicalForRecipe(sha_calls, recipe == .local_zero_v1) };
}
pub fn validateAdmission(a: std.mem.Allocator, statement: *const profile.admission.Statement) !void {
    return validateAdmissionForRecipe(protocol.execution_recipe, a, statement);
}
pub fn validateAdmissionForRecipe(recipe: Recipe, a: std.mem.Allocator, statement: *const profile.admission.Statement) !void {
    try recipe.requireCaller(statement, profile.externalCount(statement));
    const expected = try standaloneAdmission(recipe, a, statement.ethereum.counts.keccak_calls, statement.ethereum.counts.signer_calls, statement.sha.call_count);
    if (!std.meta.eql(expected, statement.ethereum.admission)) return error.InvalidBlockV5StandaloneAdmission;
}
fn standaloneAdmission(recipe: Recipe, a: std.mem.Allocator, keccak: u32, signer: u32, sha_calls: u32) !geometry.Admission {
    const Bounds = @import("../air/guest_precompile/sha256_coefficient_bounds.zig");
    const sha_bounds = if (recipe == .local_zero_v1) try Bounds.deriveForRecipe(true, a, sha_calls) else try Bounds.derive(a, sha_calls);
    var bounds: [geometry.fixed_table_count]u64 = sha_bounds.tables;
    try demand(&bounds, .range_check_20, keccak, 51);
    try demand(&bounds, .range_check_8_8, keccak, 1);
    try demand(&bounds, .range_check_8_8_4, keccak, 1);
    try demand(&bounds, .range_check_20, signer, 43);
    try demand(&bounds, .range_check_8_8, signer, 1);
    try demand(&bounds, .range_check_8_8_4, signer, 1);
    const extra = try add(try add(try mul(keccak, 48), try mul(signer, 40)), sha_bounds.extra_memory_terms);
    // SHA's typed census subtracts three reserved transitions per call from
    // extra_memory_terms. Derive the total from its exact positive/negative
    // DAG effects, rather than restoring only two and losing one real access.
    if (sha_bounds.memory_positive != sha_bounds.memory_negative) return error.UnbalancedBlockV5ShaMemoryCensus;
    const memory = try add(try add(try mul(keccak, 51), try mul(signer, 43)), sha_bounds.memory_positive);
    for (bounds) |value| try bounded(value);
    try bounded(extra);
    try bounded(memory);
    return .{ .extra_memory_terms = extra, .memory_relation_terms = memory, .base_fixed_table_bounds = @splat(0), .extended_fixed_table_bounds = bounds };
}
fn demand(values: *[geometry.fixed_table_count]u64, kind: tables.Kind, count: u32, per_row: u32) !void {
    const value = &values[@intFromEnum(kind)];
    value.* = try add(value.*, try mul(count, per_row));
}
fn bounded(value: u64) !void {
    if (value >= core.fields.m31.Modulus) return error.BlockV5PrecompileCoefficientOverflow;
}
fn add(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b);
}
fn mul(a: u64, b: u64) !u64 {
    return std.math.mul(u64, a, b);
}
fn disjoint(sha_calls: anytype, other_calls: anytype) !void {
    var other: usize = 0;
    for (sha_calls) |entry| {
        while (other < other_calls.len and other_calls[other].execution_clock < entry.call.execution_clock) : (other += 1) {}
        if (other < other_calls.len and other_calls[other].execution_clock == entry.call.execution_clock)
            return error.DuplicateExternalClock;
    }
}
