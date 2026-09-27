//! Claim proposals and empty typed cache owners only: no fabricated successful
//! admission/capture/receipt, commitments, proof generation or device work.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Exports = @import("block_v5_supplemental_recursive_exports_v1.zig");
const Caller = @import("block_v5_caller_fused_proof_v1.zig");
const Native = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Program = @import("block_v5_program_extension_proof_v1.zig");
const Table = @import("block_v5_precompile_lookup_algebra_v1.zig");
const Access = @import("block_v5_external_memory_sidecar_proof_v1.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Range = @import("block_execution_byte_range_v2.zig");
fn scalar(value: u32) Q {
    return Q.fromBase(M.fromCanonical(value));
}
fn callerCopies(a: std.mem.Allocator) !void {
    var program = [_]Program.Claim{ .{ .sum = scalar(3), .fetch_count = 7 }, .{ .sum = scalar(5), .fetch_count = 11 } };
    var state = [_]Program.Claim{.{ .sum = scalar(13), .fetch_count = 17 }};
    var tables = [_]Table.Claim{ .{ .sum = scalar(19), .row_count = 23 }, .{ .sum = scalar(29), .row_count = 31 } };
    var ranges = [_]Range.Claims{ @splat(scalar(37)), @splat(scalar(41)) };
    var memory = [_]Access.Claim{.{ .transition_sum = scalar(43), .universal_sum = scalar(47), .range_claims = ranges[0], .active_count = 53 }};
    const expected_program = program;
    const expected_state = state;
    const expected_tables = tables;
    const expected_memory = memory;
    const expected_ranges = ranges;
    const source = Caller.ClaimFrames{ .program_claims = &program, .state_claims = &state, .table_claims = &tables, .memory_claims = &memory };
    var copied = try Exports.CallerCopies.clone(a, source, &ranges);
    defer copied.deinit(a);
    try std.testing.expect(copied.claims.program_claims.ptr != source.program_claims.ptr);
    try std.testing.expect(copied.claims.state_claims.ptr != source.state_claims.ptr);
    try std.testing.expect(copied.claims.table_claims.ptr != source.table_claims.ptr);
    try std.testing.expect(copied.claims.memory_claims.ptr != source.memory_claims.ptr);
    try std.testing.expect(copied.range_claims.ptr != ranges[0..].ptr);
    // Mutating/releasing a source capture cannot alter final export custody.
    program[1].fetch_count += 1;
    state[0].sum = scalar(59);
    tables[1].row_count += 1;
    memory[0].range_claims[0] = scalar(61);
    ranges[1][0] = scalar(67);
    try std.testing.expectEqualDeep(@as([]const Program.Claim, &expected_program), copied.claims.program_claims);
    try std.testing.expectEqualDeep(@as([]const Program.Claim, &expected_state), copied.claims.state_claims);
    try std.testing.expectEqualDeep(@as([]const Table.Claim, &expected_tables), copied.claims.table_claims);
    try std.testing.expectEqualDeep(@as([]const Access.Claim, &expected_memory), copied.claims.memory_claims);
    try std.testing.expectEqualDeep(@as([]const Range.Claims, &expected_ranges), copied.range_claims);
}
fn nativeCopies(a: std.mem.Allocator) !void {
    var projections = [_]Native.Claim{ .{ .sum = scalar(71), .row_count = 73 }, .{ .sum = scalar(79), .row_count = 83 } };
    var ranges = [_]Range.Claims{@splat(scalar(89))};
    var memory = [_]Memory.Claim{.{ .transition_sum = scalar(97), .universal_sum = scalar(101), .range_claims = ranges[0], .active_count = 103 }};
    const expected_projections = projections;
    const expected_memory = memory;
    const expected_ranges = ranges;
    var copied = try Exports.NativeCopies.clone(a, &projections, &memory, &ranges);
    defer copied.deinit(a);
    try std.testing.expect(copied.projection_claims.ptr != projections[0..].ptr);
    try std.testing.expect(copied.memory_claims.ptr != memory[0..].ptr);
    try std.testing.expect(copied.range_claims.?.ptr != ranges[0..].ptr);
    projections[0].sum = scalar(107);
    memory[0].active_count += 1;
    ranges[0][0] = scalar(109);
    try std.testing.expectEqualDeep(@as([]const Native.Claim, &expected_projections), copied.projection_claims);
    try std.testing.expectEqualDeep(@as([]const Memory.Claim, &expected_memory), copied.memory_claims);
    try std.testing.expectEqualDeep(@as([]const Range.Claims, &expected_ranges), copied.range_claims.?);
    var absent = try Exports.NativeCopies.clone(a, &projections, &.{}, null);
    defer absent.deinit(a);
    try std.testing.expect(absent.range_claims == null);
    try std.testing.expectEqual(@as(usize, 0), absent.memory_claims.len);
    var present_empty = try Exports.NativeCopies.clone(a, &projections, &.{}, &.{});
    defer present_empty.deinit(a);
    try std.testing.expect(present_empty.range_claims != null);
    try std.testing.expectEqual(@as(usize, 0), present_empty.range_claims.?.len);
}
test "supplemental stage lifetime: caller four claim frames and ranges retain independent custody" {
    try callerCopies(std.testing.allocator);
}
test "supplemental stage lifetime: caller export partial allocation failures unwind" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, callerCopies, .{});
}
test "supplemental stage lifetime: native claims and typed absent access retain independent custody" {
    try nativeCopies(std.testing.allocator);
}
test "supplemental stage lifetime: native optional export allocation failures unwind" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, nativeCopies, .{});
}
test "supplemental stage lifetime: every supplemental family checks original profile and borrowed cache" {
    const Stages = .{
        @import("block_v5_program_table_recursive_stage_v1.zig").ForBackend(Cpu),
        @import("block_v5_native_lookup_recursive_stage_v1.zig").ForBackend(Cpu),
        @import("block_v5_caller_arithmetic_recursive_stage_v1.zig").ForBackend(Cpu),
        @import("block_v5_caller_fused_recursive_stage_v1.zig").ForBackend(Cpu),
        @import("block_v5_native_capacity_fused_recursive_stage_v1.zig").ForBackend(Cpu),
    };
    const failures = .{ error.ProgramRecursiveSecurityMismatch, error.LookupRecursiveSecurityMismatch, error.CallerArithmeticRecursiveSecurityMismatch, error.CallerFusedRecursiveSecurityMismatch, error.CapacityFusedRecursiveSecurityMismatch };
    inline for (Stages, failures) |Stage, mismatch| {
        var options = Stage.Options{ .profile = .diagnostic_q8_pow0 };
        try options.validate(options.profile.config());
        try std.testing.expectError(mismatch, options.validate(@import("../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config()));
        var cache = try Stage.SetupCache.init(std.testing.allocator, .{ .profile = .csp_q70_pow26, .aggregate_host_byte_limit = 1 << 20, .worker_options = .{ .worker_count = 1, .host_byte_limit = 1 << 20, .retained_scratch_limit = 0 } });
        defer cache.deinit();
        options.cache = &cache;
        try std.testing.expectError(mismatch, options.validate(options.profile.config()));
        try std.testing.expect(cache.entry == null);
        try std.testing.expectEqual(@as(usize, 0), cache.stats.misses);
        try std.testing.expectEqual(@as(u64, 0), cache.request_lane.snapshot().starts);
    }
}
