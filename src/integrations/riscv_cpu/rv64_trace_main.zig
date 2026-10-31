//! Owned CPU main commitment handoff. Borrowed whole-execution arenas stay
//! with their outer owner; this transfer consumes only a standalone allocation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const Frame = rv.full.frame;
const Tables = rv.providers.tables;
const M = core.fields.m31.M31;
const Trace = @import("rv64_full_trace.zig").Trace;
/// Complete source ownership for one main commitment. PCS consumes both slices
/// on success and failure; deinit is only for a transfer not yet submitted.
pub const Commit = struct {
    columns: []engine.pcs.ColumnEvaluation,
    backing: [][]M,
    pub fn deinit(self: *Commit, a: std.mem.Allocator) void {
        for (self.backing) |buffer| a.free(buffer);
        a.free(self.backing);
        a.free(self.columns);
        self.* = undefined;
    }
};
/// Copies only small provider multiplicities into the reserved tail. Their
/// original vectors stay live for generation after the shared challenge.
/// All allocations/shape checks precede transfer; OOM leaves this owner
/// intact. On success this owner retains metadata, but no source matrix.
pub fn take(self: *Trace, a: std.mem.Allocator, providers: []const engine.pcs.ColumnEvaluation) !Commit {
    try self.validateCommitAllocator(a);
    if (self.borrowed_main) return error.BorrowedRv64MainCannotTransfer;
    const width = self.plan.main_count + Frame.widthWithControl(self.plan.execution_profile, self.plan.control_policy);
    const size = self.domainSize();
    if (self.main.len != width * size or self.main_backing.len < self.main.len) return error.InvalidRv64FullMainPhase;
    var expected_logs: [4]u32 = undefined;
    expected_logs[0] = self.program.log_size;
    expected_logs[1] = 8;
    var count: usize = 2;
    if (self.plan.byte_bitwise) {
        expected_logs[count] = Tables.Kind.byte_and.logSize();
        count += 1;
    }
    if (self.plan.support.shifts) {
        expected_logs[count] = Tables.Kind.byte_shift.logSize();
        count += 1;
    }
    if (providers.len != count) return error.InvalidRv64FullProviderShape;
    var cells = self.main.len;
    for (providers, expected_logs[0..count]) |provider, log| {
        if (provider.log_size != log or provider.values.len != (@as(usize, 1) << @intCast(log))) return error.InvalidRv64FullProviderShape;
        cells = try std.math.add(usize, cells, provider.values.len);
    }
    if (cells != self.main_backing.len) return error.InvalidRv64FullProviderShape;
    const descriptors = try a.alloc(engine.pcs.ColumnEvaluation, width + count);
    errdefer a.free(descriptors);
    const backing = try a.alloc([]M, 1);
    for (descriptors[0..width], 0..) |*column, c| column.* = .{ .log_size = self.log_size, .values = self.main[c * size ..][0..size] };
    var cursor = self.main.len;
    for (descriptors[width..], providers) |*column, provider| {
        const values = self.main_backing[cursor..][0..provider.values.len];
        @memcpy(values, provider.values);
        column.* = .{ .log_size = provider.log_size, .values = values };
        cursor += values.len;
    }
    backing[0] = self.main_backing;
    self.main = &.{};
    self.main_backing = &.{};
    return .{ .columns = descriptors, .backing = backing };
}
