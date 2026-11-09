//! The cache must never read outputs while an asynchronous device owns them.
const std = @import("std");
const core = @import("stwo_core");
const preparation = @import("preparation.zig");
const cache = @import("../column_preparation_cache.zig");
const TwiddleSource = @import("../../poly/twiddle_source.zig").TwiddleSource;
const profile = @import("stwo_prover_api").work_profile;
const M31 = core.fields.m31.M31;
const ColumnEvaluation = @import("../commitment_tree.zig").ColumnEvaluation;

const Probe = struct {
    identifications: usize = 0,
    stores: usize = 0,
    valid: bool = true,
    fn identify(raw: *anyopaque, _: cache.Request, _: []const []const M31) ?[32]u8 {
        const self: *Probe = @ptrCast(@alignCast(raw));
        self.identifications += 1;
        return @splat(1);
    }
    fn load(_: *anyopaque, _: [32]u8, _: cache.Request, _: []const []M31, _: []const []M31) bool {
        return false;
    }
    fn store(raw: *anyopaque, _: [32]u8, _: cache.Request, coefficients: []const []M31, evaluations: []const []M31) void {
        const self: *Probe = @ptrCast(@alignCast(raw));
        self.stores += 1;
        for (coefficients) |column| for (column) |value| {
            self.valid = self.valid and value.v == 42;
        };
        for (evaluations) |column| for (column) |value| {
            self.valid = self.valid and value.v == 43;
        };
    }
};
const DeferredBackend = struct {
    pub const combined_base_in_place = true;
    pub fn interpolateAndEvaluateCircleBuffers() void {
        unreachable;
    }
    pub const CircleLdeBatch = struct {
        coefficients: [16][]M31 = undefined,
        evaluations: [16][]M31 = undefined,
        count: usize = 0,
        pub fn init() !@This() {
            return .{};
        }
        pub fn deinit(_: *@This()) void {}
        pub fn finish(self: *@This()) !void {
            for (self.coefficients[0..self.count]) |column| @memset(column, .{ .v = 42 });
            for (self.evaluations[0..self.count]) |column| @memset(column, .{ .v = 43 });
        }
    };
    pub fn interpolateAndEvaluateCircleBuffersBatched(batch: *CircleLdeBatch, _: std.mem.Allocator, _: []const []const M31, coefficients: []const []M31, evaluations: []const []M31, _: []M31, _: usize, _: usize, base_domain: anytype, _: anytype, extended_domain: anytype, _: anytype) !profile.M31CircleLdeExecution {
        for (coefficients, evaluations) |coefficient, evaluation| {
            // Until finish, these buffers deliberately contain wrong data.
            @memset(coefficient, .{ .v = 11 });
            @memset(evaluation, .{ .v = 12 });
            batch.coefficients[batch.count] = coefficient;
            batch.evaluations[batch.count] = evaluation;
            batch.count += 1;
        }
        return .{ .interpolation = .{ .log_size = base_domain.logSize(), .column_count = coefficients.len, .batch_count = 1 }, .forward = .{ .log_size = extended_domain.logSize(), .column_count = coefficients.len } };
    }
};

test "column preparation: cache publication waits for device completion and audits bypass reuse" {
    const allocator = std.testing.allocator;
    var probe = Probe{};
    cache.arm(.{ .ctx = &probe, .identify = Probe.identify, .load = Probe.load, .store = Probe.store });
    defer cache.disarm();
    for ([_]bool{ false, true }) |audit| {
        probe = .{};
        const columns = try allocator.alloc(ColumnEvaluation, 2);
        for (columns, 0..) |*column, index| {
            const log_size: u32 = @intCast(3 + index);
            column.* = .{ .log_size = log_size, .values = try allocator.alloc(M31, @as(usize, 1) << @intCast(log_size)) };
            @memset(@constCast(column.values), M31.zero());
        }
        var twiddles = TwiddleSource.initOwned(allocator);
        defer twiddles.deinit(allocator);
        var recorder: profile.Recorder(true) = .{};
        var prepared = try preparation.prepareColumnsForCommitOwnedForBackendWithWorkRecorder(DeferredBackend, allocator, columns, 1, .always, &twiddles, null, null, if (audit) &recorder else null);
        defer prepared.deinit(allocator);
        try std.testing.expectEqual(@as(usize, if (audit) 0 else 2), probe.identifications);
        try std.testing.expectEqual(@as(usize, if (audit) 0 else 2), probe.stores);
        try std.testing.expect(probe.valid);
        for (prepared.columns) |column| for (column.values) |value| try std.testing.expectEqual(@as(u32, 43), value.v);
    }
}

test "column preparation: adopted in-place coefficient subcolumns borrow arena custody" {
    const allocator = std.testing.allocator;
    const arena = try allocator.alloc(M31, 24);
    @memset(arena, M31.zero());
    const columns = try allocator.alloc(ColumnEvaluation, 2);
    columns[0] = .{ .log_size = 3, .values = arena[0..8] };
    columns[1] = .{ .log_size = 4, .values = arena[8..24] };
    var twiddles = TwiddleSource.initOwned(allocator);
    defer twiddles.deinit(allocator);
    var prepared = try preparation.prepareColumnsForCommitOwnedForBackend(DeferredBackend, allocator, columns, 1, .always, &twiddles, null, arena);
    defer prepared.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), prepared.coefficient_backing_buffers.?.len);
    try std.testing.expectEqual(arena.ptr, prepared.coefficient_backing_buffers.?[0].ptr);
    for (prepared.coefficients.?) |coefficient| {
        try std.testing.expect(!coefficient.owns_coeffs);
        for (coefficient.coeffs) |value| try std.testing.expectEqual(@as(u32, 42), value.v);
    }
}

const BoundedBackend = struct {
    pub const requires_contiguous_resident_columns = true;
    pub const circle_lde_epoch_coefficient_bytes: usize = 2 * 4096 * @sizeOf(M31);
    pub const CircleLdeBatch = DeferredBackend.CircleLdeBatch;
    pub const interpolateAndEvaluateCircleBuffers = DeferredBackend.interpolateAndEvaluateCircleBuffers;
    pub const interpolateAndEvaluateCircleBuffersBatched = DeferredBackend.interpolateAndEvaluateCircleBuffersBatched;
};

fn exerciseBoundedEpochs(allocator: std.mem.Allocator, adopted: bool, retained: bool) !void {
    // Both split and unsplit heights share one final backing. A non-power-of-
    // two column count exercises the final partial epoch.
    const logs = [_]u32{ 12, 13, 12, 13, 12, 3 };
    const source_words = 3 * 4096 + 2 * 8192 + 8;
    const arena: ?[]M31 = if (adopted) try allocator.alloc(M31, source_words) else null;
    var sources_owned = true;
    defer if (sources_owned) {
        if (arena) |buffer| allocator.free(buffer);
    };
    const columns = try allocator.alloc(ColumnEvaluation, logs.len);
    var initialized: usize = 0;
    defer if (sources_owned) {
        if (!adopted) for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    };
    var cursor: usize = 0;
    for (columns, logs) |*column, log| {
        const len = @as(usize, 1) << @intCast(log);
        const values = if (arena) |buffer| buffer[cursor..][0..len] else try allocator.alloc(M31, len);
        @memset(values, M31.zero());
        column.* = .{ .log_size = log, .values = values };
        initialized += 1;
        cursor += len;
    }
    var twiddles = TwiddleSource.initOwned(allocator);
    defer twiddles.deinit(allocator);
    var prepared = try preparation.prepareColumnsForCommitOwnedForBackend(BoundedBackend, allocator, columns, 1, if (retained) .always else .never, &twiddles, null, arena);
    sources_owned = false;
    defer prepared.deinit(allocator);
    if (retained) {
        try std.testing.expectEqual(logs.len, prepared.coefficients.?.len);
        for (prepared.coefficients.?) |coefficient| for (coefficient.coeffs) |value|
            try std.testing.expectEqual(@as(u32, 42), value.v);
    } else {
        try std.testing.expect(prepared.coefficients == null);
        try std.testing.expect(prepared.coefficient_backing_buffers == null);
    }
    try std.testing.expectEqual(@as(usize, 1), prepared.column_backing_buffers.?.len);
    const backing = prepared.column_backing_buffers.?[0];
    for (prepared.columns, logs) |column, log| {
        try std.testing.expectEqual(log + 1, column.log_size);
        try std.testing.expectEqual(@as(usize, 2) << @intCast(log), column.values.len);
        try std.testing.expect(@intFromPtr(column.values.ptr) >= @intFromPtr(backing.ptr));
        try std.testing.expect(@intFromPtr(column.values.ptr + column.values.len) <= @intFromPtr(backing.ptr + backing.len));
        for (column.values) |value| try std.testing.expectEqual(@as(u32, 43), value.v);
    }
}

test "column preparation: bounded epochs preserve final arena and allocation-failure custody" {
    for ([_]bool{ false, true }) |adopted| for ([_]bool{ false, true }) |retained| {
        try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseBoundedEpochs, .{ adopted, retained });
    };
}

test "column preparation: bounded cache publication follows each joined epoch" {
    var probe = Probe{};
    cache.arm(.{ .ctx = &probe, .identify = Probe.identify, .load = Probe.load, .store = Probe.store });
    defer cache.disarm();
    try exerciseBoundedEpochs(std.testing.allocator, false, false);
    // log12: 2+1 columns; log13: 1+1 columns; log3: one group.
    try std.testing.expectEqual(@as(usize, 5), probe.identifications);
    try std.testing.expectEqual(@as(usize, 5), probe.stores);
    try std.testing.expect(probe.valid);
}
