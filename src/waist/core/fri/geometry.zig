//! Validated fixed-step FRI round geometry.

const std = @import("std");
const foldStepAt = @import("config.zig").foldStepAt;

pub const Error = error{BindingSizeMismatch};

pub const RuntimeConfig = struct {
    round_count: usize,
    fold_step: u32,
    final_log: u32,
    packed_log: u32,
};

pub const FriGeometry = struct {
    /// Canonical SN2 defaults retained for source compatibility.
    pub const round_count: usize = 8;
    pub const fold_step: u32 = 3;
    pub const final_log: u32 = 1;
    pub const packed_log: u32 = 2;
    pub const max_round_count: usize = 31;

    start_log: u32,
    runtime_round_count: usize,
    runtime_fold_step: u32,
    runtime_final_log: u32,
    runtime_packed_log: u32,

    /// Constructs the canonical eight-round SN2 geometry.
    pub fn init(start_log: u32) Error!FriGeometry {
        return initRuntime(start_log, .{
            .round_count = round_count,
            .fold_step = fold_step,
            .final_log = final_log,
            .packed_log = packed_log,
        });
    }

    /// Authenticates the declared round count against the folding parameters
    /// and requires the final round to terminate at exactly `final_log`.
    pub fn initRuntime(start_log: u32, config: RuntimeConfig) Error!FriGeometry {
        if (config.round_count == 0 or config.round_count > max_round_count or
            config.fold_step == 0 or start_log > 31 or config.final_log >= start_log or
            config.packed_log > start_log)
            return Error.BindingSizeMismatch;
        const folds = start_log - config.final_log;
        if (config.fold_step > folds) return Error.BindingSizeMismatch;
        const expected_rounds = (folds + config.fold_step - 1) / config.fold_step;
        if (config.round_count != expected_rounds) return Error.BindingSizeMismatch;

        const last_cumulative = @as(u32, @intCast(config.round_count - 1)) * config.fold_step;
        if (last_cumulative >= folds or start_log - last_cumulative < config.packed_log)
            return Error.BindingSizeMismatch;
        const last_fold = foldStepAt(config.fold_step, start_log - last_cumulative - config.final_log);
        if (start_log - last_cumulative - last_fold != config.final_log)
            return Error.BindingSizeMismatch;

        return .{
            .start_log = start_log,
            .runtime_round_count = config.round_count,
            .runtime_fold_step = config.fold_step,
            .runtime_final_log = config.final_log,
            .runtime_packed_log = config.packed_log,
        };
    }

    pub fn roundCount(self: FriGeometry) usize {
        return self.runtime_round_count;
    }

    pub fn startLog(self: FriGeometry) u32 {
        return self.start_log;
    }

    pub fn foldStep(self: FriGeometry) u32 {
        return self.runtime_fold_step;
    }

    pub fn finalLog(self: FriGeometry) u32 {
        return self.runtime_final_log;
    }

    pub fn packedLog(self: FriGeometry) u32 {
        return self.runtime_packed_log;
    }

    pub fn evaluationLog(self: FriGeometry, round: usize) Error!u32 {
        if (round >= self.runtime_round_count) return Error.BindingSizeMismatch;
        return self.start_log - @as(u32, @intCast(round)) * self.runtime_fold_step;
    }

    pub fn cumulativeFold(self: FriGeometry, round: usize) Error!u32 {
        if (round >= self.runtime_round_count) return Error.BindingSizeMismatch;
        return @as(u32, @intCast(round)) * self.runtime_fold_step;
    }

    pub fn roundFold(self: FriGeometry, round: usize) Error!u32 {
        const evaluation_log = try self.evaluationLog(round);
        return foldStepAt(self.runtime_fold_step, evaluation_log - self.runtime_final_log);
    }

    pub fn terminalLog(self: FriGeometry) u32 {
        const last_round = self.runtime_round_count - 1;
        const evaluation_log = self.evaluationLog(last_round) catch unreachable;
        return evaluation_log - (self.roundFold(last_round) catch unreachable);
    }

    pub fn leafLog(self: FriGeometry, round: usize) Error!u32 {
        return (try self.evaluationLog(round)) - self.runtime_packed_log;
    }

    pub fn layerCount(self: FriGeometry, round: usize) Error!usize {
        return @as(usize, try self.leafLog(round)) + 1;
    }

    pub fn totalLayerCount(self: FriGeometry) usize {
        var total: usize = 0;
        for (0..self.runtime_round_count) |round| total += self.layerCount(round) catch unreachable;
        return total;
    }

    pub fn inverseTwiddleWords(self: FriGeometry) u64 {
        return @as(u64, 1) << @intCast(self.start_log - 1);
    }
};

test "FRI geometry preserves canonical eight-round SN2 defaults" {
    const log24 = try FriGeometry.init(24);
    try std.testing.expectEqual(@as(usize, 8), log24.roundCount());
    try std.testing.expectEqual(@as(usize, 100), log24.totalLayerCount());
    try std.testing.expectEqual(@as(u64, 1) << 23, log24.inverseTwiddleWords());
    try std.testing.expectEqual(@as(u32, 24), try log24.evaluationLog(0));
    try std.testing.expectEqual(@as(u32, 3), try log24.evaluationLog(7));
    try std.testing.expectEqual(@as(u32, 2), try log24.roundFold(7));
    try std.testing.expectEqual(@as(u32, 1), log24.terminalLog());
    try std.testing.expectEqual(@as(u32, 22), try log24.leafLog(0));

    const log25 = try FriGeometry.init(25);
    try std.testing.expectEqual(@as(usize, 108), log25.totalLayerCount());
    try std.testing.expectEqual(@as(u64, 1) << 24, log25.inverseTwiddleWords());
    try std.testing.expectEqual(@as(u32, 25), try log25.evaluationLog(0));
    try std.testing.expectEqual(@as(u32, 4), try log25.evaluationLog(7));
    try std.testing.expectEqual(@as(u32, 3), try log25.roundFold(7));
    try std.testing.expectError(Error.BindingSizeMismatch, log25.leafLog(log25.roundCount()));
}

test "FRI geometry authenticates Fib-like seven-round termination" {
    const fib = try FriGeometry.initRuntime(21, .{
        .round_count = 7,
        .fold_step = 3,
        .final_log = 1,
        .packed_log = 2,
    });
    try std.testing.expectEqual(@as(usize, 7), fib.roundCount());
    try std.testing.expectEqual(@as(usize, 77), fib.totalLayerCount());
    try std.testing.expectEqual(@as(u32, 3), try fib.evaluationLog(6));
    try std.testing.expectEqual(@as(u32, 2), try fib.roundFold(6));
    try std.testing.expectEqual(@as(u32, 1), fib.terminalLog());
    try std.testing.expectEqual(@as(u32, 1), try fib.leafLog(6));

    try std.testing.expectError(Error.BindingSizeMismatch, FriGeometry.initRuntime(21, .{
        .round_count = 8,
        .fold_step = 3,
        .final_log = 1,
        .packed_log = 2,
    }));
    try std.testing.expectError(Error.BindingSizeMismatch, FriGeometry.initRuntime(21, .{
        .round_count = 7,
        .fold_step = 3,
        .final_log = 1,
        .packed_log = 4,
    }));
}
