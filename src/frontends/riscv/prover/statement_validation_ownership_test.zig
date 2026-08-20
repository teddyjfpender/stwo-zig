//! Consuming-commit ownership regression for base preprocessed verification.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const prover_pcs = @import("stwo_prover_engine").pcs;
const support = @import("../air/guest_precompile/main_trace_test_support.zig");
const types = @import("types.zig");
const subject = @import("statement_validation.zig");

const FakeEngine = struct {
    pub const Channel = struct {};
    pub const Scheme = struct {
        pub fn roots(
            _: *Scheme,
            allocator: std.mem.Allocator,
        ) !pcs_core.TreeVec(types.Hasher.Hash) {
            return pcs_core.TreeVec(types.Hasher.Hash).initOwned(
                try allocator.alloc(types.Hasher.Hash, 0),
            );
        }
    };

    var commit_calls: usize = 0;
    var consumed_commit_calls: usize = 0;
    var deinit_calls: usize = 0;

    fn reset() void {
        commit_calls = 0;
        consumed_commit_calls = 0;
        deinit_calls = 0;
    }

    pub fn init(_: std.mem.Allocator, _: pcs_core.PcsConfig) !Scheme {
        return .{};
    }

    pub fn deinit(_: *Scheme, _: std.mem.Allocator) void {
        deinit_calls += 1;
    }

    pub fn commit(
        _: *Scheme,
        allocator: std.mem.Allocator,
        columns: []prover_pcs.ColumnEvaluation,
        _: anytype,
        _: *Channel,
    ) !void {
        commit_calls += 1;
        freeColumns(allocator, columns);
        consumed_commit_calls += 1;
        return error.InjectedCommitFailure;
    }
};

test "base preprocessed verifier relinquishes columns before failed commit" {
    const statement = support.coreFixture(1);
    var counter = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    FakeEngine.reset();

    try std.testing.expectError(
        error.InjectedCommitFailure,
        subject.verifyPreprocessedRoot(
            FakeEngine,
            counter.allocator(),
            pcs_core.PcsConfig.default(),
            statement,
            .{0} ** 32,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), FakeEngine.commit_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeEngine.consumed_commit_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeEngine.deinit_calls);
    try std.testing.expectEqual(counter.allocated_bytes, counter.freed_bytes);
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}
