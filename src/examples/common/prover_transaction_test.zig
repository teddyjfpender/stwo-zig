//! Ownership and allocation-failure tests for the shared prover transaction.

const std = @import("std");
const fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const pcs_core = @import("stwo_core").pcs;
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_engine = @import("stwo_prover_engine").engine;
const prover_pcs = @import("stwo_prover_engine").pcs;
const stage_profile = @import("stwo_prover_api").stage_profile;
const subject = @import("prover_transaction.zig");

const M31 = m31.M31;
const ColumnEvaluation = prover_pcs.ColumnEvaluation;
const FakeRequest = struct {};
const FakeStatement = u8;

const FakeEngine = struct {
    pub const Channel = Blake2sChannel;
    pub const Component = prover_component.ComponentProver;
    pub const ExtendedProof = struct { marker: u8 };
    pub const Scheme = struct { allocation: *u8 };

    var commit_calls: usize = 0;
    var flush_calls: usize = 0;
    var deinit_calls: usize = 0;
    var prove_calls: usize = 0;
    var fail_commit_index: ?usize = null;
    var fail_prove: bool = false;

    pub fn reset() void {
        commit_calls = 0;
        flush_calls = 0;
        deinit_calls = 0;
        prove_calls = 0;
        fail_commit_index = null;
        fail_prove = false;
    }

    pub fn init(allocator: std.mem.Allocator, _: pcs_core.PcsConfig) !Scheme {
        const allocation = try allocator.create(u8);
        allocation.* = 0x5a;
        return .{ .allocation = allocation };
    }

    pub fn deinit(scheme: *Scheme, allocator: std.mem.Allocator) void {
        deinit_calls += 1;
        allocator.destroy(scheme.allocation);
        scheme.* = undefined;
    }

    pub fn commit(
        _: *Scheme,
        allocator: std.mem.Allocator,
        columns: []ColumnEvaluation,
        _: ?*stage_profile.Recorder,
        _: *Channel,
    ) !void {
        const call_index = commit_calls;
        commit_calls += 1;
        freeColumns(allocator, columns);
        if (fail_commit_index == call_index) return error.InjectedCommitFailure;
    }

    pub fn commitWithBacking(
        scheme: *Scheme,
        allocator: std.mem.Allocator,
        columns: []ColumnEvaluation,
        backing_buffers: ?[][]M31,
        recorder: ?*stage_profile.Recorder,
        channel: *Channel,
    ) !void {
        if (backing_buffers) |buffers| {
            const call_index = commit_calls;
            commit_calls += 1;
            allocator.free(columns);
            for (buffers) |buffer| allocator.free(buffer);
            allocator.free(buffers);
            if (fail_commit_index == call_index) return error.InjectedCommitFailure;
            return;
        }
        return commit(scheme, allocator, columns, recorder, channel);
    }

    pub fn commitPreparedWithBacking(
        scheme: *Scheme,
        allocator: std.mem.Allocator,
        columns: []ColumnEvaluation,
        backing_buffers: ?[][]M31,
        source: prover_pcs.ColumnSource,
        recorder: ?*stage_profile.Recorder,
        channel: *Channel,
    ) !void {
        try std.testing.expect(source.isMaterialized());
        return commitWithBacking(
            scheme,
            allocator,
            columns,
            backing_buffers,
            recorder,
            channel,
        );
    }

    pub fn flushPendingCommit(
        _: *Scheme,
        _: std.mem.Allocator,
        _: *Channel,
    ) !void {
        flush_calls += 1;
    }

    pub fn prove(
        allocator: std.mem.Allocator,
        _: []const prover_component.ComponentProver,
        _: *Channel,
        scheme: Scheme,
        _: prover_engine.ProveOptions,
    ) !ExtendedProof {
        prove_calls += 1;
        allocator.destroy(scheme.allocation);
        if (fail_prove) return error.InjectedProveFailure;
        return .{ .marker = 0xa5 };
    }
};

const FakeBoundarySpec = struct {
    pub const Statement = FakeSpec.Statement;
    pub const PreparedInput = FakeSpec.PreparedInput;
    pub const max_components = FakeSpec.max_components;
    pub const ProverContext = FakeSpec.ProverContext;

    pub const validateRequest = FakeSpec.validateRequest;
    pub const validatePrepared = FakeSpec.validatePrepared;
    pub const compositionLog = FakeSpec.compositionLog;
    pub const initProverContext = FakeSpec.initProverContext;
    pub const statement = FakeSpec.statement;
    pub const proverComponents = FakeSpec.proverComponents;

    pub fn beforeMainCommit(_: *Blake2sChannel, _: FakeRequest) !void {
        if (FakeEngine.flush_calls != 1)
            return error.TranscriptBoundaryNotFlushed;
    }
};

const FakeSpec = struct {
    pub const Statement = FakeStatement;
    pub const PreparedInput = subject.PreparedInput(FakeRequest);
    pub const max_components: usize = 0;
    pub const ProverContext = struct { statement_value: FakeStatement };

    pub fn validateRequest(_: FakeRequest) !void {}

    pub fn validatePrepared(prepared: *const PreparedInput) !void {
        if (prepared.trace.preprocessed.columns.?.len != 1 or
            prepared.trace.main.columns.?.len != 2)
        {
            return error.InvalidTestGeometry;
        }
    }

    pub fn compositionLog(_: FakeRequest) !u32 {
        return 2;
    }

    pub fn initProverContext(
        out: *ProverContext,
        _: *Blake2sChannel,
        _: FakeRequest,
    ) !void {
        out.* = .{ .statement_value = 7 };
    }

    pub fn statement(context: *const ProverContext) FakeStatement {
        return context.statement_value;
    }

    pub fn proverComponents(
        _: *const ProverContext,
        out: []prover_component.ComponentProver,
    ) ![]const prover_component.ComponentProver {
        return out;
    }
};

const FakeInteractionSpec = struct {
    pub const Statement = FakeStatement;
    pub const PreparedInput = FakeSpec.PreparedInput;
    pub const PreparedInteraction = struct {
        columns: subject.OwnedColumns,
    };
    pub const max_components: usize = 0;
    pub const ProverContext = FakeSpec.ProverContext;

    var fail_prepare = false;
    var interaction_deinit_calls: usize = 0;

    pub fn reset() void {
        fail_prepare = false;
        interaction_deinit_calls = 0;
    }

    pub const validateRequest = FakeSpec.validateRequest;
    pub const validatePrepared = FakeSpec.validatePrepared;
    pub const compositionLog = FakeSpec.compositionLog;
    pub const statement = FakeSpec.statement;
    pub const proverComponents = FakeSpec.proverComponents;

    pub fn prepareInteraction(
        allocator: std.mem.Allocator,
        _: *Blake2sChannel,
        _: *const PreparedInput,
    ) !PreparedInteraction {
        if (fail_prepare) return error.InjectedInteractionPrepareFailure;
        return .{
            .columns = subject.OwnedColumns.init(try makeColumns(allocator, 1)),
        };
    }

    pub fn deinitPreparedInteraction(
        prepared: *PreparedInteraction,
        allocator: std.mem.Allocator,
    ) void {
        interaction_deinit_calls += 1;
        prepared.columns.deinit(allocator);
        prepared.* = undefined;
    }

    pub fn initProverContext(
        out: *ProverContext,
        _: *Blake2sChannel,
        _: FakeRequest,
        _: *const PreparedInteraction,
    ) !void {
        out.* = .{ .statement_value = 7 };
    }
};

fn config() !pcs_core.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
}

fn makeColumns(
    allocator: std.mem.Allocator,
    count: usize,
) ![]ColumnEvaluation {
    const columns = try allocator.alloc(ColumnEvaluation, count);
    errdefer allocator.free(columns);

    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column.values);
    for (columns) |*column| {
        const values = try allocator.alloc(M31, 2);
        @memset(values, M31.zero());
        column.* = .{ .log_size = 1, .values = values };
        initialized += 1;
    }
    return columns;
}

fn makePrepared(allocator: std.mem.Allocator) !FakeSpec.PreparedInput {
    var preprocessed = subject.OwnedColumns.init(try makeColumns(allocator, 1));
    errdefer preprocessed.deinit(allocator);
    var main = subject.OwnedColumns.init(try makeColumns(allocator, 2));
    errdefer main.deinit(allocator);

    return .{
        .request = .{},
        .trace = try subject.PreparedTrace.initOwned(
            allocator,
            preprocessed.take(),
            main.take(),
        ),
    };
}

fn freeColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}

fn prepareAndDeinit(allocator: std.mem.Allocator) !void {
    var prepared = try makePrepared(allocator);
    defer prepared.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), prepared.trace.committed_columns);
    try std.testing.expectEqual(@as(u64, 6), prepared.trace.committed_cells);
}

fn runTransaction(allocator: std.mem.Allocator) !FakeEngine.ExtendedProof {
    const prepared = try makePrepared(allocator);
    const output = try subject.provePreparedEx(
        FakeEngine,
        FakeSpec,
        false,
        {},
        allocator,
        try config(),
        prepared,
        .{},
    );
    try std.testing.expectEqual(@as(FakeStatement, 7), output.statement);
    return output.proof;
}

fn runBoundaryTransaction(allocator: std.mem.Allocator) !FakeEngine.ExtendedProof {
    const prepared = try makePrepared(allocator);
    const output = try subject.provePreparedEx(
        FakeEngine,
        FakeBoundarySpec,
        false,
        {},
        allocator,
        try config(),
        prepared,
        .{},
    );
    return output.proof;
}

fn runInteractionTransaction(
    allocator: std.mem.Allocator,
) !FakeEngine.ExtendedProof {
    const prepared = try makePrepared(allocator);
    const output = try subject.provePreparedEx(
        FakeEngine,
        FakeInteractionSpec,
        false,
        {},
        allocator,
        try config(),
        prepared,
        .{},
    );
    return output.proof;
}

test "prover transaction: prepared trace cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        prepareAndDeinit,
        .{},
    );
}

test "prover transaction: moved columns are cleared before final cleanup" {
    var prepared = try makePrepared(std.testing.allocator);
    const moved = prepared.trace.preprocessed.take();
    try std.testing.expectEqual(null, prepared.trace.preprocessed.columns);
    freeColumns(std.testing.allocator, moved);
    prepared.deinit(std.testing.allocator);
}

test "prover transaction: commit failures consume moved trees exactly once" {
    inline for (0..2) |failure_index| {
        FakeEngine.reset();
        FakeEngine.fail_commit_index = failure_index;
        try std.testing.expectError(
            error.InjectedCommitFailure,
            runTransaction(std.testing.allocator),
        );
        try std.testing.expectEqual(failure_index + 1, FakeEngine.commit_calls);
        try std.testing.expectEqual(@as(usize, 1), FakeEngine.deinit_calls);
        try std.testing.expectEqual(@as(usize, 0), FakeEngine.prove_calls);
    }
}

test "prover transaction: prove failure consumes the transferred scheme" {
    FakeEngine.reset();
    FakeEngine.fail_prove = true;
    try std.testing.expectError(
        error.InjectedProveFailure,
        runTransaction(std.testing.allocator),
    );
    try std.testing.expectEqual(@as(usize, 2), FakeEngine.commit_calls);
    try std.testing.expectEqual(@as(usize, 0), FakeEngine.deinit_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeEngine.prove_calls);
}

test "prover transaction: success transfers every owned resource once" {
    FakeEngine.reset();
    const proof = try runTransaction(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0xa5), proof.marker);
    try std.testing.expectEqual(@as(usize, 2), FakeEngine.commit_calls);
    try std.testing.expectEqual(@as(usize, 0), FakeEngine.flush_calls);
    try std.testing.expectEqual(@as(usize, 0), FakeEngine.deinit_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeEngine.prove_calls);
}

test "prover transaction: flushes a deferred root before transcript boundary data" {
    FakeEngine.reset();
    const proof = try runBoundaryTransaction(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0xa5), proof.marker);
    try std.testing.expectEqual(@as(usize, 1), FakeEngine.flush_calls);
}

test "prover transaction: failed interaction preparation never deinitializes undefined state" {
    FakeEngine.reset();
    FakeInteractionSpec.reset();
    FakeInteractionSpec.fail_prepare = true;
    try std.testing.expectError(
        error.InjectedInteractionPrepareFailure,
        runInteractionTransaction(std.testing.allocator),
    );
    try std.testing.expectEqual(@as(usize, 2), FakeEngine.commit_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeEngine.deinit_calls);
    try std.testing.expectEqual(
        @as(usize, 0),
        FakeInteractionSpec.interaction_deinit_calls,
    );
}
