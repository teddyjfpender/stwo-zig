//! Ownership and authority tests for retained degree-five Stage A.

const std = @import("std");
const fri = @import("stwo_core").fri;
const core_pcs = @import("stwo_core").pcs;
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const stage_profile = @import("stwo_prover_api").stage_profile;
const prover_pcs = @import("stwo_prover_engine").pcs;
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;

const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const authority = @import("authority.zig");
const binding = @import("degree5_ethereum_omit_provider_authority_v1.zig");
const subject = @import("degree5_provider_stage_a_transaction_v1.zig");

const FakeEngine = struct {
    pub const Hasher = struct {
        pub const Hash = [8]u32;
    };
    pub const Channel = Blake2sChannel;
    pub const Scheme = struct {
        token: *u8,
        commit_count: usize = 0,
        retention_always: bool = false,

        pub fn setCoefficientRetentionPolicy(self: *@This(), value: anytype) void {
            self.retention_always = value == .always;
        }

        pub fn roots(
            self: *@This(),
            allocator: std.mem.Allocator,
        ) !OwnedRoots {
            if (self.commit_count != 2 or !self.retention_always)
                return error.InvalidFakeStageA;
            const items = try allocator.alloc(Hasher.Hash, 2);
            items[0] = [_]u32{0x51} ** 8;
            items[1] = [_]u32{0xa2} ** 8;
            return .{ .items = items };
        }
    };

    const OwnedRoots = struct {
        items: []Hasher.Hash,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.items);
            self.* = undefined;
        }
    };

    var deinit_count: usize = 0;
    var fail_commit_index: ?usize = null;

    fn reset() void {
        deinit_count = 0;
        fail_commit_index = null;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        _: core_pcs.PcsConfig,
    ) !Scheme {
        const token = try allocator.create(u8);
        token.* = 0xc5;
        return .{ .token = token };
    }

    pub fn deinit(scheme: *Scheme, allocator: std.mem.Allocator) void {
        deinit_count += 1;
        allocator.destroy(scheme.token);
        scheme.* = undefined;
    }

    pub fn commit(
        scheme: *Scheme,
        allocator: std.mem.Allocator,
        columns: []prover_pcs.ColumnEvaluation,
        _: ?*stage_profile.Recorder,
        _: *Channel,
    ) !void {
        const index = scheme.commit_count;
        scheme.commit_count += 1;
        for (columns) |column| allocator.free(column.values);
        allocator.free(columns);
        if (fail_commit_index == index) return error.InjectedCommitFailure;
    }

    pub fn flushPendingCommit(
        _: *Scheme,
        _: std.mem.Allocator,
        _: *Channel,
    ) !void {}
};

test "retained degree-five Stage A moves its exact scheme once" {
    const allocator = std.testing.allocator;
    FakeEngine.reset();
    const calls = try callsFixture(allocator, 16);
    defer allocator.free(calls);
    var plan = try makePlan(allocator, calls);
    defer plan.deinit(allocator);
    const program = try binding.VerifierProgramAuthorityV2.coldCompile(allocator);

    var prepared = try subject.PreparedStageATransactionV1(FakeEngine).init(
        allocator,
        try config(),
        program,
        &plan,
        calls,
        0,
    );
    defer prepared.deinit();
    const roots = try prepared.roots();
    try prepared.validateBorrowed(
        program,
        &plan,
        calls,
        0,
        roots.preprocessed_root,
        roots.main_root,
    );

    var scheme = try prepared.takeScheme(
        program,
        &plan,
        calls,
        0,
        roots.preprocessed_root,
        roots.main_root,
    );
    defer FakeEngine.deinit(&scheme, allocator);
    try prepared.validateConsumed();
    try std.testing.expectEqual(@as(u8, 1), prepared.receipt.scheme_moves);
    try std.testing.expectEqual(
        @as(u8, 1),
        prepared.receipt.duplicate_stage_a_transactions_avoided,
    );
    try std.testing.expectError(
        error.Degree5StageATransactionConsumed,
        prepared.takeScheme(
            program,
            &plan,
            calls,
            0,
            roots.preprocessed_root,
            roots.main_root,
        ),
    );
}

test "retained degree-five Stage A rejects pointer and root substitution" {
    const allocator = std.testing.allocator;
    FakeEngine.reset();
    const calls = try callsFixture(allocator, 16);
    defer allocator.free(calls);
    const copied_calls = try allocator.dupe(poseidon2_air.Call, calls);
    defer allocator.free(copied_calls);
    var plan = try makePlan(allocator, calls);
    defer plan.deinit(allocator);
    const program = try binding.VerifierProgramAuthorityV2.coldCompile(allocator);
    var prepared = try subject.PreparedStageATransactionV1(FakeEngine).init(
        allocator,
        try config(),
        program,
        &plan,
        calls,
        0,
    );
    defer prepared.deinit();
    const roots = try prepared.roots();

    try std.testing.expectError(
        error.InvalidDegree5StageABorrowedAuthority,
        prepared.validateBorrowed(
            program,
            &plan,
            copied_calls,
            0,
            roots.preprocessed_root,
            roots.main_root,
        ),
    );
    var wrong_root = roots.main_root;
    wrong_root[0] +%= 1;
    try std.testing.expectError(
        error.Degree5StageARootMismatch,
        prepared.validateBorrowed(
            program,
            &plan,
            calls,
            0,
            roots.preprocessed_root,
            wrong_root,
        ),
    );
}

test "retained degree-five Stage A cleans candidate and scheme on commit error" {
    const allocator = std.testing.allocator;
    FakeEngine.reset();
    const calls = try callsFixture(allocator, 16);
    defer allocator.free(calls);
    var plan = try makePlan(allocator, calls);
    defer plan.deinit(allocator);
    const program = try binding.VerifierProgramAuthorityV2.coldCompile(allocator);
    FakeEngine.fail_commit_index = 1;
    try std.testing.expectError(
        error.InjectedCommitFailure,
        subject.PreparedStageATransactionV1(FakeEngine).init(
            allocator,
            try config(),
            program,
            &plan,
            calls,
            0,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), FakeEngine.deinit_count);
}

test "degree-five runtime execution profile is not pinned to N4" {
    const program = try binding.VerifierProgramAuthorityV2.coldCompile(
        std.testing.allocator,
    );
    const profile = try binding.ExecutionProfileV2.runtime(
        program.base,
        18,
        1,
        1024 * 1024 * 1024,
    );
    try profile.validate(program.base);
    try std.testing.expectEqual(@as(u16, 18), profile.concurrent_provider_limit);

    var mutated = profile;
    mutated.concurrent_provider_limit = 4;
    try std.testing.expectError(
        error.InvalidDegree5ExecutionProfile,
        mutated.validate(program.base),
    );
    try std.testing.expectError(
        error.InvalidDegree5ExecutionProfile,
        binding.ExecutionProfileV2.runtime(
            program.base,
            33,
            1,
            1024 * 1024 * 1024,
        ),
    );
}

fn config() !core_pcs.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try fri.FriConfig.init(0, 1, 3),
    };
}

fn callsFixture(
    allocator: std.mem.Allocator,
    count: usize,
) ![]poseidon2_air.Call {
    const calls = try allocator.alloc(poseidon2_air.Call, count);
    for (calls, 0..) |*call, index| {
        call.* = poseidon2_air.Call.narrowWithOutput(
            @intCast(index + 1),
            @intCast(index + 2),
            @intCast(index + 3),
        );
    }
    return calls;
}

fn makePlan(
    allocator: std.mem.Allocator,
    calls: []const poseidon2_air.Call,
) !authority.ProviderShardPlanV1 {
    return authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0x73} ** 32,
        calls,
        shard_planner.Request{
            .logical_row_count = @intCast(calls.len),
            .column_count = authority.main_column_count,
            .min_shard_log_size = 4,
            .max_shard_log_size = 4,
            .log_blowup_factor = 1,
            .retention_policy = .always,
            .host_byte_budget = 1024 * 1024 * 1024,
            .reserved_host_bytes = 0,
            .requested_parallel_shards = 1,
        },
    );
}
