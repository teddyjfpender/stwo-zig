//! Parallel, fail-atomic preparation of retained degree-five Stage-A owners.

const std = @import("std");
const core_pcs = @import("stwo_core").pcs;
const frontend = @import("stwo_riscv_frontend");

const execution_mod =
    @import("ethereum_candidate_degree5_provider_batch_execution_v1.zig");

const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const provider_harness =
    frontend.testing.narrow_memory_provider_proof_harness;
const candidate_provider =
    frontend.testing.narrow_memory_provider_degree5_ethereum_candidate_v1;

pub fn OwnedPreparedBatchV1(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        plan: *const provider_authority.ProviderShardPlanV1,
        validated_calls: ?*const provider_authority.OwnedValidatedPlanCallAuthorityV1,
        calls_ptr: [*]const poseidon2_air.Call,
        calls_len: usize,
        program_identity: [32]u8,
        execution_identity_sha256: [32]u8,
        transactions: []candidate_provider.PreparedStageATransactionV1(Engine),
        roots_values: []provider_harness.StageACommitment(Engine),

        const Self = @This();

        pub fn validatePrepared(
            self: *Self,
            program: candidate_provider.VerifierProgramAuthorityV2,
            plan: *const provider_authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            execution: *const execution_mod.AuthorityV1,
        ) !void {
            return self.validatePreparedInternal(
                program,
                plan,
                calls,
                null,
                execution,
            );
        }

        pub fn validatePreparedValidated(
            self: *Self,
            program: candidate_provider.VerifierProgramAuthorityV2,
            plan: *const provider_authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            validated_calls: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
            execution: *const execution_mod.AuthorityV1,
        ) !void {
            return self.validatePreparedInternal(
                program,
                plan,
                calls,
                validated_calls,
                execution,
            );
        }

        fn validatePreparedInternal(
            self: *Self,
            program: candidate_provider.VerifierProgramAuthorityV2,
            plan: *const provider_authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            validated_calls: ?*const provider_authority.OwnedValidatedPlanCallAuthorityV1,
            execution: *const execution_mod.AuthorityV1,
        ) !void {
            try execution.validateAgainstPlan(plan);
            if (validated_calls) |validated|
                try validated.validateBorrowed(plan, calls)
            else
                try plan.validate(calls);
            if (self.plan != plan or self.validated_calls != validated_calls or
                self.calls_ptr != calls.ptr or
                self.calls_len != calls.len or
                self.transactions.len != plan.shards.len or
                self.roots_values.len != plan.shards.len or
                !std.mem.eql(
                    u8,
                    &self.program_identity,
                    &program.air_program_identity,
                ) or !std.mem.eql(
                u8,
                &self.execution_identity_sha256,
                &execution.identity_sha256,
            )) return error.InvalidDegree5PreparedStageABatch;
            for (self.transactions, self.roots_values, 0..) |*transaction, root_pair, index| {
                if (validated_calls) |validated|
                    try transaction.validateBorrowedValidated(
                        program,
                        plan,
                        calls,
                        validated,
                        @intCast(index),
                        root_pair.preprocessed_root,
                        root_pair.main_root,
                    )
                else
                    try transaction.validateBorrowed(
                        program,
                        plan,
                        calls,
                        @intCast(index),
                        root_pair.preprocessed_root,
                        root_pair.main_root,
                    );
            }
        }

        pub fn validateConsumed(self: *const Self) !void {
            for (self.transactions) |*transaction|
                try transaction.validateConsumed();
        }

        pub fn roots(self: *const Self) []const provider_harness.StageACommitment(Engine) {
            return self.roots_values;
        }

        pub fn deinit(self: *Self) void {
            for (self.transactions) |*transaction| transaction.deinit();
            self.allocator.free(self.roots_values);
            self.allocator.free(self.transactions);
            self.* = undefined;
        }
    };
}

pub fn prepareParallel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: candidate_provider.VerifierProgramAuthorityV2,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    execution: *const execution_mod.AuthorityV1,
) !OwnedPreparedBatchV1(Engine) {
    return prepareParallelInternal(
        Engine,
        allocator,
        pcs_config,
        program,
        plan,
        calls,
        null,
        execution,
    );
}

pub fn prepareParallelValidated(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: candidate_provider.VerifierProgramAuthorityV2,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    validated_calls: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    execution: *const execution_mod.AuthorityV1,
) !OwnedPreparedBatchV1(Engine) {
    return prepareParallelInternal(
        Engine,
        allocator,
        pcs_config,
        program,
        plan,
        calls,
        validated_calls,
        execution,
    );
}

fn prepareParallelInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: candidate_provider.VerifierProgramAuthorityV2,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    validated_calls: ?*const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    execution: *const execution_mod.AuthorityV1,
) !OwnedPreparedBatchV1(Engine) {
    if (validated_calls) |validated|
        try validated.validateBorrowed(plan, calls)
    else
        try plan.validate(calls);
    try execution.validateAgainstPlan(plan);
    try program.validateCold(allocator);

    const Transaction = candidate_provider.PreparedStageATransactionV1(Engine);
    const transactions = try allocator.alloc(Transaction, plan.shards.len);
    errdefer allocator.free(transactions);
    const roots = try allocator.alloc(
        provider_harness.StageACommitment(Engine),
        plan.shards.len,
    );
    errdefer allocator.free(roots);
    const initialized = try allocator.alloc(bool, plan.shards.len);
    defer allocator.free(initialized);
    @memset(initialized, false);
    const failures = try allocator.alloc(?anyerror, plan.shards.len);
    defer allocator.free(failures);
    @memset(failures, null);

    var transactions_owned = true;
    errdefer if (transactions_owned) {
        for (transactions, initialized) |*transaction, live|
            if (live) transaction.deinit();
    };

    var shared = Shared(Engine){
        .pcs_config = pcs_config,
        .program = program,
        .plan = plan,
        .calls = calls,
        .validated_calls = validated_calls,
        .transactions = transactions,
        .roots = roots,
        .initialized = initialized,
        .failures = failures,
    };
    try runWorkers(execution.concurrent_owners, &shared, @TypeOf(shared).run);
    for (failures) |failure| if (failure) |err| return err;
    for (initialized) |live| if (!live)
        return error.MissingDegree5PreparedStageATransaction;

    var result = OwnedPreparedBatchV1(Engine){
        .allocator = allocator,
        .plan = plan,
        .validated_calls = validated_calls,
        .calls_ptr = calls.ptr,
        .calls_len = calls.len,
        .program_identity = program.air_program_identity,
        .execution_identity_sha256 = execution.identity_sha256,
        .transactions = transactions,
        .roots_values = roots,
    };
    try result.validatePreparedInternal(
        program,
        plan,
        calls,
        validated_calls,
        execution,
    );
    transactions_owned = false;
    return result;
}

fn Shared(comptime Engine: type) type {
    return struct {
        pcs_config: core_pcs.PcsConfig,
        program: candidate_provider.VerifierProgramAuthorityV2,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        validated_calls: ?*const provider_authority.OwnedValidatedPlanCallAuthorityV1,
        transactions: []candidate_provider.PreparedStageATransactionV1(Engine),
        roots: []provider_harness.StageACommitment(Engine),
        initialized: []bool,
        failures: []?anyerror,
        next: std.atomic.Value(usize) = .init(0),

        const Self = @This();

        fn run(self: *Self) void {
            while (true) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.transactions.len) return;
                self.prepare(index) catch |err| {
                    self.failures[index] = err;
                    continue;
                };
            }
        }

        fn prepare(self: *Self, index: usize) !void {
            self.transactions[index] = if (self.validated_calls) |validated|
                try candidate_provider.PreparedStageATransactionV1(Engine)
                    .initValidated(
                    std.heap.smp_allocator,
                    self.pcs_config,
                    self.program,
                    self.plan,
                    self.calls,
                    validated,
                    @intCast(index),
                )
            else
                try candidate_provider.PreparedStageATransactionV1(Engine).init(
                    std.heap.smp_allocator,
                    self.pcs_config,
                    self.program,
                    self.plan,
                    self.calls,
                    @intCast(index),
                );
            self.initialized[index] = true;
            self.roots[index] = try self.transactions[index].roots();
        }
    };
}

fn runWorkers(
    worker_count: u16,
    context: anytype,
    comptime run: anytype,
) !void {
    if (worker_count == 0 or worker_count > execution_mod.MAX_ENGINE_WORKERS)
        return error.InvalidDegree5ProviderBatchExecution;
    if (worker_count == 1) {
        run(context);
        return;
    }
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{
        .allocator = std.heap.smp_allocator,
        .n_jobs = worker_count - 1,
    });
    defer pool.deinit();
    var wait_group: std.Thread.WaitGroup = .{};
    for (1..@as(usize, worker_count)) |_|
        pool.spawnWg(&wait_group, run, .{context});
    run(context);
    pool.waitAndWork(&wait_group);
}
