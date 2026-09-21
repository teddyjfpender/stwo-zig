//! Canonically scattered parallel prove/verify for retained D5 providers.

const std = @import("std");
const core_pcs = @import("stwo_core").pcs;
const frontend = @import("stwo_riscv_frontend");

const execution_mod =
    @import("ethereum_candidate_degree5_provider_batch_execution_v1.zig");
const prepared_mod =
    @import("ethereum_candidate_degree5_provider_prepared_batch_v1.zig");

const candidate_provider =
    frontend.testing.narrow_memory_provider_degree5_ethereum_candidate_v1;

pub fn OwnedProofBatchV1(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        proof_allocator: std.mem.Allocator,
        outputs: []candidate_provider.ProviderProofOutputV1(Engine),
        proof_live: []bool,
        execution_identity: [32]u8,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            for (self.outputs, self.proof_live) |*output, live|
                if (live) output.proof.deinit(self.proof_allocator);
            self.allocator.free(self.proof_live);
            self.allocator.free(self.outputs);
            self.* = undefined;
        }

        pub fn validateCanonical(self: *const Self) !void {
            if (self.outputs.len == 0 or self.outputs.len != self.proof_live.len)
                return error.InvalidDegree5ProviderProofBatch;
            for (self.outputs, self.proof_live, 0..) |output, live, index| {
                if (!live or output.statement.provider.shard_index != index or
                    !std.mem.eql(
                        u8,
                        &output.execution_profile_identity,
                        &self.execution_identity,
                    ))
                {
                    return error.InvalidDegree5ProviderProofBatch;
                }
            }
        }
    };
}

pub fn OwnedFreshBatchV1(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        claims: []candidate_provider.FreshCandidateProviderClaimV1,

        pub fn deinit(self: *@This()) void {
            self.allocator.free(self.claims);
            self.* = undefined;
        }

        pub fn validateAgainst(
            self: *const @This(),
            source: candidate_provider.Source(Engine),
        ) !void {
            if (self.claims.len != source.plan.shards.len)
                return error.InvalidDegree5ProviderFreshBatch;
            for (self.claims, 0..) |claim, index| {
                try claim.validateAgainst(source);
                if (claim.provider.provider.native_claim.shard_index != index)
                    return error.InvalidDegree5ProviderFreshBatch;
            }
        }
    };
}

pub fn provePreparedParallel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: candidate_provider.VerifierProgramAuthorityV2,
    profile: candidate_provider.ExecutionProfileV2,
    source: candidate_provider.Source(Engine),
    prepared: *prepared_mod.OwnedPreparedBatchV1(Engine),
    execution: *const execution_mod.AuthorityV1,
) !OwnedProofBatchV1(Engine) {
    try source.validate();
    try execution.validateAgainstPlan(source.plan);
    const expected_profile = try execution.executionProfile(program);
    if (!std.meta.eql(profile, expected_profile))
        return error.Degree5ProviderBatchExecutionProfileMismatch;
    try prepared.validatePrepared(
        program,
        source.plan,
        source.calls,
        execution,
    );
    for (prepared.roots_values, source.provider_stage_a.providers) |roots, record| {
        if (!std.meta.eql(roots.preprocessed_root, record.preprocessed_root) or
            !std.meta.eql(roots.main_root, record.main_root))
        {
            return error.Degree5PreparedStageAManifestMismatch;
        }
    }

    const outputs = try allocator.alloc(
        candidate_provider.ProviderProofOutputV1(Engine),
        source.plan.shards.len,
    );
    errdefer allocator.free(outputs);
    const proof_live = try allocator.alloc(bool, outputs.len);
    errdefer allocator.free(proof_live);
    @memset(proof_live, false);
    const failures = try allocator.alloc(?anyerror, outputs.len);
    defer allocator.free(failures);
    @memset(failures, null);

    var outputs_owned = true;
    errdefer if (outputs_owned) {
        for (outputs, proof_live) |*output, live|
            if (live) output.proof.deinit(std.heap.smp_allocator);
    };
    var shared = ProveShared(Engine){
        .pcs_config = pcs_config,
        .program = program,
        .profile = profile,
        .source = source,
        .transactions = prepared.transactions,
        .outputs = outputs,
        .proof_live = proof_live,
        .failures = failures,
    };
    try runWorkers(execution.concurrent_owners, &shared, @TypeOf(shared).run);
    for (failures) |failure| if (failure) |err| return err;
    try prepared.validateConsumed();

    var result = OwnedProofBatchV1(Engine){
        .allocator = allocator,
        .proof_allocator = std.heap.smp_allocator,
        .outputs = outputs,
        .proof_live = proof_live,
        .execution_identity = profile.identity,
    };
    try result.validateCanonical();
    outputs_owned = false;
    return result;
}

pub fn verifyFreshParallel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: candidate_provider.VerifierProgramAuthorityV2,
    profile: candidate_provider.ExecutionProfileV2,
    source: candidate_provider.Source(Engine),
    proofs: *OwnedProofBatchV1(Engine),
    execution: *const execution_mod.AuthorityV1,
) !OwnedFreshBatchV1(Engine) {
    try source.validate();
    try execution.validateAgainstPlan(source.plan);
    const expected_profile = try execution.executionProfile(program);
    if (!std.meta.eql(profile, expected_profile))
        return error.Degree5ProviderBatchExecutionProfileMismatch;
    try proofs.validateCanonical();
    if (!std.mem.eql(u8, &proofs.execution_identity, &profile.identity) or
        proofs.outputs.len != source.plan.shards.len)
    {
        return error.InvalidDegree5ProviderProofBatch;
    }

    const claims = try allocator.alloc(
        candidate_provider.FreshCandidateProviderClaimV1,
        proofs.outputs.len,
    );
    errdefer allocator.free(claims);
    const initialized = try allocator.alloc(bool, claims.len);
    defer allocator.free(initialized);
    @memset(initialized, false);
    const failures = try allocator.alloc(?anyerror, claims.len);
    defer allocator.free(failures);
    @memset(failures, null);

    var shared = VerifyShared(Engine){
        .pcs_config = pcs_config,
        .program = program,
        .profile = profile,
        .source = source,
        .proofs = proofs,
        .claims = claims,
        .initialized = initialized,
        .failures = failures,
    };
    try runWorkers(execution.concurrent_owners, &shared, @TypeOf(shared).run);
    for (failures) |failure| if (failure) |err| return err;
    for (initialized) |live| if (!live)
        return error.MissingDegree5FreshProviderClaim;

    var result = OwnedFreshBatchV1(Engine){
        .allocator = allocator,
        .claims = claims,
    };
    try result.validateAgainst(source);
    return result;
}

fn ProveShared(comptime Engine: type) type {
    return struct {
        pcs_config: core_pcs.PcsConfig,
        program: candidate_provider.VerifierProgramAuthorityV2,
        profile: candidate_provider.ExecutionProfileV2,
        source: candidate_provider.Source(Engine),
        transactions: []candidate_provider.PreparedStageATransactionV1(Engine),
        outputs: []candidate_provider.ProviderProofOutputV1(Engine),
        proof_live: []bool,
        failures: []?anyerror,
        next: std.atomic.Value(usize) = .init(0),

        const Self = @This();

        fn run(self: *Self) void {
            while (true) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.outputs.len) return;
                self.outputs[index] = candidate_provider.proveProviderPreparedV2(
                    Engine,
                    std.heap.smp_allocator,
                    self.pcs_config,
                    self.program,
                    self.profile,
                    self.source,
                    @intCast(index),
                    &self.transactions[index],
                ) catch |err| {
                    self.failures[index] = err;
                    continue;
                };
                self.proof_live[index] = true;
            }
        }
    };
}

fn VerifyShared(comptime Engine: type) type {
    return struct {
        pcs_config: core_pcs.PcsConfig,
        program: candidate_provider.VerifierProgramAuthorityV2,
        profile: candidate_provider.ExecutionProfileV2,
        source: candidate_provider.Source(Engine),
        proofs: *OwnedProofBatchV1(Engine),
        claims: []candidate_provider.FreshCandidateProviderClaimV1,
        initialized: []bool,
        failures: []?anyerror,
        next: std.atomic.Value(usize) = .init(0),

        const Self = @This();

        fn run(self: *Self) void {
            while (true) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.claims.len) return;
                self.verify(index) catch |err| {
                    self.failures[index] = err;
                    continue;
                };
            }
        }

        fn verify(self: *Self, index: usize) !void {
            if (!self.proofs.proof_live[index])
                return error.Degree5ProviderProofAlreadyConsumed;
            const proof = self.proofs.outputs[index].proof;
            self.proofs.outputs[index].proof = undefined;
            self.proofs.proof_live[index] = false;
            self.claims[index] = try candidate_provider.verifyProviderFreshV2(
                Engine,
                std.heap.smp_allocator,
                self.pcs_config,
                self.program,
                self.profile,
                self.source,
                self.proofs.outputs[index].statement,
                proof,
            );
            self.initialized[index] = true;
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
