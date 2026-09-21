//! Canonical-byte boundary for a retained ordered D5 provider batch.
//!
//! Metal proves each shard from its one-shot prepared Stage-A transaction.
//! Before independent CPU verification, every proof is serialized through the
//! canonical Zig postcard codec and the producer proof object is destroyed.
//! The CPU verifier therefore receives no producer-owned proof capability.

const std = @import("std");
const core_pcs = @import("stwo_core").pcs;
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");

const execution_mod =
    @import("ethereum_candidate_degree5_provider_batch_execution_v1.zig");
const prepared_mod =
    @import("ethereum_candidate_degree5_provider_prepared_batch_v1.zig");

const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const provider =
    frontend.testing.narrow_memory_provider_degree5_order_proof_v2;
const prepared_transaction =
    frontend.testing.narrow_memory_provider_degree5_ethereum_candidate_v1;

pub const EncodedShardV1 = struct {
    statement: provider.StatementV2,
    execution_profile_identity: [32]u8,
    canonical_proof_bytes: []u8,
    canonical_proof_sha256: [32]u8,
};

pub fn OwnedEncodedBatchV1(comptime ProducerEngine: type) type {
    _ = ProducerEngine;
    return struct {
        allocator: std.mem.Allocator,
        item_allocator: std.mem.Allocator,
        shards: []EncodedShardV1,
        live: []bool,
        execution_identity: [32]u8,

        const Self = @This();

        pub fn validateCanonical(
            self: *const Self,
            plan: *const provider_authority.ProviderShardPlanV1,
        ) !void {
            if (self.shards.len == 0 or self.shards.len != plan.shards.len or
                self.shards.len != self.live.len)
            {
                return error.InvalidDegree5OrderedProofBatch;
            }
            for (self.shards, self.live, plan.shards, 0..) |
                shard,
                live,
                descriptor,
                index,
            | {
                if (!live or shard.canonical_proof_bytes.len == 0 or
                    shard.canonical_proof_bytes.len >
                        execution_mod.MAX_CANONICAL_PROOF_BYTES_PER_SHARD or
                    shard.statement.shard_index != index or
                    !std.meta.eql(
                        shard.statement.source_descriptor_identity,
                        descriptor.identity,
                    ) or
                    !std.mem.eql(
                        u8,
                        &shard.execution_profile_identity,
                        &self.execution_identity,
                    ) or !std.mem.eql(
                    u8,
                    &shard.canonical_proof_sha256,
                    &sha256(shard.canonical_proof_bytes),
                )) return error.InvalidDegree5OrderedProofBatch;
            }
        }

        pub fn deinit(self: *Self) void {
            for (self.shards, self.live) |shard, live|
                if (live) self.item_allocator.free(shard.canonical_proof_bytes);
            self.allocator.free(self.live);
            self.allocator.free(self.shards);
            self.* = undefined;
        }
    };
}

pub const OwnedFreshBatchV1 = struct {
    allocator: std.mem.Allocator,
    claims: []provider.FreshVerifiedShardV2,

    pub fn validateAgainst(
        self: *const OwnedFreshBatchV1,
        plan: *const provider_authority.ProviderShardPlanV1,
        execution_profile: provider.ExecutionProfileV2,
    ) !void {
        if (self.claims.len != plan.shards.len)
            return error.InvalidDegree5OrderedFreshBatch;
        for (self.claims, plan.shards, 0..) |claim, descriptor, index| {
            try claim.validate();
            if (!std.meta.eql(
                claim.source_descriptor_identity,
                descriptor.identity,
            ) or !std.meta.eql(
                claim.source_plan_identity,
                plan.identity,
            ) or !std.meta.eql(
                claim.execution_profile_identity,
                execution_profile.identity,
            ) or
                descriptor.shard_index != index)
            {
                return error.InvalidDegree5OrderedFreshBatch;
            }
        }
    }

    pub fn deinit(self: *OwnedFreshBatchV1) void {
        self.allocator.free(self.claims);
        self.* = undefined;
    }
};

pub fn provePreparedParallel(
    comptime ProducerEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: provider.VerifierProgramAuthorityV2,
    profile: provider.ExecutionProfileV2,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    prepared: *prepared_mod.OwnedPreparedBatchV1(ProducerEngine),
    execution: *const execution_mod.AuthorityV1,
) !OwnedEncodedBatchV1(ProducerEngine) {
    return provePreparedParallelInternal(
        ProducerEngine,
        allocator,
        pcs_config,
        program,
        profile,
        plan,
        calls,
        null,
        prepared,
        execution,
    );
}

pub fn provePreparedParallelValidated(
    comptime ProducerEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: provider.VerifierProgramAuthorityV2,
    profile: provider.ExecutionProfileV2,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    validated_calls: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    prepared: *prepared_mod.OwnedPreparedBatchV1(ProducerEngine),
    execution: *const execution_mod.AuthorityV1,
) !OwnedEncodedBatchV1(ProducerEngine) {
    return provePreparedParallelInternal(
        ProducerEngine,
        allocator,
        pcs_config,
        program,
        profile,
        plan,
        calls,
        validated_calls,
        prepared,
        execution,
    );
}

fn provePreparedParallelInternal(
    comptime ProducerEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: provider.VerifierProgramAuthorityV2,
    profile: provider.ExecutionProfileV2,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    validated_calls: ?*const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    prepared: *prepared_mod.OwnedPreparedBatchV1(ProducerEngine),
    execution: *const execution_mod.AuthorityV1,
) !OwnedEncodedBatchV1(ProducerEngine) {
    if (validated_calls) |validated|
        try validated.validateBorrowed(plan, calls)
    else
        try plan.validate(calls);
    try execution.validateAgainstPlan(plan);
    const expected_profile = try execution.executionProfile(program);
    if (!std.meta.eql(profile, expected_profile))
        return error.Degree5ProviderBatchExecutionProfileMismatch;
    if (validated_calls) |validated|
        try prepared.validatePreparedValidated(
            program,
            plan,
            calls,
            validated,
            execution,
        )
    else
        try prepared.validatePrepared(program, plan, calls, execution);

    const shards = try allocator.alloc(EncodedShardV1, plan.shards.len);
    errdefer allocator.free(shards);
    const live = try allocator.alloc(bool, shards.len);
    errdefer allocator.free(live);
    @memset(live, false);
    const failures = try allocator.alloc(?anyerror, shards.len);
    defer allocator.free(failures);
    @memset(failures, null);
    var owned = true;
    errdefer if (owned) for (shards, live) |shard, is_live|
        if (is_live) std.heap.smp_allocator.free(shard.canonical_proof_bytes);

    var shared = ProveShared(ProducerEngine){
        .pcs_config = pcs_config,
        .program = program,
        .profile = profile,
        .plan = plan,
        .calls = calls,
        .validated_calls = validated_calls,
        .transactions = prepared.transactions,
        .shards = shards,
        .live = live,
        .failures = failures,
    };
    try runWorkers(execution.concurrent_owners, &shared, @TypeOf(shared).run);
    for (failures) |failure| if (failure) |err| return err;
    for (live) |is_live| if (!is_live)
        return error.MissingDegree5OrderedProof;
    try prepared.validateConsumed();

    var result = OwnedEncodedBatchV1(ProducerEngine){
        .allocator = allocator,
        .item_allocator = std.heap.smp_allocator,
        .shards = shards,
        .live = live,
        .execution_identity = profile.identity,
    };
    try result.validateCanonical(plan);
    owned = false;
    return result;
}

pub fn verifyFreshParallel(
    comptime ProducerEngine: type,
    comptime CpuVerifierEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: provider.VerifierProgramAuthorityV2,
    profile: provider.ExecutionProfileV2,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    proofs: *const OwnedEncodedBatchV1(ProducerEngine),
    execution: *const execution_mod.AuthorityV1,
) !OwnedFreshBatchV1 {
    return verifyFreshParallelInternal(
        ProducerEngine,
        CpuVerifierEngine,
        allocator,
        pcs_config,
        program,
        profile,
        plan,
        calls,
        null,
        proofs,
        execution,
    );
}

pub fn verifyFreshParallelValidated(
    comptime ProducerEngine: type,
    comptime CpuVerifierEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: provider.VerifierProgramAuthorityV2,
    profile: provider.ExecutionProfileV2,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    validated_calls: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    proofs: *const OwnedEncodedBatchV1(ProducerEngine),
    execution: *const execution_mod.AuthorityV1,
) !OwnedFreshBatchV1 {
    return verifyFreshParallelInternal(
        ProducerEngine,
        CpuVerifierEngine,
        allocator,
        pcs_config,
        program,
        profile,
        plan,
        calls,
        validated_calls,
        proofs,
        execution,
    );
}

fn verifyFreshParallelInternal(
    comptime ProducerEngine: type,
    comptime CpuVerifierEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    program: provider.VerifierProgramAuthorityV2,
    profile: provider.ExecutionProfileV2,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    validated_calls: ?*const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    proofs: *const OwnedEncodedBatchV1(ProducerEngine),
    execution: *const execution_mod.AuthorityV1,
) !OwnedFreshBatchV1 {
    comptime {
        if (ProducerEngine.Hasher != CpuVerifierEngine.Hasher or
            ProducerEngine.Channel != CpuVerifierEngine.Channel or
            ProducerEngine.MerkleChannel != CpuVerifierEngine.MerkleChannel)
        {
            @compileError("D5 producer and cold verifier transcript types differ");
        }
    }
    if (validated_calls) |validated|
        try validated.validateBorrowed(plan, calls)
    else
        try plan.validate(calls);
    try execution.validateAgainstPlan(plan);
    const expected_profile = try execution.executionProfile(program);
    if (!std.meta.eql(profile, expected_profile))
        return error.Degree5ProviderBatchExecutionProfileMismatch;
    try proofs.validateCanonical(plan);

    const claims = try allocator.alloc(
        provider.FreshVerifiedShardV2,
        proofs.shards.len,
    );
    errdefer allocator.free(claims);
    const live = try allocator.alloc(bool, claims.len);
    defer allocator.free(live);
    @memset(live, false);
    const failures = try allocator.alloc(?anyerror, claims.len);
    defer allocator.free(failures);
    @memset(failures, null);

    var shared = VerifyShared(ProducerEngine, CpuVerifierEngine){
        .pcs_config = pcs_config,
        .program = program,
        .profile = profile,
        .plan = plan,
        .calls = calls,
        .validated_calls = validated_calls,
        .proofs = proofs,
        .claims = claims,
        .live = live,
        .failures = failures,
    };
    try runWorkers(execution.concurrent_owners, &shared, @TypeOf(shared).run);
    for (failures) |failure| if (failure) |err| return err;
    for (live) |is_live| if (!is_live)
        return error.MissingDegree5OrderedFreshClaim;

    var result = OwnedFreshBatchV1{ .allocator = allocator, .claims = claims };
    try result.validateAgainst(plan, profile);
    return result;
}

fn ProveShared(comptime Engine: type) type {
    return struct {
        pcs_config: core_pcs.PcsConfig,
        program: provider.VerifierProgramAuthorityV2,
        profile: provider.ExecutionProfileV2,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        validated_calls: ?*const provider_authority.OwnedValidatedPlanCallAuthorityV1,
        transactions: []prepared_transaction.PreparedStageATransactionV1(Engine),
        shards: []EncodedShardV1,
        live: []bool,
        failures: []?anyerror,
        next: std.atomic.Value(usize) = .init(0),

        const Self = @This();

        fn run(self: *Self) void {
            while (true) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.shards.len) return;
                self.prove(index) catch |err| {
                    self.failures[index] = err;
                    continue;
                };
            }
        }

        fn prove(self: *Self, index: usize) !void {
            var output = if (self.validated_calls) |validated|
                try provider.proveShardPreparedValidatedV2(
                    Engine,
                    std.heap.smp_allocator,
                    self.pcs_config,
                    self.program,
                    self.profile,
                    self.plan,
                    self.calls,
                    validated,
                    @intCast(index),
                    &self.transactions[index],
                )
            else
                try provider.proveShardPreparedV2(
                    Engine,
                    std.heap.smp_allocator,
                    self.pcs_config,
                    self.program,
                    self.profile,
                    self.plan,
                    self.calls,
                    @intCast(index),
                    &self.transactions[index],
                );
            defer output.proof.deinit(std.heap.smp_allocator);
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(std.heap.smp_allocator);
            var bounded_writer = BoundedProofWriterV1{
                .allocator = std.heap.smp_allocator,
                .bytes = &encoded,
                .maximum_len = @intCast(
                    execution_mod.MAX_CANONICAL_PROOF_BYTES_PER_SHARD,
                ),
            };
            try postcard.serializeProof(
                Engine.Hasher,
                &bounded_writer,
                output.proof,
            );
            const bytes = try encoded.toOwnedSlice(std.heap.smp_allocator);
            errdefer std.heap.smp_allocator.free(bytes);
            self.shards[index] = .{
                .statement = output.statement,
                .execution_profile_identity = output.execution_profile_identity,
                .canonical_proof_bytes = bytes,
                .canonical_proof_sha256 = sha256(bytes),
            };
            self.live[index] = true;
        }
    };
}

fn VerifyShared(
    comptime ProducerEngine: type,
    comptime CpuVerifierEngine: type,
) type {
    return struct {
        pcs_config: core_pcs.PcsConfig,
        program: provider.VerifierProgramAuthorityV2,
        profile: provider.ExecutionProfileV2,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        validated_calls: ?*const provider_authority.OwnedValidatedPlanCallAuthorityV1,
        proofs: *const OwnedEncodedBatchV1(ProducerEngine),
        claims: []provider.FreshVerifiedShardV2,
        live: []bool,
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
            var stream = std.io.fixedBufferStream(
                self.proofs.shards[index].canonical_proof_bytes,
            );
            const proof = try postcard.deserializeProof(
                CpuVerifierEngine.Hasher,
                std.heap.smp_allocator,
                stream.reader(),
            );
            if (stream.pos != self.proofs.shards[index].canonical_proof_bytes.len) {
                var owned = proof;
                owned.deinit(std.heap.smp_allocator);
                return error.TrailingDegree5OrderedProofBytes;
            }
            self.claims[index] = if (self.validated_calls) |validated|
                try provider.verifyShardFreshValidatedV2(
                    CpuVerifierEngine,
                    std.heap.smp_allocator,
                    self.pcs_config,
                    self.program,
                    self.profile,
                    self.plan,
                    self.calls,
                    validated,
                    self.proofs.shards[index].statement,
                    proof,
                )
            else
                try provider.verifyShardFreshV2(
                    CpuVerifierEngine,
                    std.heap.smp_allocator,
                    self.pcs_config,
                    self.program,
                    self.profile,
                    self.plan,
                    self.calls,
                    self.proofs.shards[index].statement,
                    proof,
                );
            self.live[index] = true;
        }
    };
}

fn runWorkers(worker_count: u16, context: anytype, comptime run: anytype) !void {
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

const BoundedProofWriterV1 = struct {
    allocator: std.mem.Allocator,
    bytes: *std.ArrayList(u8),
    maximum_len: usize,

    pub fn writeByte(self: *BoundedProofWriterV1, byte: u8) !void {
        if (self.bytes.items.len >= self.maximum_len)
            return error.Degree5CanonicalProofTooLarge;
        try self.bytes.append(self.allocator, byte);
    }

    pub fn writeAll(self: *BoundedProofWriterV1, source: []const u8) !void {
        const remaining = self.maximum_len - self.bytes.items.len;
        if (source.len > remaining)
            return error.Degree5CanonicalProofTooLarge;
        try self.bytes.appendSlice(self.allocator, source);
    }
};

fn sha256(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}
