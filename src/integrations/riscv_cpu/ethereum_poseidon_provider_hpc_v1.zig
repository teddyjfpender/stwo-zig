//! Opt-in provider-side parallelism with explicit host-memory admission.
//!
//! Stage-A commitments and provider proofs are independent by shard ordinal.
//! This module makes that existing property available to integration tools
//! without changing the serial product route.  Every raw proof is published
//! create-only before any fresh-verification claim exists; callers must admit
//! the results in canonical ordinal order with the cold verifier below.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const work_pool = @import("stwo_prover_engine").work_pool;

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const proof_artifact_v1 = @import("ethereum_poseidon_provider_proof_artifact_v1.zig");
const proof_artifact = @import("ethereum_poseidon_provider_proof_artifact_v2.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const harness = frontend.testing.narrow_memory_provider_proof_harness;
const joint = frontend.testing.narrow_memory_provider_joint_protocol;
const joint_v2 = frontend.testing.narrow_memory_provider_joint_proof_v2;
const omitted_v1 = frontend.testing.narrow_memory_provider_ethereum_omit_proof_v1;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;

pub const Engine = support.RecursiveEngine;
pub const max_workers: u32 = 4;
pub const default_host_byte_budget: u64 = 48 * 1024 * 1024 * 1024;
pub const default_controller_reserve_bytes: u64 = 8 * 1024 * 1024 * 1024;
pub const default_worker_rss_budget_bytes: u64 = 10 * 1024 * 1024 * 1024;
pub const Digest = [32]u8;

pub const WorkerAdmissionRequestV1 = struct {
    requested_workers: u32,
    available_cpu_workers: u32,
    work_items: u32,
    host_byte_budget: u64,
    controller_reserve_bytes: u64,
    worker_rss_budget_bytes: u64,
};

/// Controller-owned memory admission. `worker_rss_budget_bytes` is an
/// explicit operational bound, not a value inferred from the host. External
/// process supervisors may additionally enforce the same bound per child.
pub const WorkerAdmissionV1 = struct {
    format: u32,
    requested_workers: u32,
    admitted_workers: u32,
    available_cpu_workers: u32,
    work_items: u32,
    host_byte_budget: u64,
    controller_reserve_bytes: u64,
    worker_rss_budget_bytes: u64,
    concurrent_worker_reservation_bytes: u64,
    identity: Digest,

    pub fn create(request: WorkerAdmissionRequestV1) !WorkerAdmissionV1 {
        if (request.requested_workers == 0 or
            request.requested_workers > max_workers or
            request.available_cpu_workers == 0 or
            request.work_items == 0 or
            request.host_byte_budget == 0 or
            request.controller_reserve_bytes >= request.host_byte_budget or
            request.worker_rss_budget_bytes == 0)
        {
            return error.InvalidProviderWorkerAdmission;
        }
        const worker_budget = request.host_byte_budget -
            request.controller_reserve_bytes;
        const memory_workers = worker_budget /
            request.worker_rss_budget_bytes;
        const admitted_u64 = @min(
            @as(u64, request.requested_workers),
            @min(
                @as(u64, request.available_cpu_workers),
                @min(@as(u64, request.work_items), memory_workers),
            ),
        );
        if (admitted_u64 == 0) return error.ProviderWorkerBudgetExceeded;
        const admitted = std.math.cast(u32, admitted_u64) orelse
            return error.ProviderWorkerBudgetExceeded;
        const reservation = std.math.mul(
            u64,
            admitted,
            request.worker_rss_budget_bytes,
        ) catch return error.ProviderWorkerBudgetExceeded;
        if (reservation > worker_budget)
            return error.ProviderWorkerBudgetExceeded;
        var result = WorkerAdmissionV1{
            .format = 1,
            .requested_workers = request.requested_workers,
            .admitted_workers = admitted,
            .available_cpu_workers = request.available_cpu_workers,
            .work_items = request.work_items,
            .host_byte_budget = request.host_byte_budget,
            .controller_reserve_bytes = request.controller_reserve_bytes,
            .worker_rss_budget_bytes = request.worker_rss_budget_bytes,
            .concurrent_worker_reservation_bytes = reservation,
            .identity = undefined,
        };
        result.identity = admissionIdentity(result);
        return result;
    }

    pub fn validate(self: WorkerAdmissionV1) !void {
        const expected = try create(.{
            .requested_workers = self.requested_workers,
            .available_cpu_workers = self.available_cpu_workers,
            .work_items = self.work_items,
            .host_byte_budget = self.host_byte_budget,
            .controller_reserve_bytes = self.controller_reserve_bytes,
            .worker_rss_budget_bytes = self.worker_rss_budget_bytes,
        });
        if (!std.meta.eql(self, expected))
            return error.InvalidProviderWorkerAdmission;
    }
};

pub const RawWorkerAdmissionRequestV1 = struct {
    requested_concurrent_jobs: u32,
    available_cpu_workers: u32,
    work_items: u32,
    per_job_engine_workers: u32,
    host_byte_budget: u64,
    controller_reserve_bytes: u64,
    per_job_rss_budget_bytes: u64,
};

/// Admission for independent raw proofs. Each outer job owns a private,
/// proof-scoped engine pool, so the aggregate CPU and RSS reservations are
/// explicit before any proof or output publication begins.
pub const RawWorkerAdmissionV1 = struct {
    format: u32,
    requested_concurrent_jobs: u32,
    admitted_concurrent_jobs: u32,
    available_cpu_workers: u32,
    work_items: u32,
    per_job_engine_workers: u32,
    aggregate_engine_workers: u32,
    host_byte_budget: u64,
    controller_reserve_bytes: u64,
    per_job_rss_budget_bytes: u64,
    aggregate_rss_reservation_bytes: u64,
    aggregate_engine_stack_reservation_bytes: u64,
    identity: Digest,

    pub fn create(request: RawWorkerAdmissionRequestV1) !RawWorkerAdmissionV1 {
        if (request.requested_concurrent_jobs == 0 or
            request.requested_concurrent_jobs > max_workers or
            request.available_cpu_workers == 0 or request.work_items == 0 or
            request.per_job_engine_workers == 0 or
            request.per_job_engine_workers > work_pool.MAX_WORKERS or
            request.host_byte_budget == 0 or
            request.controller_reserve_bytes >= request.host_byte_budget or
            request.per_job_rss_budget_bytes == 0)
        {
            return error.InvalidRawProviderWorkerAdmission;
        }
        const helper_count = request.per_job_engine_workers - 1;
        const stack_reservation_per_job = std.math.mul(
            u64,
            helper_count,
            work_pool.WORKER_STACK_SIZE,
        ) catch return error.RawProviderWorkerBudgetExceeded;
        if (stack_reservation_per_job > request.per_job_rss_budget_bytes)
            return error.RawProviderWorkerBudgetExceeded;
        const memory_slots = (request.host_byte_budget -
            request.controller_reserve_bytes) / request.per_job_rss_budget_bytes;
        const cpu_slots = request.available_cpu_workers /
            request.per_job_engine_workers;
        const admitted_u64 = @min(
            @as(u64, request.requested_concurrent_jobs),
            @min(
                @as(u64, request.work_items),
                @min(@as(u64, cpu_slots), memory_slots),
            ),
        );
        if (admitted_u64 == 0) return error.RawProviderWorkerBudgetExceeded;
        const admitted = std.math.cast(u32, admitted_u64) orelse
            return error.RawProviderWorkerBudgetExceeded;
        const aggregate_engine_workers = std.math.mul(
            u32,
            admitted,
            request.per_job_engine_workers,
        ) catch return error.RawProviderWorkerBudgetExceeded;
        const aggregate_rss = std.math.mul(
            u64,
            admitted,
            request.per_job_rss_budget_bytes,
        ) catch return error.RawProviderWorkerBudgetExceeded;
        const aggregate_stacks = std.math.mul(
            u64,
            admitted,
            stack_reservation_per_job,
        ) catch return error.RawProviderWorkerBudgetExceeded;
        var result = RawWorkerAdmissionV1{
            .format = 1,
            .requested_concurrent_jobs = request.requested_concurrent_jobs,
            .admitted_concurrent_jobs = admitted,
            .available_cpu_workers = request.available_cpu_workers,
            .work_items = request.work_items,
            .per_job_engine_workers = request.per_job_engine_workers,
            .aggregate_engine_workers = aggregate_engine_workers,
            .host_byte_budget = request.host_byte_budget,
            .controller_reserve_bytes = request.controller_reserve_bytes,
            .per_job_rss_budget_bytes = request.per_job_rss_budget_bytes,
            .aggregate_rss_reservation_bytes = aggregate_rss,
            .aggregate_engine_stack_reservation_bytes = aggregate_stacks,
            .identity = undefined,
        };
        result.identity = rawAdmissionIdentity(result);
        return result;
    }

    pub fn validate(self: RawWorkerAdmissionV1) !void {
        const expected = try create(.{
            .requested_concurrent_jobs = self.requested_concurrent_jobs,
            .available_cpu_workers = self.available_cpu_workers,
            .work_items = self.work_items,
            .per_job_engine_workers = self.per_job_engine_workers,
            .host_byte_budget = self.host_byte_budget,
            .controller_reserve_bytes = self.controller_reserve_bytes,
            .per_job_rss_budget_bytes = self.per_job_rss_budget_bytes,
        });
        if (!std.meta.eql(self, expected))
            return error.InvalidRawProviderWorkerAdmission;
    }
};

pub fn commitStageAParallel(
    comptime ProvingEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core.pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    admission: WorkerAdmissionV1,
) ![]harness.StageACommitment(ProvingEngine) {
    try plan.validate(calls);
    try admission.validate();
    if (admission.work_items != plan.shard_count)
        return error.ProviderWorkerAdmissionWorkMismatch;

    const roots = try allocator.alloc(
        harness.StageACommitment(ProvingEngine),
        plan.shards.len,
    );
    errdefer allocator.free(roots);
    const failures = try allocator.alloc(?anyerror, plan.shards.len);
    defer allocator.free(failures);
    @memset(failures, null);
    var shared = StageAShared(ProvingEngine){
        .pcs_config = pcs_config,
        .plan = plan,
        .calls = calls,
        .roots = roots,
        .failures = failures,
    };
    try runWorkers(admission.admitted_workers, &shared, @TypeOf(shared).run);
    for (failures) |failure| if (failure) |err| return err;
    return roots;
}

pub fn commitStageAParallelBounded(
    comptime ProvingEngine: type,
    allocator: std.mem.Allocator,
    pcs_config: core.pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    admission: RawWorkerAdmissionV1,
) ![]harness.StageACommitment(ProvingEngine) {
    try plan.validate(calls);
    try admission.validate();
    if (admission.work_items != plan.shard_count)
        return error.ProviderWorkerAdmissionWorkMismatch;

    const roots = try allocator.alloc(
        harness.StageACommitment(ProvingEngine),
        plan.shards.len,
    );
    errdefer allocator.free(roots);
    const failures = try allocator.alloc(?anyerror, plan.shards.len);
    defer allocator.free(failures);
    @memset(failures, null);
    var shared = StageABoundedShared(ProvingEngine){
        .pcs_config = pcs_config,
        .plan = plan,
        .calls = calls,
        .roots = roots,
        .failures = failures,
        .per_job_engine_workers = admission.per_job_engine_workers,
    };
    try runWorkers(
        admission.admitted_concurrent_jobs,
        &shared,
        @TypeOf(shared).run,
    );
    for (failures) |failure| if (failure) |err| return err;
    return roots;
}

pub const RawProviderJobV1 = struct {
    ordinal: u32,
    proof_path: []const u8,
};

pub const RawProviderPublicationV1 = struct {
    ordinal: u32,
    statement: joint_v2.ProviderStatementV2,
    proof: evidence.FileIdentity,
    prove_wall_ns: u64,
};

pub const JointSourceV1 = struct {
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest: *const joint.JointManifest(Engine),
    shared: joint.SharedRelationAuthorityV1,

    pub fn validate(self: JointSourceV1) !void {
        try self.manifest.validate(self.plan, self.calls);
        if (self.shared.interaction_pow_bits == 0 or
            !std.meta.eql(
                self.shared.manifest_identity,
                self.manifest.identity,
            ))
        {
            return error.InvalidProviderHpcSource;
        }
    }
};

/// Proves V2 provider jobs against the research joint caller. The same worker
/// controller is used by the concrete omitted-Ethereum wrapper below.
pub fn proveJointRawParallel(
    allocator: std.mem.Allocator,
    source: JointSourceV1,
    jobs: []const RawProviderJobV1,
    admission: WorkerAdmissionV1,
) ![]RawProviderPublicationV1 {
    try source.validate();
    return proveRawParallel(
        JointKernel,
        allocator,
        source,
        jobs,
        admission,
    );
}

/// Concrete provider-free Ethereum adapter. It performs no fresh admission;
/// each output remains an inert raw proof until the omission-aware verifier
/// consumes it in canonical ordinal order.
pub fn proveOmittedRawParallel(
    allocator: std.mem.Allocator,
    source: omitted_v1.Source(Engine),
    jobs: []const RawProviderJobV1,
    admission: WorkerAdmissionV1,
) ![]RawProviderPublicationV1 {
    try source.validate();
    return proveRawParallel(
        OmittedKernel,
        allocator,
        source,
        jobs,
        admission,
    );
}

pub fn proveJointRawParallelBounded(
    allocator: std.mem.Allocator,
    source: JointSourceV1,
    jobs: []const RawProviderJobV1,
    admission: RawWorkerAdmissionV1,
) ![]RawProviderPublicationV1 {
    try source.validate();
    return proveRawParallelBounded(
        JointKernel,
        allocator,
        source,
        jobs,
        admission,
    );
}

pub fn proveOmittedRawParallelBounded(
    allocator: std.mem.Allocator,
    source: omitted_v1.Source(Engine),
    jobs: []const RawProviderJobV1,
    admission: RawWorkerAdmissionV1,
) ![]RawProviderPublicationV1 {
    try source.validate();
    return proveRawParallelBounded(
        OmittedKernel,
        allocator,
        source,
        jobs,
        admission,
    );
}

pub const FreshProviderCheckV1 = struct {
    claim: joint_v2.FreshProviderClaimV2,
    verify_timing: evidence.Timing,
    canonical_proof_bytes_equal: bool,
    stage_a_roots_equal: bool,
    statement_identity_equal: bool,
    native_claim_equal: bool,
    ordered_claim_equal: bool,

    pub fn validate(self: FreshProviderCheckV1) !void {
        try self.claim.validate();
        if (self.verify_timing.wall_ns == 0 or
            !self.canonical_proof_bytes_equal or
            !self.stage_a_roots_equal or
            !self.statement_identity_equal or
            !self.native_claim_equal or
            !self.ordered_claim_equal)
        {
            return error.ProviderHpcFreshCheckFailed;
        }
    }
};

/// Cold-reopens one raw proof and mints a fresh claim. Re-serialization must
/// reproduce the exact bytes before the proof is consumed by verification.
pub fn verifyJointRawFresh(
    allocator: std.mem.Allocator,
    source: JointSourceV1,
    raw: RawProviderPublicationV1,
) !FreshProviderCheckV1 {
    try source.validate();
    if (raw.ordinal != raw.statement.shard_index or
        raw.ordinal >= source.plan.shard_count)
    {
        return error.InvalidRawProviderPublication;
    }
    const bytes = try artifact_io.readFileBounded(
        allocator,
        raw.proof.path,
        proof_artifact_v1.max_proof_bytes,
    );
    defer allocator.free(bytes);
    const actual_proof = evidence.identity(raw.proof.path, bytes);
    if (actual_proof.bytes != raw.proof.bytes or
        !std.mem.eql(u8, actual_proof.path, raw.proof.path) or
        !std.mem.eql(u8, &actual_proof.sha256, &raw.proof.sha256))
    {
        return error.RawProviderProofIdentityMismatch;
    }
    const proof = try proof_artifact.deserializeProof(
        allocator,
        bytes,
        try proof_artifact.proofShape(raw.statement),
    );
    const commitments = proof.commitment_scheme_proof.commitments.items;
    const provider = source.manifest.providers[@intCast(raw.ordinal)];
    const roots_equal = commitments.len >= 2 and
        std.meta.eql(commitments[0], provider.preprocessed_root) and
        std.meta.eql(commitments[1], provider.main_root);
    const canonical = try proof_artifact.serializeProofAlloc(
        allocator,
        proof,
        try proof_artifact.proofShape(raw.statement),
    );
    defer allocator.free(canonical);
    const canonical_equal = std.mem.eql(u8, bytes, canonical);

    var clock = try evidence.Clock.start();
    const claim = try joint_v2.verifyProviderFreshV2(
        Engine,
        allocator,
        support.recursive_pcs_config,
        source.plan,
        source.calls,
        source.manifest,
        source.shared,
        raw.statement,
        proof,
    );
    const timing = try clock.finish();
    const result = FreshProviderCheckV1{
        .claim = claim,
        .verify_timing = timing,
        .canonical_proof_bytes_equal = canonical_equal,
        .stage_a_roots_equal = roots_equal,
        .statement_identity_equal = std.meta.eql(
            raw.statement.identity,
            joint_v2.providerStatementIdentity(raw.statement),
        ),
        .native_claim_equal = std.meta.eql(
            claim.native_claim.claims,
            raw.statement.claims,
        ),
        .ordered_claim_equal = std.meta.eql(
            claim.ordered_call_claim,
            raw.statement.ordered_call_claim,
        ),
    };
    try result.validate();
    return result;
}

fn StageAShared(comptime ProvingEngine: type) type {
    return struct {
        pcs_config: core.pcs.PcsConfig,
        plan: *const authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        roots: []harness.StageACommitment(ProvingEngine),
        failures: []?anyerror,
        next: std.atomic.Value(usize) = .init(0),

        const Self = @This();

        fn run(self: *Self) void {
            while (true) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.roots.len) return;
                self.roots[index] = harness.commitStageA(
                    ProvingEngine,
                    std.heap.smp_allocator,
                    self.pcs_config,
                    self.plan,
                    self.calls,
                    @intCast(index),
                ) catch |err| {
                    self.failures[index] = err;
                    continue;
                };
            }
        }
    };
}

fn StageABoundedShared(comptime ProvingEngine: type) type {
    return struct {
        pcs_config: core.pcs.PcsConfig,
        plan: *const authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        roots: []harness.StageACommitment(ProvingEngine),
        failures: []?anyerror,
        per_job_engine_workers: u32,
        next: std.atomic.Value(usize) = .init(0),

        const Self = @This();

        fn run(self: *Self) void {
            while (true) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.roots.len) return;
                self.commit(index) catch |err| {
                    self.failures[index] = err;
                    continue;
                };
            }
        }

        fn commit(self: *Self, index: usize) !void {
            var pool: work_pool.WorkPool = undefined;
            try pool.initInPlaceWithOptions(.{
                .worker_count = self.per_job_engine_workers,
            });
            defer pool.deinit();
            var binding = try work_pool.ScopedPoolBinding.init(&pool);
            defer binding.deinit();
            self.roots[index] = try harness.commitStageA(
                ProvingEngine,
                std.heap.smp_allocator,
                self.pcs_config,
                self.plan,
                self.calls,
                @intCast(index),
            );
        }
    };
}

fn proveRawParallel(
    comptime Kernel: type,
    allocator: std.mem.Allocator,
    source: Kernel.Source,
    jobs: []const RawProviderJobV1,
    admission: WorkerAdmissionV1,
) ![]RawProviderPublicationV1 {
    try admission.validate();
    if (admission.work_items != jobs.len or jobs.len == 0)
        return error.ProviderWorkerAdmissionWorkMismatch;
    try validateJobs(jobs, Kernel.shardCount(source));

    const slots = try allocator.alloc(RawSlot, jobs.len);
    defer allocator.free(slots);
    @memset(slots, .{});
    var shared = RawShared(Kernel){
        .source = source,
        .jobs = jobs,
        .slots = slots,
    };
    try runWorkers(admission.admitted_workers, &shared, @TypeOf(shared).run);
    for (slots) |slot| if (slot.failure) |err| return err;
    const result = try allocator.alloc(RawProviderPublicationV1, slots.len);
    errdefer allocator.free(result);
    for (slots, result) |slot, *destination|
        destination.* = slot.publication orelse
            return error.MissingRawProviderPublication;
    return result;
}

fn proveRawParallelBounded(
    comptime Kernel: type,
    allocator: std.mem.Allocator,
    source: Kernel.Source,
    jobs: []const RawProviderJobV1,
    admission: RawWorkerAdmissionV1,
) ![]RawProviderPublicationV1 {
    try admission.validate();
    if (admission.work_items != jobs.len or jobs.len == 0)
        return error.ProviderWorkerAdmissionWorkMismatch;
    try validateCanonicalJobs(jobs, Kernel.shardCount(source));

    const slots = try allocator.alloc(RawSlot, jobs.len);
    defer allocator.free(slots);
    @memset(slots, .{});
    var shared = RawBoundedShared(Kernel){
        .source = source,
        .jobs = jobs,
        .slots = slots,
        .per_job_engine_workers = admission.per_job_engine_workers,
    };
    try runWorkers(
        admission.admitted_concurrent_jobs,
        &shared,
        @TypeOf(shared).run,
    );
    for (slots) |slot| if (slot.failure) |err| return err;
    const result = try allocator.alloc(RawProviderPublicationV1, slots.len);
    errdefer allocator.free(result);
    for (slots, result) |slot, *destination|
        destination.* = slot.publication orelse
            return error.MissingRawProviderPublication;
    return result;
}

const RawSlot = struct {
    publication: ?RawProviderPublicationV1 = null,
    failure: ?anyerror = null,
};

fn RawShared(comptime Kernel: type) type {
    return struct {
        source: Kernel.Source,
        jobs: []const RawProviderJobV1,
        slots: []RawSlot,
        next: std.atomic.Value(usize) = .init(0),

        const Self = @This();

        fn run(self: *Self) void {
            while (true) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.jobs.len) return;
                self.prove(index) catch |err| {
                    self.slots[index].failure = err;
                    continue;
                };
            }
        }

        fn prove(self: *Self, index: usize) !void {
            const job = self.jobs[index];
            var timer = try std.time.Timer.start();
            var output = try Kernel.prove(
                std.heap.smp_allocator,
                self.source,
                job.ordinal,
            );
            defer output.proof.deinit(std.heap.smp_allocator);
            const proof_bytes = try proof_artifact.serializeProofAlloc(
                std.heap.smp_allocator,
                output.proof,
                try proof_artifact.proofShape(output.statement),
            );
            defer std.heap.smp_allocator.free(proof_bytes);
            const wall_ns = timer.read();
            try artifact_io.publishCreateOnlyDurable(
                job.proof_path,
                proof_bytes,
            );
            self.slots[index].publication = .{
                .ordinal = job.ordinal,
                .statement = output.statement,
                .proof = evidence.identity(job.proof_path, proof_bytes),
                .prove_wall_ns = wall_ns,
            };
        }
    };
}

fn RawBoundedShared(comptime Kernel: type) type {
    return struct {
        source: Kernel.Source,
        jobs: []const RawProviderJobV1,
        slots: []RawSlot,
        per_job_engine_workers: u32,
        next: std.atomic.Value(usize) = .init(0),

        const Self = @This();

        fn run(self: *Self) void {
            while (true) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.jobs.len) return;
                self.prove(index) catch |err| {
                    self.slots[index].failure = err;
                    continue;
                };
            }
        }

        fn prove(self: *Self, index: usize) !void {
            var pool: work_pool.WorkPool = undefined;
            try pool.initInPlaceWithOptions(.{
                .worker_count = self.per_job_engine_workers,
            });
            defer pool.deinit();
            var binding = try work_pool.ScopedPoolBinding.init(&pool);
            defer binding.deinit();

            const job = self.jobs[index];
            var timer = try std.time.Timer.start();
            var output = try Kernel.prove(
                std.heap.smp_allocator,
                self.source,
                job.ordinal,
            );
            defer output.proof.deinit(std.heap.smp_allocator);
            const proof_bytes = try proof_artifact.serializeProofAlloc(
                std.heap.smp_allocator,
                output.proof,
                try proof_artifact.proofShape(output.statement),
            );
            defer std.heap.smp_allocator.free(proof_bytes);
            const wall_ns = timer.read();
            try artifact_io.publishCreateOnlyDurable(
                job.proof_path,
                proof_bytes,
            );
            self.slots[index].publication = .{
                .ordinal = job.ordinal,
                .statement = output.statement,
                .proof = evidence.identity(job.proof_path, proof_bytes),
                .prove_wall_ns = wall_ns,
            };
        }
    };
}

const JointKernel = struct {
    pub const Source = JointSourceV1;

    fn shardCount(source: Source) u32 {
        return source.plan.shard_count;
    }

    fn prove(
        allocator: std.mem.Allocator,
        source: Source,
        ordinal: u32,
    ) !joint_v2.ProviderProofOutputV2(Engine) {
        return joint_v2.proveProviderV2(
            Engine,
            allocator,
            support.recursive_pcs_config,
            source.plan,
            source.calls,
            source.manifest,
            source.shared,
            ordinal,
        );
    }
};

const OmittedKernel = struct {
    pub const Source = omitted_v1.Source(Engine);

    fn shardCount(source: Source) u32 {
        return source.plan.shard_count;
    }

    fn prove(
        allocator: std.mem.Allocator,
        source: Source,
        ordinal: u32,
    ) !omitted_v1.ProviderProofOutputV2(Engine) {
        return omitted_v1.proveProviderV2(
            Engine,
            allocator,
            support.recursive_pcs_config,
            source,
            ordinal,
        );
    }
};

fn runWorkers(
    admitted_workers: u32,
    context: anytype,
    comptime run: anytype,
) !void {
    if (admitted_workers == 0 or admitted_workers > max_workers)
        return error.InvalidProviderWorkerAdmission;
    if (admitted_workers == 1) {
        run(context);
        return;
    }
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{
        .allocator = std.heap.smp_allocator,
        .n_jobs = admitted_workers - 1,
    });
    defer pool.deinit();
    var wait_group: std.Thread.WaitGroup = .{};
    for (1..@as(usize, admitted_workers)) |_|
        pool.spawnWg(&wait_group, run, .{context});
    run(context);
    pool.waitAndWork(&wait_group);
}

fn validateJobs(jobs: []const RawProviderJobV1, shard_count: u32) !void {
    for (jobs, 0..) |job, index| {
        if (job.ordinal >= shard_count or
            !std.fs.path.isAbsolute(job.proof_path))
        {
            return error.InvalidRawProviderJob;
        }
        for (jobs[0..index]) |previous| {
            if (previous.ordinal == job.ordinal or
                std.mem.eql(u8, previous.proof_path, job.proof_path))
            {
                return error.DuplicateRawProviderJob;
            }
        }
    }
}

fn validateCanonicalJobs(
    jobs: []const RawProviderJobV1,
    shard_count: u32,
) !void {
    try validateJobs(jobs, shard_count);
    for (jobs[1..], jobs[0 .. jobs.len - 1]) |current, previous| {
        if (current.ordinal <= previous.ordinal)
            return error.NonCanonicalRawProviderJobs;
    }
}

fn admissionIdentity(value: WorkerAdmissionV1) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/ethereum/provider-hpc-worker-admission/v1\x00");
    hashInt(&hash, u32, value.format);
    hashInt(&hash, u32, value.requested_workers);
    hashInt(&hash, u32, value.admitted_workers);
    hashInt(&hash, u32, value.available_cpu_workers);
    hashInt(&hash, u32, value.work_items);
    hashInt(&hash, u64, value.host_byte_budget);
    hashInt(&hash, u64, value.controller_reserve_bytes);
    hashInt(&hash, u64, value.worker_rss_budget_bytes);
    hashInt(&hash, u64, value.concurrent_worker_reservation_bytes);
    return hash.finalResult();
}

fn rawAdmissionIdentity(value: RawWorkerAdmissionV1) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/ethereum/provider-hpc-raw-worker-admission/v1\x00");
    hashInt(&hash, u32, value.format);
    hashInt(&hash, u32, value.requested_concurrent_jobs);
    hashInt(&hash, u32, value.admitted_concurrent_jobs);
    hashInt(&hash, u32, value.available_cpu_workers);
    hashInt(&hash, u32, value.work_items);
    hashInt(&hash, u32, value.per_job_engine_workers);
    hashInt(&hash, u32, value.aggregate_engine_workers);
    hashInt(&hash, u64, value.host_byte_budget);
    hashInt(&hash, u64, value.controller_reserve_bytes);
    hashInt(&hash, u64, value.per_job_rss_budget_bytes);
    hashInt(&hash, u64, value.aggregate_rss_reservation_bytes);
    hashInt(&hash, u64, value.aggregate_engine_stack_reservation_bytes);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

test "provider HPC admission is finite and mutation closed" {
    const admission = try WorkerAdmissionV1.create(.{
        .requested_workers = 4,
        .available_cpu_workers = 18,
        .work_items = 10,
        .host_byte_budget = default_host_byte_budget,
        .controller_reserve_bytes = default_controller_reserve_bytes,
        .worker_rss_budget_bytes = default_worker_rss_budget_bytes,
    });
    try std.testing.expectEqual(@as(u32, 4), admission.admitted_workers);
    try admission.validate();
    var mutated = admission;
    mutated.admitted_workers = 3;
    try std.testing.expectError(
        error.InvalidProviderWorkerAdmission,
        mutated.validate(),
    );
    try std.testing.expectError(
        error.ProviderWorkerBudgetExceeded,
        WorkerAdmissionV1.create(.{
            .requested_workers = 1,
            .available_cpu_workers = 1,
            .work_items = 1,
            .host_byte_budget = 8,
            .controller_reserve_bytes = 4,
            .worker_rss_budget_bytes = 5,
        }),
    );
}

test "raw provider admission caps aggregate CPU stacks and RSS" {
    const admission = try RawWorkerAdmissionV1.create(.{
        .requested_concurrent_jobs = 2,
        .available_cpu_workers = 18,
        .work_items = 2,
        .per_job_engine_workers = 4,
        .host_byte_budget = default_host_byte_budget,
        .controller_reserve_bytes = default_controller_reserve_bytes,
        .per_job_rss_budget_bytes = default_worker_rss_budget_bytes,
    });
    try admission.validate();
    try std.testing.expectEqual(@as(u32, 2), admission.admitted_concurrent_jobs);
    try std.testing.expectEqual(@as(u32, 8), admission.aggregate_engine_workers);
    try std.testing.expectEqual(
        @as(u64, 20 * 1024 * 1024 * 1024),
        admission.aggregate_rss_reservation_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 6 * work_pool.WORKER_STACK_SIZE),
        admission.aggregate_engine_stack_reservation_bytes,
    );
    var mutated = admission;
    mutated.aggregate_engine_workers += 1;
    try std.testing.expectError(
        error.InvalidRawProviderWorkerAdmission,
        mutated.validate(),
    );
}

comptime {
    if (max_workers != 4 or poseidon2_air.N_MAIN_COLUMNS != 445 or
        joint_v2.provider_tree2_columns != 12 or
        omitted_v1.provider_tree2_columns != 12)
    {
        @compileError("provider HPC physical geometry drifted");
    }
}
