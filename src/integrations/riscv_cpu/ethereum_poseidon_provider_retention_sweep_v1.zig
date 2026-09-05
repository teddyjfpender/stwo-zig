//! Opt-in four-way `.always` versus `.never` provider retention sweep.

const std = @import("std");
const builtin = @import("builtin");
const postcard = @import("interop_postcard");
const frontend = @import("stwo_riscv_frontend");
const work_pool = @import("stwo_prover_engine").work_pool;

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const call_artifact = @import("ethereum_poseidon_provider_call_artifact_v1.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const geometry_snapshot = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");
const hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");
const batch_receipt = @import("ethereum_poseidon_provider_raw_batch_receipt_v2.zig");
const receipt = @import("ethereum_poseidon_provider_retention_sweep_receipt_v1.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const resource_usage = @import("resource_usage.zig");
const support = @import("ethereum_block_leaf_support.zig");
const topology_receipt = @import("ethereum_poseidon_provider_topology_sweep_receipt_v1.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const harness = frontend.testing.narrow_memory_provider_proof_harness;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;

const Engine = support.RecursiveEngine;
const arm_count = receipt.arm_count;
const proof_count = receipt.proof_count;

pub const execute_flag = "--run-retained-provider-retention-sweep-v1";

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var options = try Options.parse(allocator, arguments);
    defer options.deinit(allocator);
    var paths = try OutputPaths.init(allocator, options.output_root);
    defer paths.deinit(allocator);
    try paths.requireFresh();
    var total_deadline = Deadline{ .duration_ns = options.total_hard_cap_ns };
    try total_deadline.start();
    defer total_deadline.finish();
    var total_timer = try std.time.Timer.start();

    const metadata_bytes = try artifact_io.readFileBounded(
        allocator,
        options.call_artifact,
        call_artifact.max_metadata_bytes,
    );
    defer allocator.free(metadata_bytes);
    var parsed = try call_artifact.parse(allocator, metadata_bytes);
    defer parsed.deinit();
    const metadata_identity = evidence.identity(
        options.call_artifact,
        metadata_bytes,
    );
    const geometry_bytes = try support.readIdentity(
        allocator,
        parsed.value.geometry_snapshot,
        geometry_snapshot.max_snapshot_bytes,
    );
    defer allocator.free(geometry_bytes);
    var geometry = try geometry_snapshot.parse(allocator, geometry_bytes);
    defer geometry.deinit();
    const geometry_file = evidence.identity(
        parsed.value.geometry_snapshot.path,
        geometry_bytes,
    );
    const whole_resource = try resource.ProviderResourcePlanV1.create(
        &geometry.value,
        geometry_file.sha256,
    );
    var reopened = try call_artifact.reopen(
        allocator,
        parsed.value,
        &whole_resource,
    );
    defer reopened.deinit(allocator);
    const rows_per_shard = try powerOfTwo(options.log_size);
    const slice_count = std.math.mul(usize, rows_per_shard, proof_count) catch
        return error.ProviderBenchmarkSliceOverflow;
    const slice_end = std.math.add(
        usize,
        options.slice_offset,
        slice_count,
    ) catch return error.ProviderBenchmarkSliceOverflow;
    if (slice_end > reopened.calls.len)
        return error.ProviderBenchmarkSliceOutOfRange;
    const calls = reopened.calls[options.slice_offset..slice_end];
    var plan = try authority.ProviderShardPlanV1.create(
        allocator,
        reopened.session,
        calls,
        .{
            .logical_row_count = calls.len,
            .column_count = authority.main_column_count,
            .min_shard_log_size = options.log_size,
            .max_shard_log_size = options.log_size,
            .log_blowup_factor = support.recursive_pcs_config
                .fri_config.log_blowup_factor,
            .retention_policy = .never,
            .host_byte_budget = options.host_byte_budget,
            .reserved_host_bytes = options.controller_reserve_bytes,
            .requested_parallel_shards = proof_count,
        },
    );
    defer plan.deinit(allocator);
    if (plan.shard_count != proof_count)
        return error.ProviderBenchmarkShardCountMismatch;
    const cpu_workers = std.math.cast(u32, try std.Thread.getCpuCount()) orelse
        std.math.maxInt(u32);
    const admission = try hpc.RawWorkerAdmissionV1.create(.{
        .requested_concurrent_jobs = proof_count,
        .available_cpu_workers = cpu_workers,
        .work_items = proof_count,
        .per_job_engine_workers = 4,
        .host_byte_budget = options.host_byte_budget,
        .controller_reserve_bytes = options.controller_reserve_bytes,
        .per_job_rss_budget_bytes = options.per_job_rss_budget_bytes,
    });
    if (admission.admitted_concurrent_jobs != proof_count)
        return error.ProviderRetentionTopologyNotFullyAdmitted;

    var executions: [arm_count]ArmExecution = undefined;
    var completed: usize = 0;
    defer for (executions[0..completed]) |*execution|
        execution.deinit(allocator);
    const policies = [_]harness.CoefficientRetention{ .always, .never };
    for (policies, 0..) |policy, arm_index| {
        executions[arm_index] = try runArm(
            allocator,
            &plan,
            calls,
            paths.proofs[arm_index][0..],
            admission,
            policy,
            options.arm_hard_cap_ns,
        );
        completed += 1;
    }
    const total_wall_ns = total_timer.read();
    if (total_wall_ns > options.total_hard_cap_ns)
        return error.ProviderRetentionTotalDeadlineExceeded;

    const executable_sha256 = try support.executableSha256(allocator);
    const self_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_path);
    var self_file = try std.fs.openFileAbsolute(self_path, .{});
    defer self_file.close();
    const self_stat = try self_file.stat();
    const bytes = try encodeReceipt(
        allocator,
        options,
        parsed.value,
        metadata_identity,
        plan,
        admission,
        &executions,
        total_wall_ns,
        self_path,
        self_stat.size,
        executable_sha256,
    );
    defer allocator.free(bytes);
    try receipt.publishCreateOnly(paths.receipt_path, bytes);
}

fn runArm(
    allocator: std.mem.Allocator,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    proof_paths: []const []const u8,
    admission: hpc.RawWorkerAdmissionV1,
    retention: harness.CoefficientRetention,
    hard_cap_ns: u64,
) !ArmExecution {
    const before = resource_usage.capture();
    var total_clock = try evidence.Clock.start();
    var deadline = Deadline{ .duration_ns = hard_cap_ns };
    try deadline.start();
    defer deadline.finish();
    var proof_timer = try std.time.Timer.start();
    const publications = try proveParallel(
        allocator,
        plan,
        calls,
        proof_paths,
        admission,
        retention,
    );
    errdefer allocator.free(publications);
    const proof_wall_ns = proof_timer.read();
    const checks = try allocator.alloc(FreshCheck, publications.len);
    errdefer allocator.free(checks);
    var verify_timer = try std.time.Timer.start();
    for (checks, publications) |*check, publication| check.* =
        try verifyFresh(allocator, plan, calls, publication);
    const verify_wall_ns = verify_timer.read();
    const total = try total_clock.finish();
    if (total.wall_ns > hard_cap_ns) {
        allocator.free(checks);
        allocator.free(publications);
        return error.ProviderRetentionArmDeadlineExceeded;
    }
    return .{
        .checks = checks,
        .proof_batch_wall_ns = proof_wall_ns,
        .publications = publications,
        .resources = resource_usage.report(before, resource_usage.capture()),
        .total = total,
        .verify_wall_ns = verify_wall_ns,
    };
}

const Publication = struct {
    ordinal: u32,
    owner_telemetry: harness.OwnerTeardownTelemetryV1,
    proof: evidence.FileIdentity,
    prove_wall_ns: u64,
    roots: [harness.tree_count]Engine.Hasher.Hash,
    statement: harness.StatementV1,
};

const FreshCheck = struct {
    canonical_proof_bytes_equal: bool,
    roots_equal_proof: bool,
    timing: evidence.Timing,
};

const ArmExecution = struct {
    checks: []FreshCheck,
    proof_batch_wall_ns: u64,
    publications: []Publication,
    resources: resource_usage.Report,
    total: evidence.Timing,
    verify_wall_ns: u64,

    fn deinit(self: *ArmExecution, allocator: std.mem.Allocator) void {
        allocator.free(self.checks);
        allocator.free(self.publications);
        self.* = undefined;
    }
};

fn proveParallel(
    allocator: std.mem.Allocator,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    proof_paths: []const []const u8,
    admission: hpc.RawWorkerAdmissionV1,
    retention: harness.CoefficientRetention,
) ![]Publication {
    try admission.validate();
    if (proof_paths.len != proof_count or admission.work_items != proof_count)
        return error.ProviderRetentionWorkMismatch;
    const slots = try allocator.alloc(Slot, proof_count);
    defer allocator.free(slots);
    @memset(slots, .{});
    var shared = Shared{
        .admission = admission,
        .calls = calls,
        .paths = proof_paths,
        .plan = plan,
        .retention = retention,
        .slots = slots,
    };
    try runWorkers(admission.admitted_concurrent_jobs, &shared);
    for (slots) |slot| if (slot.failure) |failure| return failure;
    const result = try allocator.alloc(Publication, proof_count);
    errdefer allocator.free(result);
    for (slots, result) |slot, *publication| publication.* =
        slot.publication orelse return error.MissingProviderRetentionProof;
    return result;
}

const Slot = struct {
    failure: ?anyerror = null,
    publication: ?Publication = null,
};

const Shared = struct {
    admission: hpc.RawWorkerAdmissionV1,
    calls: []const poseidon2_air.Call,
    paths: []const []const u8,
    plan: *const authority.ProviderShardPlanV1,
    retention: harness.CoefficientRetention,
    slots: []Slot,
    next: std.atomic.Value(usize) = .init(0),

    fn run(self: *Shared) void {
        while (true) {
            const index = self.next.fetchAdd(1, .monotonic);
            if (index >= self.slots.len) return;
            self.prove(index) catch |err| {
                self.slots[index].failure = err;
                continue;
            };
        }
    }

    fn prove(self: *Shared, index: usize) !void {
        var pool: work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{
            .worker_count = self.admission.per_job_engine_workers,
        });
        defer pool.deinit();
        var binding = try work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var timer = try std.time.Timer.start();
        var output = try harness.proveShard(
            Engine,
            std.heap.smp_allocator,
            support.recursive_pcs_config,
            self.plan,
            self.calls,
            @intCast(index),
            self.retention,
            null,
        );
        defer output.proof.deinit(std.heap.smp_allocator);
        var encoded: std.ArrayList(u8) = .{};
        defer encoded.deinit(std.heap.smp_allocator);
        try postcard.serializeProof(
            Engine.Hasher,
            encoded.writer(std.heap.smp_allocator),
            output.proof,
        );
        const wall_ns = timer.read();
        try artifact_io.publishCreateOnlyDurable(self.paths[index], encoded.items);
        self.slots[index].publication = .{
            .ordinal = @intCast(index),
            .owner_telemetry = output.owner_telemetry,
            .proof = evidence.identity(self.paths[index], encoded.items),
            .prove_wall_ns = wall_ns,
            .roots = output.roots,
            .statement = output.statement,
        };
    }
};

fn runWorkers(count: u32, shared: *Shared) !void {
    if (count != proof_count) return error.ProviderRetentionWorkMismatch;
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{
        .allocator = std.heap.smp_allocator,
        .n_jobs = count - 1,
    });
    defer pool.deinit();
    var wait_group: std.Thread.WaitGroup = .{};
    for (1..@as(usize, count)) |_|
        pool.spawnWg(&wait_group, Shared.run, .{shared});
    shared.run();
    pool.waitAndWork(&wait_group);
}

fn verifyFresh(
    allocator: std.mem.Allocator,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    publication: Publication,
) !FreshCheck {
    const bytes = try artifact_io.readFileBounded(
        allocator,
        publication.proof.path,
        256 * 1024 * 1024,
    );
    defer allocator.free(bytes);
    const identity = evidence.identity(publication.proof.path, bytes);
    if (!std.meta.eql(identity, publication.proof))
        return error.ProviderRetentionProofIdentityMismatch;
    var stream = std.io.fixedBufferStream(bytes);
    var proof = try postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        stream.reader(),
    );
    var proof_owned = true;
    defer if (proof_owned) proof.deinit(allocator);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    const roots_equal = commitments.len >= harness.tree_count and
        std.meta.eql(commitments[0], publication.roots[0]) and
        std.meta.eql(commitments[1], publication.roots[1]) and
        std.meta.eql(commitments[2], publication.roots[2]);
    var canonical: std.ArrayList(u8) = .{};
    defer canonical.deinit(allocator);
    try postcard.serializeProof(Engine.Hasher, canonical.writer(allocator), proof);
    const canonical_equal = std.mem.eql(u8, bytes, canonical.items);
    var clock = try evidence.Clock.start();
    proof_owned = false;
    try harness.verifyShard(
        Engine,
        allocator,
        support.recursive_pcs_config,
        plan,
        calls,
        publication.statement,
        proof,
    );
    return .{
        .canonical_proof_bytes_equal = canonical_equal,
        .roots_equal_proof = roots_equal,
        .timing = try clock.finish(),
    };
}

fn encodeReceipt(
    allocator: std.mem.Allocator,
    options: Options,
    artifact: call_artifact.Artifact,
    metadata: evidence.FileIdentity,
    plan: authority.ProviderShardPlanV1,
    admission: hpc.RawWorkerAdmissionV1,
    executions: *const [arm_count]ArmExecution,
    total_wall_ns: u64,
    executable_path: []const u8,
    executable_bytes: u64,
    executable_sha256: [32]u8,
) ![]u8 {
    var arm_values: [arm_count]receipt.Arm = undefined;
    var proof_values: [arm_count][proof_count]receipt.Proof = undefined;
    var proof_hashes: [arm_count][proof_count][64]u8 = undefined;
    var statement_hashes: [arm_count][proof_count][64]u8 = undefined;
    var all_resources = true;
    for (0..arm_count) |arm_index| {
        const execution = executions[arm_index];
        for (0..proof_count) |ordinal| {
            const publication = execution.publications[ordinal];
            const check = execution.checks[ordinal];
            const reference = executions[0].publications[ordinal];
            proof_hashes[arm_index][ordinal] = hex(publication.proof.sha256);
            statement_hashes[arm_index][ordinal] = hex(statementIdentity(
                publication.statement,
            ));
            proof_values[arm_index][ordinal] = .{
                .canonical_proof_bytes_equal = check.canonical_proof_bytes_equal,
                .cold_verify = check.timing,
                .committed_column_count = publication.owner_telemetry.committed_column_count,
                .exact_cross_retention_proof_bytes_equal = try exactProofBytesEqual(
                    allocator,
                    reference.proof.path,
                    publication.proof.path,
                ),
                .fresh_verified = true,
                .ordinal = @intCast(ordinal),
                .proof = .{
                    .bytes = publication.proof.bytes,
                    .path = publication.proof.path,
                    .sha256 = &proof_hashes[arm_index][ordinal],
                },
                .prove_wall_ns = publication.prove_wall_ns,
                .retained_coefficient_columns = publication.owner_telemetry.retained_coefficient_columns,
                .roots_equal_cross_retention = std.meta.eql(
                    reference.roots,
                    publication.roots,
                ),
                .roots_equal_proof = check.roots_equal_proof,
                .statement_identity_sha256 = &statement_hashes[arm_index][ordinal],
                .statement_equal_cross_retention = std.meta.eql(
                    reference.statement,
                    publication.statement,
                ),
            };
        }
        const resource_value = armResource(execution.resources);
        if (!std.mem.eql(u8, resource_value.availability, "available"))
            all_resources = false;
        arm_values[arm_index] = .{
            .arm_index = @intCast(arm_index),
            .cold_verify_wall_ns = execution.verify_wall_ns,
            .hard_cap_ns = options.arm_hard_cap_ns,
            .policy = if (arm_index == 0) "always" else "never",
            .proof_batch_wall_ns = execution.proof_batch_wall_ns,
            .proofs = &proof_values[arm_index],
            .resource_usage = resource_value,
            .total = execution.total,
        };
    }
    const placeholder = [_]u8{'0'} ** 64;
    const executable_hex = hex(executable_sha256);
    const metadata_hex = hex(metadata.sha256);
    const slice_commitment = hex(plan.call_list_commitment);
    const admission_hex = hex(admission.identity);
    const ordinals = [_]u32{ 0, 1, 2, 3 };
    const correct = armsCorrect(&arm_values);
    const eligible = correct and all_resources and
        total_wall_ns <= options.total_hard_cap_ns and
        std.mem.eql(u8, options.power_classification, "ac-high-power-pinned");
    return receipt.encode(allocator, .{
        .content_sha256 = &placeholder,
        .admission = admissionValue(admission, &admission_hex),
        .arms = &arm_values,
        .benchmark_executable = .{
            .bytes = executable_bytes,
            .path = executable_path,
            .sha256 = &executable_hex,
        },
        .performance_claim_eligible = eligible,
        .production_eligible = false,
        .profile = .{
            .build_mode = @tagName(builtin.mode),
            .composition_columns = 8,
            .coefficient_retention = "sweep(always,never)",
            .host_power_classification = options.power_classification,
            .main_columns = 445,
            .preprocessed_columns = 2,
            .provider_profile = "standalone-provider-v1",
            .synthetic_core_stage_a = false,
            .tree2_columns = 8,
        },
        .recursive_admissible = false,
        .retention_speedup_milli = ratioMilli(
            executions[1].proof_batch_wall_ns,
            executions[0].proof_batch_wall_ns,
        ),
        .schema = receipt.schema,
        .status = if (eligible) receipt.status_fresh else receipt.status_nonranking,
        .timing_scope = receipt.timing_scope,
        .total_hard_cap_ns = options.total_hard_cap_ns,
        .total_wall_ns = total_wall_ns,
        .workload = .{
            .batch_size = proof_count,
            .call_artifact = .{
                .bytes = metadata.bytes,
                .path = metadata.path,
                .sha256 = &metadata_hex,
            },
            .call_artifact_content_sha256 = artifact.content_sha256,
            .full_call_count = artifact.call_count,
            .full_call_list_commitment_sha256 = artifact.call_list_commitment_sha256,
            .log_size = options.log_size,
            .ordinals = &ordinals,
            .raw_call_file = .{
                .bytes = artifact.calls.bytes,
                .path = artifact.calls.path,
                .sha256 = artifact.calls.sha256,
            },
            .session_sha256 = artifact.session_sha256,
            .shard_count = plan.shard_count,
            .slice_call_count = plan.total_call_count,
            .slice_call_list_commitment_sha256 = &slice_commitment,
            .slice_offset = options.slice_offset,
            .source_producer_sha256 = artifact.producer_sha256,
        },
    });
}

fn statementIdentity(value: harness.StatementV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/ethereum/provider-retention-statement/v1\x00");
    hash.update(&value.plan_identity);
    hash.update(&value.descriptor_identity);
    hash.update(&value.relation_context_identity);
    hashInt(&hash, u32, value.shard_index);
    hashInt(&hash, u32, value.log_size);
    hashInt(&hash, u32, value.n_rows);
    for (value.claims.sums) |sum| for (sum.toM31Array()) |limb|
        hashInt(&hash, u32, limb.v);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn exactProofBytesEqual(
    allocator: std.mem.Allocator,
    reference_path: []const u8,
    candidate_path: []const u8,
) !bool {
    const reference = try artifact_io.readFileBounded(
        allocator,
        reference_path,
        256 * 1024 * 1024,
    );
    defer allocator.free(reference);
    const candidate = try artifact_io.readFileBounded(
        allocator,
        candidate_path,
        256 * 1024 * 1024,
    );
    defer allocator.free(candidate);
    return std.mem.eql(u8, reference, candidate);
}

fn admissionValue(
    value: hpc.RawWorkerAdmissionV1,
    identity: []const u8,
) batch_receipt.RawAdmission {
    return .{
        .admitted_concurrent_jobs = value.admitted_concurrent_jobs,
        .aggregate_engine_stack_reservation_bytes = value.aggregate_engine_stack_reservation_bytes,
        .aggregate_engine_workers = value.aggregate_engine_workers,
        .aggregate_rss_reservation_bytes = value.aggregate_rss_reservation_bytes,
        .available_cpu_workers = value.available_cpu_workers,
        .controller_reserve_bytes = value.controller_reserve_bytes,
        .host_byte_budget = value.host_byte_budget,
        .identity_sha256 = identity,
        .per_job_engine_workers = value.per_job_engine_workers,
        .per_job_rss_budget_bytes = value.per_job_rss_budget_bytes,
        .requested_concurrent_jobs = value.requested_concurrent_jobs,
        .work_items = value.work_items,
    };
}

fn armResource(value: resource_usage.Report) topology_receipt.ArmResourceUsage {
    if (value.availability == .available) return .{
        .availability = "available",
        .cycles = value.interval_delta.?.cycles,
        .energy_nj = value.interval_delta.?.energy_nj,
        .instructions = value.interval_delta.?.instructions,
        .lifetime_peak_after_bytes = value.after_verified_samples.?
            .lifetime_max_phys_footprint_bytes,
        .lifetime_peak_before_bytes = value.before_warmups.?
            .lifetime_max_phys_footprint_bytes,
        .rss_scope = topology_receipt.rss_scope,
        .source = value.source,
    };
    return .{
        .availability = "unavailable",
        .cycles = null,
        .energy_nj = null,
        .instructions = null,
        .lifetime_peak_after_bytes = null,
        .lifetime_peak_before_bytes = null,
        .rss_scope = topology_receipt.rss_scope,
        .source = value.source,
    };
}

fn armsCorrect(arms: []const receipt.Arm) bool {
    for (arms) |arm| for (arm.proofs) |proof| if (!proof.canonical_proof_bytes_equal or
        !proof.exact_cross_retention_proof_bytes_equal or !proof.fresh_verified or
        !proof.roots_equal_cross_retention or !proof.roots_equal_proof or
        !proof.statement_equal_cross_retention) return false;
    return true;
}

fn ratioMilli(numerator: u64, denominator: u64) u32 {
    if (denominator == 0) return 0;
    const scaled = std.math.mul(u64, numerator, 1000) catch
        return std.math.maxInt(u32);
    return std.math.cast(u32, scaled / denominator) orelse
        std.math.maxInt(u32);
}

const OutputPaths = struct {
    proofs: [arm_count][proof_count][]u8,
    receipt_path: []u8,

    fn init(allocator: std.mem.Allocator, root: []const u8) !OutputPaths {
        var result: OutputPaths = undefined;
        var arm_filled: usize = 0;
        var proof_filled: usize = 0;
        errdefer {
            for (0..arm_filled) |arm| for (result.proofs[arm]) |path|
                allocator.free(path);
            if (arm_filled < arm_count)
                for (result.proofs[arm_filled][0..proof_filled]) |path|
                    allocator.free(path);
        }
        for (0..arm_count) |arm| {
            proof_filled = 0;
            for (0..proof_count) |ordinal| {
                const name = try std.fmt.allocPrint(
                    allocator,
                    "retention-{s}-ordinal{d}.stw",
                    .{ if (arm == 0) "always" else "never", ordinal },
                );
                defer allocator.free(name);
                result.proofs[arm][ordinal] =
                    try artifact_io.resolveCreateOnlyChild(allocator, root, name);
                proof_filled += 1;
            }
            arm_filled += 1;
        }
        result.receipt_path = try artifact_io.resolveCreateOnlyChild(
            allocator,
            root,
            "retention-sweep-v1-receipt.json",
        );
        return result;
    }

    fn requireFresh(self: OutputPaths) !void {
        for (self.proofs) |arm| for (arm) |path| try requireAbsent(path);
        try requireAbsent(self.receipt_path);
    }

    fn deinit(self: *OutputPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.receipt_path);
        for (self.proofs) |arm| for (arm) |path| allocator.free(path);
        self.* = undefined;
    }
};

pub const Options = struct {
    arm_hard_cap_ns: u64 = 50 * std.time.ns_per_s,
    call_artifact: []u8,
    controller_reserve_bytes: u64 = hpc.default_controller_reserve_bytes,
    host_byte_budget: u64 = hpc.default_host_byte_budget,
    log_size: u32 = 16,
    output_root: []u8,
    per_job_rss_budget_bytes: u64 = hpc.default_worker_rss_budget_bytes,
    power_classification: []u8,
    slice_offset: usize = 0,
    total_hard_cap_ns: u64 = 118 * std.time.ns_per_s,

    fn parse(allocator: std.mem.Allocator, arguments: []const []const u8) !Options {
        var call_path: ?[]const u8 = null;
        var output_root: ?[]const u8 = null;
        var power: ?[]const u8 = null;
        var result: Options = undefined;
        result.arm_hard_cap_ns = 50 * std.time.ns_per_s;
        result.controller_reserve_bytes = hpc.default_controller_reserve_bytes;
        result.host_byte_budget = hpc.default_host_byte_budget;
        result.log_size = 16;
        result.per_job_rss_budget_bytes = hpc.default_worker_rss_budget_bytes;
        result.slice_offset = 0;
        result.total_hard_cap_ns = 118 * std.time.ns_per_s;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 >= arguments.len) return error.InvalidArguments;
            const name = arguments[index];
            const value = arguments[index + 1];
            if (std.mem.eql(u8, name, "--call-artifact"))
                call_path = value
            else if (std.mem.eql(u8, name, "--output-root"))
                output_root = value
            else if (std.mem.eql(u8, name, "--power-classification"))
                power = value
            else if (std.mem.eql(u8, name, "--log-size"))
                result.log_size = try parseInt(u32, value)
            else if (std.mem.eql(u8, name, "--slice-offset"))
                result.slice_offset = try parseInt(usize, value)
            else if (std.mem.eql(u8, name, "--host-byte-budget"))
                result.host_byte_budget = try parseInt(u64, value)
            else if (std.mem.eql(u8, name, "--controller-reserve-bytes"))
                result.controller_reserve_bytes = try parseInt(u64, value)
            else if (std.mem.eql(u8, name, "--per-job-rss-budget-bytes"))
                result.per_job_rss_budget_bytes = try parseInt(u64, value)
            else if (std.mem.eql(u8, name, "--arm-hard-cap-seconds"))
                result.arm_hard_cap_ns = try secondsToNs(value)
            else if (std.mem.eql(u8, name, "--total-hard-cap-seconds"))
                result.total_hard_cap_ns = try secondsToNs(value)
            else
                return error.InvalidArguments;
        }
        const raw_call = call_path orelse return error.InvalidArguments;
        const raw_root = output_root orelse return error.InvalidArguments;
        const raw_power = power orelse return error.InvalidArguments;
        const cap_sum = std.math.mul(u64, result.arm_hard_cap_ns, arm_count) catch
            return error.InvalidArguments;
        if (result.log_size < 4 or result.log_size > 18 or
            result.arm_hard_cap_ns == 0 or result.total_hard_cap_ns == 0 or
            result.total_hard_cap_ns > receipt.total_time_budget_ns or
            cap_sum > result.total_hard_cap_ns or
            !std.fs.path.isAbsolute(raw_call) or
            !std.fs.path.isAbsolute(raw_root) or
            std.mem.eql(u8, raw_call, raw_root) or
            (!std.mem.eql(u8, raw_power, "ac-high-power-pinned") and
                !std.mem.eql(u8, raw_power, "battery-diagnostic")))
        {
            return error.InvalidArguments;
        }
        result.call_artifact = try allocator.dupe(u8, raw_call);
        errdefer allocator.free(result.call_artifact);
        result.output_root = try allocator.dupe(u8, raw_root);
        errdefer allocator.free(result.output_root);
        result.power_classification = try allocator.dupe(u8, raw_power);
        return result;
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.power_classification);
        allocator.free(self.output_root);
        allocator.free(self.call_artifact);
        self.* = undefined;
    }
};

const Deadline = struct {
    duration_ns: u64,
    completed: std.Thread.ResetEvent = .{},
    thread: ?std.Thread = null,

    fn start(self: *Deadline) !void {
        self.thread = try std.Thread.spawn(.{}, wait, .{self});
    }

    fn finish(self: *Deadline) void {
        if (self.thread) |thread| {
            self.completed.set();
            thread.join();
            self.thread = null;
        }
    }

    fn wait(self: *Deadline) void {
        self.completed.timedWait(self.duration_ns) catch |err| switch (err) {
            error.Timeout => std.process.exit(124),
        };
    }
};

fn requireAbsent(path: []const u8) !void {
    if (std.fs.accessAbsolute(path, .{})) |_| {
        return error.OutputAlreadyExists;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
}

fn parseInt(comptime T: type, value: []const u8) !T {
    return std.fmt.parseUnsigned(T, value, 10) catch return error.InvalidArguments;
}

fn secondsToNs(value: []const u8) !u64 {
    return std.math.mul(u64, try parseInt(u64, value), std.time.ns_per_s) catch
        return error.InvalidArguments;
}

fn powerOfTwo(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidArguments;
    return @as(usize, 1) << @intCast(log_size);
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

pub const testing = struct {
    pub fn parseOptions(
        allocator: std.mem.Allocator,
        arguments: []const []const u8,
    ) !void {
        var options = try Options.parse(allocator, arguments);
        options.deinit(allocator);
    }
};
