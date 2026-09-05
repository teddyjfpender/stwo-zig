//! Opt-in concurrent-only provider topology sweep for an 18-core host.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const call_artifact = @import("ethereum_poseidon_provider_call_artifact_v1.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const geometry_snapshot = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");
const hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");
const base_receipt = @import("ethereum_poseidon_provider_hpc_receipt_v1.zig");
const batch_receipt = @import("ethereum_poseidon_provider_raw_batch_receipt_v2.zig");
const proof_artifact_v1 = @import("ethereum_poseidon_provider_proof_artifact_v1.zig");
const receipt = @import("ethereum_poseidon_provider_topology_sweep_receipt_v1.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const resource_usage = @import("resource_usage.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const harness = frontend.testing.narrow_memory_provider_proof_harness;
const joint = frontend.testing.narrow_memory_provider_joint_protocol;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;

pub const execute_flag = "--run-retained-provider-topology-sweep-v1";

const configuration_count = receipt.arm_count;
const proof_count = receipt.proof_count;

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
    var total_clock = try std.time.Timer.start();

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
    const slice_count = std.math.mul(
        usize,
        rows_per_shard,
        proof_count,
    ) catch return error.ProviderBenchmarkSliceOverflow;
    const slice_end = std.math.add(
        usize,
        options.slice_offset,
        slice_count,
    ) catch return error.ProviderBenchmarkSliceOverflow;
    if (slice_end > reopened.calls.len)
        return error.ProviderBenchmarkSliceOutOfRange;
    const calls = reopened.calls[options.slice_offset..slice_end];
    const cpu_workers = std.math.cast(u32, try std.Thread.getCpuCount()) orelse
        std.math.maxInt(u32);
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

    const configurations = try topologyValues(options.arm_hard_cap_ns);
    var admissions: [configuration_count]hpc.RawWorkerAdmissionV1 = undefined;
    for (&admissions, configurations) |*admission, topology| {
        admission.* = try rawAdmission(options, cpu_workers, topology);
        if (admission.admitted_concurrent_jobs != topology.concurrent_jobs)
            return error.ProviderTopologyNotFullyAdmitted;
    }
    var executions: [configuration_count]ArmExecution = undefined;
    var completed: usize = 0;
    defer for (executions[0..completed]) |*execution|
        execution.deinit(allocator);

    const before_first = resource_usage.capture();
    var first_clock = try evidence.Clock.start();
    var first_deadline = Deadline{
        .duration_ns = configurations[0].hard_cap_ns,
    };
    try first_deadline.start();
    defer first_deadline.finish();
    var first_stage_clock = try evidence.Clock.start();
    const reference_roots = try hpc.commitStageAParallelBounded(
        hpc.Engine,
        allocator,
        support.recursive_pcs_config,
        &plan,
        calls,
        admissions[0],
    );
    defer allocator.free(reference_roots);
    const first_stage = try first_stage_clock.finish();
    const zero_root = std.mem.zeroes(hpc.Engine.Hasher.Hash);
    var manifest = try joint.JointManifest(hpc.Engine).create(
        allocator,
        &plan,
        calls,
        .{ .preprocessed_root = zero_root, .main_root = zero_root },
        reference_roots,
    );
    defer manifest.deinit(allocator);
    const prepared = try joint.prepareSharedTranscript(
        hpc.Engine,
        allocator,
        support.recursive_pcs_config,
        &plan,
        calls,
        &manifest,
    );
    const source = hpc.JointSourceV1{
        .plan = &plan,
        .calls = calls,
        .manifest = &manifest,
        .shared = prepared.authority_value,
    };
    executions[0] = try proveAndVerify(
        allocator,
        source,
        paths.proofs[0][0..],
        admissions[0],
        first_stage,
        true,
        before_first,
        &first_clock,
    );
    completed = 1;
    first_deadline.finish();
    if (executions[0].total.wall_ns > configurations[0].hard_cap_ns)
        return error.ProviderTopologyArmDeadlineExceeded;

    for (1..configuration_count) |index| {
        if (total_clock.read() >= options.total_hard_cap_ns)
            return error.ProviderTopologyTotalDeadlineExceeded;
        executions[index] = try runArm(
            allocator,
            &plan,
            calls,
            source,
            paths.proofs[index][0..],
            admissions[index],
            reference_roots,
            configurations[index].hard_cap_ns,
        );
        completed += 1;
    }
    const total_wall_ns = total_clock.read();
    if (total_wall_ns > options.total_hard_cap_ns)
        return error.ProviderTopologyTotalDeadlineExceeded;

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
        &configurations,
        &admissions,
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
    source: hpc.JointSourceV1,
    proof_paths: []const []const u8,
    admission: hpc.RawWorkerAdmissionV1,
    reference_roots: []const harness.StageACommitment(hpc.Engine),
    hard_cap_ns: u64,
) !ArmExecution {
    const before = resource_usage.capture();
    var total_clock = try evidence.Clock.start();
    var deadline = Deadline{ .duration_ns = hard_cap_ns };
    try deadline.start();
    defer deadline.finish();
    var stage_clock = try evidence.Clock.start();
    const roots = try hpc.commitStageAParallelBounded(
        hpc.Engine,
        allocator,
        support.recursive_pcs_config,
        plan,
        calls,
        admission,
    );
    defer allocator.free(roots);
    const stage = try stage_clock.finish();
    const roots_equal = rootsEqual(reference_roots, roots);
    if (!roots_equal) return error.ProviderStageAParallelRootMismatch;
    const result = try proveAndVerify(
        allocator,
        source,
        proof_paths,
        admission,
        stage,
        roots_equal,
        before,
        &total_clock,
    );
    if (result.total.wall_ns > hard_cap_ns) {
        var owned = result;
        owned.deinit(allocator);
        return error.ProviderTopologyArmDeadlineExceeded;
    }
    return result;
}

fn proveAndVerify(
    allocator: std.mem.Allocator,
    source: hpc.JointSourceV1,
    proof_paths: []const []const u8,
    admission: hpc.RawWorkerAdmissionV1,
    stage: evidence.Timing,
    roots_equal: bool,
    before: resource_usage.Capture,
    total_clock: *evidence.Clock,
) !ArmExecution {
    const jobs = try jobsFor(allocator, proof_paths);
    defer allocator.free(jobs);
    var proof_timer = try std.time.Timer.start();
    const raw = try hpc.proveJointRawParallelBounded(
        allocator,
        source,
        jobs,
        admission,
    );
    errdefer allocator.free(raw);
    const proof_wall_ns = proof_timer.read();
    const checks = try allocator.alloc(hpc.FreshProviderCheckV1, raw.len);
    errdefer allocator.free(checks);
    var verify_timer = try std.time.Timer.start();
    for (checks, raw) |*check, publication| {
        check.* = try hpc.verifyJointRawFresh(allocator, source, publication);
    }
    const verify_wall_ns = verify_timer.read();
    const total = try total_clock.finish();
    return .{
        .checks = checks,
        .proof_batch_wall_ns = proof_wall_ns,
        .raw = raw,
        .resources = resource_usage.report(before, resource_usage.capture()),
        .stage_a = stage,
        .stage_a_roots_equal_reference = roots_equal,
        .total = total,
        .verify_wall_ns = verify_wall_ns,
    };
}

const ArmExecution = struct {
    checks: []hpc.FreshProviderCheckV1,
    proof_batch_wall_ns: u64,
    raw: []hpc.RawProviderPublicationV1,
    resources: resource_usage.Report,
    stage_a: evidence.Timing,
    stage_a_roots_equal_reference: bool,
    total: evidence.Timing,
    verify_wall_ns: u64,

    fn deinit(self: *ArmExecution, allocator: std.mem.Allocator) void {
        allocator.free(self.checks);
        allocator.free(self.raw);
        self.* = undefined;
    }
};

fn encodeReceipt(
    allocator: std.mem.Allocator,
    options: Options,
    artifact: call_artifact.Artifact,
    metadata: evidence.FileIdentity,
    plan: authority.ProviderShardPlanV1,
    configurations: *const [configuration_count]receipt.Topology,
    admissions: *const [configuration_count]hpc.RawWorkerAdmissionV1,
    executions: *const [configuration_count]ArmExecution,
    total_wall_ns: u64,
    executable_path: []const u8,
    executable_bytes: u64,
    executable_sha256: [32]u8,
) ![]u8 {
    var arm_values: [configuration_count]receipt.Arm = undefined;
    var proof_values: [configuration_count][proof_count]receipt.Proof = undefined;
    var proof_hashes: [configuration_count][proof_count][64]u8 = undefined;
    var statement_hashes: [configuration_count][proof_count][64]u8 = undefined;
    var claim_hashes: [configuration_count][proof_count][64]u8 = undefined;
    var admission_hashes: [configuration_count][64]u8 = undefined;
    var all_resources = true;
    for (0..configuration_count) |arm_index| {
        const execution = executions[arm_index];
        for (0..proof_count) |ordinal| {
            const publication = execution.raw[ordinal];
            const check = execution.checks[ordinal];
            proof_hashes[arm_index][ordinal] = hex(publication.proof.sha256);
            statement_hashes[arm_index][ordinal] = hex(publication.statement.identity);
            claim_hashes[arm_index][ordinal] = hex(check.claim.identity);
            const reference = executions[0];
            proof_values[arm_index][ordinal] = .{
                .canonical_proof_bytes_equal = check.canonical_proof_bytes_equal,
                .claim_identity_sha256 = &claim_hashes[arm_index][ordinal],
                .cold_verify = check.verify_timing,
                .exact_reference_proof_bytes_equal = try exactProofBytesEqual(
                    allocator,
                    reference.raw[ordinal].proof.path,
                    publication.proof.path,
                ),
                .fresh_verified = check.claim.fresh_provider_stark_verified,
                .native_claim_equal_reference = std.meta.eql(
                    reference.checks[ordinal].claim.native_claim,
                    check.claim.native_claim,
                ),
                .ordered_claim_equal_reference = std.meta.eql(
                    reference.checks[ordinal].claim.ordered_call_claim,
                    check.claim.ordered_call_claim,
                ),
                .ordinal = @intCast(ordinal),
                .proof = .{
                    .bytes = publication.proof.bytes,
                    .path = publication.proof.path,
                    .sha256 = &proof_hashes[arm_index][ordinal],
                },
                .prove_wall_ns = publication.prove_wall_ns,
                .roots_equal_proof = check.stage_a_roots_equal,
                .statement_identity_equal_reference = std.meta.eql(
                    reference.raw[ordinal].statement.identity,
                    publication.statement.identity,
                ),
                .statement_identity_sha256 = &statement_hashes[arm_index][ordinal],
            };
        }
        admission_hashes[arm_index] = hex(admissions[arm_index].identity);
        const resource_value = armResource(execution.resources);
        if (!std.mem.eql(u8, resource_value.availability, "available"))
            all_resources = false;
        arm_values[arm_index] = .{
            .admission = admissionValue(
                admissions[arm_index],
                &admission_hashes[arm_index],
            ),
            .arm_index = @intCast(arm_index),
            .cold_verify_wall_ns = execution.verify_wall_ns,
            .configuration_index = @intCast(arm_index),
            .proof_batch_wall_ns = execution.proof_batch_wall_ns,
            .proofs = &proof_values[arm_index],
            .resource_usage = resource_value,
            .stage_a = execution.stage_a,
            .stage_a_roots_equal_reference = execution.stage_a_roots_equal_reference,
            .total = execution.total,
        };
    }
    const placeholder = [_]u8{'0'} ** 64;
    const executable_hex = hex(executable_sha256);
    const metadata_hex = hex(metadata.sha256);
    const slice_commitment = hex(plan.call_list_commitment);
    const ordinals = [_]u32{ 0, 1, 2, 3 };
    const correct = armsCorrect(&arm_values);
    const eligible = correct and all_resources and
        total_wall_ns <= options.total_hard_cap_ns and
        std.mem.eql(u8, options.power_classification, "ac-high-power-pinned");
    return receipt.encode(allocator, .{
        .content_sha256 = &placeholder,
        .arms = &arm_values,
        .benchmark_executable = .{
            .bytes = executable_bytes,
            .path = executable_path,
            .sha256 = &executable_hex,
        },
        .configurations = configurations,
        .performance_claim_eligible = eligible,
        .production_eligible = false,
        .profile = .{
            .build_mode = @tagName(builtin.mode),
            .composition_columns = 8,
            .coefficient_retention = "never",
            .host_power_classification = options.power_classification,
            .main_columns = 445,
            .preprocessed_columns = 2,
            .provider_profile = "ordered-provider-v2",
            .synthetic_core_stage_a = true,
            .tree2_columns = 12,
        },
        .recursive_admissible = false,
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

fn armResource(value: resource_usage.Report) receipt.ArmResourceUsage {
    if (value.availability == .available) return .{
        .availability = "available",
        .cycles = value.interval_delta.?.cycles,
        .energy_nj = value.interval_delta.?.energy_nj,
        .instructions = value.interval_delta.?.instructions,
        .lifetime_peak_after_bytes = value.after_verified_samples.?
            .lifetime_max_phys_footprint_bytes,
        .lifetime_peak_before_bytes = value.before_warmups.?
            .lifetime_max_phys_footprint_bytes,
        .rss_scope = receipt.rss_scope,
        .source = value.source,
    };
    return .{
        .availability = "unavailable",
        .cycles = null,
        .energy_nj = null,
        .instructions = null,
        .lifetime_peak_after_bytes = null,
        .lifetime_peak_before_bytes = null,
        .rss_scope = receipt.rss_scope,
        .source = value.source,
    };
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

fn armsCorrect(arms: []const receipt.Arm) bool {
    for (arms) |arm| {
        if (!arm.stage_a_roots_equal_reference) return false;
        for (arm.proofs) |proof| if (!proof.canonical_proof_bytes_equal or
            !proof.exact_reference_proof_bytes_equal or !proof.fresh_verified or
            !proof.native_claim_equal_reference or
            !proof.ordered_claim_equal_reference or !proof.roots_equal_proof or
            !proof.statement_identity_equal_reference) return false;
    }
    return true;
}

fn rawAdmission(
    options: Options,
    cpu_workers: u32,
    topology: receipt.Topology,
) !hpc.RawWorkerAdmissionV1 {
    return hpc.RawWorkerAdmissionV1.create(.{
        .requested_concurrent_jobs = topology.concurrent_jobs,
        .available_cpu_workers = cpu_workers,
        .work_items = proof_count,
        .per_job_engine_workers = topology.per_job_engine_workers,
        .host_byte_budget = options.host_byte_budget,
        .controller_reserve_bytes = options.controller_reserve_bytes,
        .per_job_rss_budget_bytes = options.per_job_rss_budget_bytes,
    });
}

fn topologyValues(
    arm_hard_cap_ns: u64,
) ![configuration_count]receipt.Topology {
    var result: [configuration_count]receipt.Topology = undefined;
    for (&result, 0..) |*configuration, index| configuration.* = .{
        .concurrent_jobs = receipt.canonical_jobs[index],
        .per_job_engine_workers = receipt.canonical_engine_workers[index],
        .hard_cap_ns = arm_hard_cap_ns,
    };
    return result;
}

fn jobsFor(
    allocator: std.mem.Allocator,
    paths: []const []const u8,
) ![]hpc.RawProviderJobV1 {
    const jobs = try allocator.alloc(hpc.RawProviderJobV1, paths.len);
    for (jobs, paths, 0..) |*job, path, index| job.* = .{
        .ordinal = @intCast(index),
        .proof_path = path,
    };
    return jobs;
}

fn exactProofBytesEqual(
    allocator: std.mem.Allocator,
    reference_path: []const u8,
    candidate_path: []const u8,
) !bool {
    const reference = try artifact_io.readFileBounded(
        allocator,
        reference_path,
        proof_artifact_v1.max_proof_bytes,
    );
    defer allocator.free(reference);
    const candidate = try artifact_io.readFileBounded(
        allocator,
        candidate_path,
        proof_artifact_v1.max_proof_bytes,
    );
    defer allocator.free(candidate);
    return std.mem.eql(u8, reference, candidate);
}

const OutputPaths = struct {
    proofs: [configuration_count][proof_count][]u8,
    receipt_path: []u8,

    fn init(allocator: std.mem.Allocator, root: []const u8) !OutputPaths {
        var result: OutputPaths = undefined;
        var arm_filled: usize = 0;
        var proof_filled: usize = 0;
        errdefer {
            for (0..arm_filled) |arm| for (result.proofs[arm]) |path|
                allocator.free(path);
            if (arm_filled < configuration_count)
                for (result.proofs[arm_filled][0..proof_filled]) |path|
                    allocator.free(path);
        }
        for (0..configuration_count) |arm| {
            proof_filled = 0;
            for (0..proof_count) |ordinal| {
                const name = try std.fmt.allocPrint(
                    allocator,
                    "topology-{d}x{d}-ordinal{d}.stw",
                    .{
                        receipt.canonical_jobs[arm],
                        receipt.canonical_engine_workers[arm],
                        ordinal,
                    },
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
            "topology-sweep-v1-receipt.json",
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
    arm_hard_cap_ns: u64 = 35 * std.time.ns_per_s,
    call_artifact: []u8,
    controller_reserve_bytes: u64 = hpc.default_controller_reserve_bytes,
    host_byte_budget: u64 = hpc.default_host_byte_budget,
    log_size: u32 = 15,
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
        result.arm_hard_cap_ns = 35 * std.time.ns_per_s;
        result.controller_reserve_bytes = hpc.default_controller_reserve_bytes;
        result.host_byte_budget = hpc.default_host_byte_budget;
        result.log_size = 15;
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
        const cap_sum = std.math.mul(
            u64,
            result.arm_hard_cap_ns,
            configuration_count,
        ) catch return error.InvalidArguments;
        if (result.log_size < 4 or result.log_size > 18 or
            result.arm_hard_cap_ns == 0 or
            result.total_hard_cap_ns == 0 or
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

fn rootsEqual(left: anytype, right: anytype) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

fn parseInt(comptime T: type, value: []const u8) !T {
    return std.fmt.parseUnsigned(T, value, 10) catch return error.InvalidArguments;
}

fn secondsToNs(value: []const u8) !u64 {
    return std.math.mul(
        u64,
        try parseInt(u64, value),
        std.time.ns_per_s,
    ) catch return error.InvalidArguments;
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
