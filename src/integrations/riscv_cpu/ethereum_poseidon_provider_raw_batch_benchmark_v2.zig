//! Opt-in N=1..4 serial-vs-concurrent provider proof benchmark.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const call_artifact = @import("ethereum_poseidon_provider_call_artifact_v1.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const geometry_snapshot = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");
const hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");
const base_receipt = @import("ethereum_poseidon_provider_hpc_receipt_v1.zig");
const proof_artifact_v1 = @import("ethereum_poseidon_provider_proof_artifact_v1.zig");
const receipt = @import("ethereum_poseidon_provider_raw_batch_receipt_v2.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const resource_usage = @import("resource_usage.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const joint = frontend.testing.narrow_memory_provider_joint_protocol;

pub const execute_flag = "--run-retained-provider-raw-batch-v2";

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var options = try Options.parse(allocator, arguments);
    defer options.deinit(allocator);
    var paths = try OutputPaths.init(
        allocator,
        options.output_root,
        options.batch_size,
    );
    defer paths.deinit(allocator);
    try paths.requireFresh();
    var total_timer = try std.time.Timer.start();
    const usage_before = resource_usage.capture();

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
        options.batch_size,
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
            .requested_parallel_shards = options.batch_size,
        },
    );
    defer plan.deinit(allocator);
    if (plan.shard_count != options.batch_size)
        return error.ProviderBenchmarkShardCountMismatch;

    const serial_admission = try rawAdmission(options, cpu_workers, 1);
    const concurrent_admission = try rawAdmission(
        options,
        cpu_workers,
        options.batch_size,
    );
    var serial_stage_clock = try evidence.Clock.start();
    const serial_roots = try hpc.commitStageAParallelBounded(
        hpc.Engine,
        allocator,
        support.recursive_pcs_config,
        &plan,
        calls,
        serial_admission,
    );
    defer allocator.free(serial_roots);
    const serial_stage = try serial_stage_clock.finish();
    var concurrent_stage_clock = try evidence.Clock.start();
    const concurrent_roots = try hpc.commitStageAParallelBounded(
        hpc.Engine,
        allocator,
        support.recursive_pcs_config,
        &plan,
        calls,
        concurrent_admission,
    );
    defer allocator.free(concurrent_roots);
    const concurrent_stage = try concurrent_stage_clock.finish();
    const stage_roots_equal = rootsEqual(serial_roots, concurrent_roots);
    if (!stage_roots_equal) return error.ProviderStageAParallelRootMismatch;

    const zero_root = std.mem.zeroes(hpc.Engine.Hasher.Hash);
    var manifest = try joint.JointManifest(hpc.Engine).create(
        allocator,
        &plan,
        calls,
        .{ .preprocessed_root = zero_root, .main_root = zero_root },
        concurrent_roots,
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
    const serial_jobs = try jobsFor(allocator, paths.serial);
    defer allocator.free(serial_jobs);
    const concurrent_jobs = try jobsFor(allocator, paths.concurrent);
    defer allocator.free(concurrent_jobs);

    var serial_timer = try std.time.Timer.start();
    const serial_raw = try hpc.proveJointRawParallelBounded(
        allocator,
        source,
        serial_jobs,
        serial_admission,
    );
    defer allocator.free(serial_raw);
    const serial_proof_wall_ns = serial_timer.read();
    const serial_checks = try allocator.alloc(
        hpc.FreshProviderCheckV1,
        options.batch_size,
    );
    defer allocator.free(serial_checks);
    var serial_verify_timer = try std.time.Timer.start();
    for (serial_checks, serial_raw) |*check, raw| {
        check.* = try hpc.verifyJointRawFresh(allocator, source, raw);
    }
    const serial_verify_wall_ns = serial_verify_timer.read();

    var concurrent_timer = try std.time.Timer.start();
    const concurrent_raw = try hpc.proveJointRawParallelBounded(
        allocator,
        source,
        concurrent_jobs,
        concurrent_admission,
    );
    defer allocator.free(concurrent_raw);
    const concurrent_proof_wall_ns = concurrent_timer.read();
    const concurrent_checks = try allocator.alloc(
        hpc.FreshProviderCheckV1,
        options.batch_size,
    );
    defer allocator.free(concurrent_checks);
    var concurrent_verify_timer = try std.time.Timer.start();
    for (concurrent_checks, concurrent_raw) |*check, raw| {
        check.* = try hpc.verifyJointRawFresh(allocator, source, raw);
    }
    const concurrent_verify_wall_ns = concurrent_verify_timer.read();

    const exact_bytes_equal = try exactProofBytesEqual(
        allocator,
        serial_raw,
        concurrent_raw,
    );
    defer allocator.free(exact_bytes_equal);
    for (exact_bytes_equal) |equal| if (!equal)
        return error.RawProviderProofByteMismatch;
    const usage = resource_usage.report(
        usage_before,
        resource_usage.capture(),
    );
    const executable_sha256 = try support.executableSha256(allocator);
    const self_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_path);
    var self_file = try std.fs.openFileAbsolute(self_path, .{});
    defer self_file.close();
    const self_stat = try self_file.stat();
    const bytes = try encodeReceipt(
        allocator,
        options,
        paths,
        parsed.value,
        metadata_identity,
        plan,
        serial_admission,
        concurrent_admission,
        serial_raw,
        concurrent_raw,
        serial_checks,
        concurrent_checks,
        exact_bytes_equal,
        stage_roots_equal,
        serial_stage,
        concurrent_stage,
        serial_proof_wall_ns,
        concurrent_proof_wall_ns,
        serial_verify_wall_ns,
        concurrent_verify_wall_ns,
        total_timer.read(),
        usage,
        self_path,
        self_stat.size,
        executable_sha256,
    );
    defer allocator.free(bytes);
    try receipt.publishCreateOnly(paths.receipt, bytes);
}

fn encodeReceipt(
    allocator: std.mem.Allocator,
    options: Options,
    paths: OutputPaths,
    artifact: call_artifact.Artifact,
    metadata: evidence.FileIdentity,
    plan: authority.ProviderShardPlanV1,
    serial_admission: hpc.RawWorkerAdmissionV1,
    concurrent_admission: hpc.RawWorkerAdmissionV1,
    serial_raw: []const hpc.RawProviderPublicationV1,
    concurrent_raw: []const hpc.RawProviderPublicationV1,
    serial_checks: []const hpc.FreshProviderCheckV1,
    concurrent_checks: []const hpc.FreshProviderCheckV1,
    exact_bytes_equal: []const bool,
    stage_roots_equal: bool,
    serial_stage: evidence.Timing,
    concurrent_stage: evidence.Timing,
    serial_proof_wall_ns: u64,
    concurrent_proof_wall_ns: u64,
    serial_verify_wall_ns: u64,
    concurrent_verify_wall_ns: u64,
    total_wall_ns: u64,
    usage: resource_usage.Report,
    executable_path: []const u8,
    executable_bytes: u64,
    executable_sha256: [32]u8,
) ![]u8 {
    _ = paths;
    const count = serial_raw.len;
    const correctness_storage = try allocator.alloc(bool, 10 * count);
    defer allocator.free(correctness_storage);
    const correctness = correctnessValue(
        correctness_storage,
        serial_raw,
        concurrent_raw,
        serial_checks,
        concurrent_checks,
        exact_bytes_equal,
        stage_roots_equal,
    );
    const ordinals = try allocator.alloc(u32, count);
    defer allocator.free(ordinals);
    for (ordinals, 0..) |*ordinal, index| ordinal.* = @intCast(index);
    const serial_hashes = try allocator.alloc([64]u8, count);
    defer allocator.free(serial_hashes);
    const concurrent_hashes = try allocator.alloc([64]u8, count);
    defer allocator.free(concurrent_hashes);
    const serial_proofs = try proofWires(
        allocator,
        serial_raw,
        serial_hashes,
    );
    defer allocator.free(serial_proofs);
    const concurrent_proofs = try proofWires(
        allocator,
        concurrent_raw,
        concurrent_hashes,
    );
    defer allocator.free(concurrent_proofs);
    const placeholder = [_]u8{'0'} ** 64;
    const executable_hex = hex(executable_sha256);
    const metadata_hex = hex(metadata.sha256);
    const slice_commitment = hex(plan.call_list_commitment);
    const serial_admission_identity = hex(serial_admission.identity);
    const concurrent_admission_identity = hex(concurrent_admission.identity);
    const resource_value: base_receipt.ResourceUsage = if (usage.availability == .available) .{
        .availability = "available",
        .cycles = usage.interval_delta.?.cycles,
        .energy_nj = usage.interval_delta.?.energy_nj,
        .instructions = usage.interval_delta.?.instructions,
        .lifetime_peak_physical_footprint_bytes = usage
            .after_verified_samples.?.lifetime_max_phys_footprint_bytes,
        .source = usage.source,
    } else .{
        .availability = "unavailable",
        .cycles = null,
        .energy_nj = null,
        .instructions = null,
        .lifetime_peak_physical_footprint_bytes = null,
        .source = usage.source,
    };
    const eligible = (try receipt.allCorrect(correctness)) and
        total_wall_ns <= base_receipt.performance_time_budget_ns and
        std.mem.eql(u8, options.power_classification, "ac-high-power-pinned") and
        usage.availability == .available;
    return receipt.encode(allocator, .{
        .content_sha256 = &placeholder,
        .benchmark_executable = .{
            .bytes = executable_bytes,
            .path = executable_path,
            .sha256 = &executable_hex,
        },
        .concurrent_admission = admissionValue(
            concurrent_admission,
            &concurrent_admission_identity,
        ),
        .correctness = correctness,
        .parallel_proof_speedup_milli = ratioMilli(
            serial_proof_wall_ns,
            concurrent_proof_wall_ns,
        ),
        .parallel_stage_a_speedup_milli = ratioMilli(
            serial_stage.wall_ns,
            concurrent_stage.wall_ns,
        ),
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
        .proofs = .{
            .concurrent = concurrent_proofs,
            .serial = serial_proofs,
        },
        .recursive_admissible = false,
        .resource_usage = resource_value,
        .schema = receipt.schema,
        .serial_admission = admissionValue(
            serial_admission,
            &serial_admission_identity,
        ),
        .status = if (eligible) receipt.status_fresh else receipt.status_nonranking,
        .timing_scope = receipt.timing_scope,
        .timings = .{
            .concurrent_cold_verify_wall_ns = concurrent_verify_wall_ns,
            .concurrent_proof_batch_wall_ns = concurrent_proof_wall_ns,
            .concurrent_stage_a = concurrent_stage,
            .serial_cold_verify_wall_ns = serial_verify_wall_ns,
            .serial_proof_batch_wall_ns = serial_proof_wall_ns,
            .serial_stage_a = serial_stage,
            .total_wall_ns = total_wall_ns,
        },
        .workload = .{
            .batch_size = @intCast(count),
            .call_artifact = .{
                .bytes = metadata.bytes,
                .path = metadata.path,
                .sha256 = &metadata_hex,
            },
            .call_artifact_content_sha256 = artifact.content_sha256,
            .full_call_count = artifact.call_count,
            .full_call_list_commitment_sha256 = artifact.call_list_commitment_sha256,
            .log_size = options.log_size,
            .ordinals = ordinals,
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
    serial: []const hpc.RawProviderPublicationV1,
    concurrent: []const hpc.RawProviderPublicationV1,
) ![]bool {
    if (serial.len != concurrent.len) return error.ProviderBatchLengthMismatch;
    const result = try allocator.alloc(bool, serial.len);
    errdefer allocator.free(result);
    for (serial, concurrent, result) |left, right, *equal| {
        const left_bytes = try artifact_io.readFileBounded(
            allocator,
            left.proof.path,
            proof_artifact_v1.max_proof_bytes,
        );
        defer allocator.free(left_bytes);
        const right_bytes = try artifact_io.readFileBounded(
            allocator,
            right.proof.path,
            proof_artifact_v1.max_proof_bytes,
        );
        defer allocator.free(right_bytes);
        equal.* = std.mem.eql(u8, left_bytes, right_bytes);
    }
    return result;
}

fn correctnessValue(
    storage: []bool,
    serial_raw: []const hpc.RawProviderPublicationV1,
    concurrent_raw: []const hpc.RawProviderPublicationV1,
    serial: []const hpc.FreshProviderCheckV1,
    concurrent: []const hpc.FreshProviderCheckV1,
    exact_bytes: []const bool,
    stage_roots_equal: bool,
) receipt.Correctness {
    const count = serial.len;
    std.debug.assert(storage.len == 10 * count);
    const exact_proof_bytes = storage[0 * count .. 1 * count];
    const parallel_canonical = storage[1 * count .. 2 * count];
    const parallel_verified = storage[2 * count .. 3 * count];
    const parallel_roots = storage[3 * count .. 4 * count];
    const serial_canonical = storage[4 * count .. 5 * count];
    const serial_verified = storage[5 * count .. 6 * count];
    const serial_roots = storage[6 * count .. 7 * count];
    const statement_equal = storage[7 * count .. 8 * count];
    const native_equal = storage[8 * count .. 9 * count];
    const ordered_equal = storage[9 * count .. 10 * count];
    for (0..count) |index| {
        exact_proof_bytes[index] = exact_bytes[index];
        parallel_canonical[index] = concurrent[index].canonical_proof_bytes_equal;
        parallel_verified[index] =
            concurrent[index].claim.fresh_provider_stark_verified;
        parallel_roots[index] = concurrent[index].stage_a_roots_equal;
        serial_canonical[index] = serial[index].canonical_proof_bytes_equal;
        serial_verified[index] =
            serial[index].claim.fresh_provider_stark_verified;
        serial_roots[index] = serial[index].stage_a_roots_equal;
        statement_equal[index] = std.meta.eql(
            serial_raw[index].statement.identity,
            concurrent_raw[index].statement.identity,
        );
        native_equal[index] = std.meta.eql(
            serial[index].claim.native_claim,
            concurrent[index].claim.native_claim,
        );
        ordered_equal[index] = std.meta.eql(
            serial[index].claim.ordered_call_claim,
            concurrent[index].claim.ordered_call_claim,
        );
    }
    return .{
        .exact_serial_parallel_proof_bytes_equal = exact_proof_bytes,
        .parallel_canonical_proof_bytes_equal = parallel_canonical,
        .parallel_fresh_verified = parallel_verified,
        .parallel_roots_equal_proof = parallel_roots,
        .serial_canonical_proof_bytes_equal = serial_canonical,
        .serial_fresh_verified = serial_verified,
        .serial_roots_equal_proof = serial_roots,
        .stage_a_serial_parallel_roots_equal = stage_roots_equal,
        .statement_identities_equal = statement_equal,
        .native_claims_equal = native_equal,
        .ordered_claims_equal = ordered_equal,
    };
}

fn proofWires(
    allocator: std.mem.Allocator,
    values: []const hpc.RawProviderPublicationV1,
    hashes: [][64]u8,
) ![]base_receipt.FileIdentity {
    if (values.len != hashes.len) return error.ProviderBatchLengthMismatch;
    const result = try allocator.alloc(base_receipt.FileIdentity, values.len);
    for (values, hashes, result) |value, *hash, *destination| {
        hash.* = hex(value.proof.sha256);
        destination.* = .{
            .bytes = value.proof.bytes,
            .path = value.proof.path,
            .sha256 = hash,
        };
    }
    return result;
}

fn admissionValue(
    value: hpc.RawWorkerAdmissionV1,
    identity: []const u8,
) receipt.RawAdmission {
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

fn rawAdmission(
    options: Options,
    cpu_workers: u32,
    jobs: u32,
) !hpc.RawWorkerAdmissionV1 {
    return hpc.RawWorkerAdmissionV1.create(.{
        .requested_concurrent_jobs = jobs,
        .available_cpu_workers = cpu_workers,
        .work_items = options.batch_size,
        .per_job_engine_workers = options.per_job_engine_workers,
        .host_byte_budget = options.host_byte_budget,
        .controller_reserve_bytes = options.controller_reserve_bytes,
        .per_job_rss_budget_bytes = options.per_job_rss_budget_bytes,
    });
}

const OutputPaths = struct {
    serial: [][]u8,
    concurrent: [][]u8,
    receipt: []u8,

    fn init(
        allocator: std.mem.Allocator,
        root: []const u8,
        count: u32,
    ) !OutputPaths {
        const length: usize = @intCast(count);
        const serial = try allocator.alloc([]u8, length);
        errdefer allocator.free(serial);
        var serial_filled: usize = 0;
        errdefer for (serial[0..serial_filled]) |path| allocator.free(path);
        const concurrent = try allocator.alloc([]u8, length);
        errdefer allocator.free(concurrent);
        var concurrent_filled: usize = 0;
        errdefer for (concurrent[0..concurrent_filled]) |path| allocator.free(path);
        for (0..length) |index| {
            const serial_name = try std.fmt.allocPrint(
                allocator,
                "serial-ordinal{d}.stw",
                .{index},
            );
            defer allocator.free(serial_name);
            serial[index] = try artifact_io.resolveCreateOnlyChild(
                allocator,
                root,
                serial_name,
            );
            serial_filled += 1;
            const concurrent_name = try std.fmt.allocPrint(
                allocator,
                "concurrent-ordinal{d}.stw",
                .{index},
            );
            defer allocator.free(concurrent_name);
            concurrent[index] = try artifact_io.resolveCreateOnlyChild(
                allocator,
                root,
                concurrent_name,
            );
            concurrent_filled += 1;
        }
        const receipt_path = try artifact_io.resolveCreateOnlyChild(
            allocator,
            root,
            "raw-batch-v2-receipt.json",
        );
        return .{
            .serial = serial,
            .concurrent = concurrent,
            .receipt = receipt_path,
        };
    }

    fn requireFresh(self: OutputPaths) !void {
        for (self.serial) |path| try requireAbsent(path);
        for (self.concurrent) |path| try requireAbsent(path);
        try requireAbsent(self.receipt);
    }

    fn deinit(self: *OutputPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.receipt);
        for (self.concurrent) |path| allocator.free(path);
        allocator.free(self.concurrent);
        for (self.serial) |path| allocator.free(path);
        allocator.free(self.serial);
        self.* = undefined;
    }
};

pub const Options = struct {
    call_artifact: []u8,
    output_root: []u8,
    power_classification: []u8,
    batch_size: u32,
    log_size: u32 = 16,
    slice_offset: usize = 0,
    per_job_engine_workers: u32 = 4,
    host_byte_budget: u64 = hpc.default_host_byte_budget,
    controller_reserve_bytes: u64 = hpc.default_controller_reserve_bytes,
    per_job_rss_budget_bytes: u64 = hpc.default_worker_rss_budget_bytes,

    fn parse(allocator: std.mem.Allocator, arguments: []const []const u8) !Options {
        var call_path: ?[]const u8 = null;
        var output_root: ?[]const u8 = null;
        var power: ?[]const u8 = null;
        var batch_size: ?u32 = null;
        var result: Options = undefined;
        result.log_size = 16;
        result.slice_offset = 0;
        result.per_job_engine_workers = 4;
        result.host_byte_budget = hpc.default_host_byte_budget;
        result.controller_reserve_bytes = hpc.default_controller_reserve_bytes;
        result.per_job_rss_budget_bytes = hpc.default_worker_rss_budget_bytes;
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
            else if (std.mem.eql(u8, name, "--batch-size"))
                batch_size = try parseInt(u32, value)
            else if (std.mem.eql(u8, name, "--log-size"))
                result.log_size = try parseInt(u32, value)
            else if (std.mem.eql(u8, name, "--slice-offset"))
                result.slice_offset = try parseInt(usize, value)
            else if (std.mem.eql(u8, name, "--per-job-engine-workers"))
                result.per_job_engine_workers = try parseInt(u32, value)
            else if (std.mem.eql(u8, name, "--host-byte-budget"))
                result.host_byte_budget = try parseInt(u64, value)
            else if (std.mem.eql(u8, name, "--controller-reserve-bytes"))
                result.controller_reserve_bytes = try parseInt(u64, value)
            else if (std.mem.eql(u8, name, "--per-job-rss-budget-bytes"))
                result.per_job_rss_budget_bytes = try parseInt(u64, value)
            else
                return error.InvalidArguments;
        }
        const raw_call = call_path orelse return error.InvalidArguments;
        const raw_root = output_root orelse return error.InvalidArguments;
        const raw_power = power orelse return error.InvalidArguments;
        result.batch_size = batch_size orelse return error.InvalidArguments;
        if (result.batch_size == 0 or
            result.batch_size > receipt.max_batch_size or
            result.log_size < 4 or result.log_size > 18 or
            result.per_job_engine_workers == 0 or
            result.per_job_engine_workers > 8 or
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

fn powerOfTwo(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidArguments;
    return @as(usize, 1) << @intCast(log_size);
}

fn ratioMilli(numerator: u64, denominator: u64) u32 {
    if (denominator == 0) return 0;
    const scaled = std.math.mul(u64, numerator, 1000) catch
        return std.math.maxInt(u32);
    return std.math.cast(u32, scaled / denominator) orelse
        std.math.maxInt(u32);
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
