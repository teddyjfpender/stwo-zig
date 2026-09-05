//! Opt-in two-ordinal serial-vs-parallel provider proof benchmark.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const call_artifact = @import("ethereum_poseidon_provider_call_artifact_v1.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const geometry_snapshot = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");
const hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");
const base_receipt = @import("ethereum_poseidon_provider_hpc_receipt_v1.zig");
const receipt = @import("ethereum_poseidon_provider_raw_pair_receipt_v1.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const resource_usage = @import("resource_usage.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const joint = frontend.testing.narrow_memory_provider_joint_protocol;

pub const execute_flag = "--run-retained-provider-raw-pair";

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var options = try Options.parse(allocator, arguments);
    defer options.deinit(allocator);
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
    const slice_count = std.math.mul(usize, rows_per_shard, 2) catch
        return error.ProviderBenchmarkSliceOverflow;
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
            .requested_parallel_shards = 2,
        },
    );
    defer plan.deinit(allocator);
    if (plan.shard_count != 2) return error.ProviderBenchmarkShardCountMismatch;

    const serial_admission = try rawAdmission(options, cpu_workers, 1);
    const parallel_admission = try rawAdmission(options, cpu_workers, 2);
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
    var parallel_stage_clock = try evidence.Clock.start();
    const parallel_roots = try hpc.commitStageAParallelBounded(
        hpc.Engine,
        allocator,
        support.recursive_pcs_config,
        &plan,
        calls,
        parallel_admission,
    );
    defer allocator.free(parallel_roots);
    const parallel_stage = try parallel_stage_clock.finish();
    if (!rootsEqual(serial_roots, parallel_roots))
        return error.ProviderStageAParallelRootMismatch;

    const zero_root = std.mem.zeroes(hpc.Engine.Hasher.Hash);
    var manifest = try joint.JointManifest(hpc.Engine).create(
        allocator,
        &plan,
        calls,
        .{ .preprocessed_root = zero_root, .main_root = zero_root },
        parallel_roots,
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

    const serial_jobs = [_]hpc.RawProviderJobV1{
        .{ .ordinal = 0, .proof_path = options.serial_proof_0 },
        .{ .ordinal = 1, .proof_path = options.serial_proof_1 },
    };
    var serial_timer = try std.time.Timer.start();
    const serial_raw = try hpc.proveJointRawParallelBounded(
        allocator,
        source,
        &serial_jobs,
        serial_admission,
    );
    defer allocator.free(serial_raw);
    const serial_proof_wall_ns = serial_timer.read();
    var serial_checks: [2]hpc.FreshProviderCheckV1 = undefined;
    var serial_verify_timer = try std.time.Timer.start();
    for (&serial_checks, serial_raw) |*check, raw| {
        check.* = try hpc.verifyJointRawFresh(allocator, source, raw);
    }
    const serial_verify_wall_ns = serial_verify_timer.read();

    const parallel_jobs = [_]hpc.RawProviderJobV1{
        .{ .ordinal = 0, .proof_path = options.parallel_proof_0 },
        .{ .ordinal = 1, .proof_path = options.parallel_proof_1 },
    };
    var parallel_timer = try std.time.Timer.start();
    const parallel_raw = try hpc.proveJointRawParallelBounded(
        allocator,
        source,
        &parallel_jobs,
        parallel_admission,
    );
    defer allocator.free(parallel_raw);
    const parallel_proof_wall_ns = parallel_timer.read();
    var parallel_checks: [2]hpc.FreshProviderCheckV1 = undefined;
    var parallel_verify_timer = try std.time.Timer.start();
    for (&parallel_checks, parallel_raw) |*check, raw| {
        check.* = try hpc.verifyJointRawFresh(allocator, source, raw);
    }
    const parallel_verify_wall_ns = parallel_verify_timer.read();

    const usage_after = resource_usage.capture();
    const usage = resource_usage.report(usage_before, usage_after);
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
        serial_admission,
        parallel_admission,
        serial_raw,
        parallel_raw,
        serial_checks,
        parallel_checks,
        serial_stage,
        parallel_stage,
        serial_proof_wall_ns,
        parallel_proof_wall_ns,
        serial_verify_wall_ns,
        parallel_verify_wall_ns,
        total_timer.read(),
        usage,
        self_path,
        self_stat.size,
        executable_sha256,
    );
    defer allocator.free(bytes);
    try receipt.publishCreateOnly(options.receipt, bytes);
}

fn encodeReceipt(
    allocator: std.mem.Allocator,
    options: Options,
    artifact: call_artifact.Artifact,
    metadata: evidence.FileIdentity,
    plan: authority.ProviderShardPlanV1,
    serial_admission: hpc.RawWorkerAdmissionV1,
    parallel_admission: hpc.RawWorkerAdmissionV1,
    serial_raw: []const hpc.RawProviderPublicationV1,
    parallel_raw: []const hpc.RawProviderPublicationV1,
    serial_checks: [2]hpc.FreshProviderCheckV1,
    parallel_checks: [2]hpc.FreshProviderCheckV1,
    serial_stage: evidence.Timing,
    parallel_stage: evidence.Timing,
    serial_proof_wall_ns: u64,
    parallel_proof_wall_ns: u64,
    serial_verify_wall_ns: u64,
    parallel_verify_wall_ns: u64,
    total_wall_ns: u64,
    usage: resource_usage.Report,
    executable_path: []const u8,
    executable_bytes: u64,
    executable_sha256: [32]u8,
) ![]u8 {
    const placeholder = [_]u8{'0'} ** 64;
    const executable_hex = hex(executable_sha256);
    const metadata_hex = hex(metadata.sha256);
    const slice_commitment = hex(plan.call_list_commitment);
    const serial_admission_identity = hex(serial_admission.identity);
    const parallel_admission_identity = hex(parallel_admission.identity);
    var serial_proof_hex: [2][64]u8 = undefined;
    var parallel_proof_hex: [2][64]u8 = undefined;
    for (0..2) |index| {
        serial_proof_hex[index] = hex(serial_raw[index].proof.sha256);
        parallel_proof_hex[index] = hex(parallel_raw[index].proof.sha256);
    }
    const correctness = correctnessValue(
        serial_raw,
        parallel_raw,
        serial_checks,
        parallel_checks,
    );
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
    const eligible = allCorrect(correctness) and
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
        .correctness = correctness,
        .parallel_admission = admissionValue(
            parallel_admission,
            &parallel_admission_identity,
        ),
        .parallel_proof_speedup_milli = ratioMilli(
            serial_proof_wall_ns,
            parallel_proof_wall_ns,
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
            .parallel = proofWires(parallel_raw, &parallel_proof_hex),
            .serial = proofWires(serial_raw, &serial_proof_hex),
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
            .parallel_cold_verify_wall_ns = parallel_verify_wall_ns,
            .parallel_proof_batch_wall_ns = parallel_proof_wall_ns,
            .parallel_stage_a = parallel_stage,
            .serial_cold_verify_wall_ns = serial_verify_wall_ns,
            .serial_proof_batch_wall_ns = serial_proof_wall_ns,
            .serial_stage_a = serial_stage,
            .total_wall_ns = total_wall_ns,
        },
        .workload = .{
            .call_artifact = .{
                .bytes = metadata.bytes,
                .path = metadata.path,
                .sha256 = &metadata_hex,
            },
            .call_artifact_content_sha256 = artifact.content_sha256,
            .full_call_count = artifact.call_count,
            .full_call_list_commitment_sha256 = artifact.call_list_commitment_sha256,
            .log_size = options.log_size,
            .ordinals = .{ 0, 1 },
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

fn proofWires(
    values: []const hpc.RawProviderPublicationV1,
    hashes: *const [2][64]u8,
) [2]base_receipt.FileIdentity {
    return .{
        .{
            .bytes = values[0].proof.bytes,
            .path = values[0].proof.path,
            .sha256 = &hashes[0],
        },
        .{
            .bytes = values[1].proof.bytes,
            .path = values[1].proof.path,
            .sha256 = &hashes[1],
        },
    };
}

fn correctnessValue(
    serial_raw: []const hpc.RawProviderPublicationV1,
    parallel_raw: []const hpc.RawProviderPublicationV1,
    serial: [2]hpc.FreshProviderCheckV1,
    parallel: [2]hpc.FreshProviderCheckV1,
) receipt.Correctness {
    var result: receipt.Correctness = undefined;
    for (0..2) |index| {
        result.serial_canonical_proof_bytes_equal[index] =
            serial[index].canonical_proof_bytes_equal;
        result.parallel_canonical_proof_bytes_equal[index] =
            parallel[index].canonical_proof_bytes_equal;
        result.serial_fresh_verified[index] =
            serial[index].claim.fresh_provider_stark_verified;
        result.parallel_fresh_verified[index] =
            parallel[index].claim.fresh_provider_stark_verified;
        result.serial_roots_equal_proof[index] = serial[index].stage_a_roots_equal;
        result.parallel_roots_equal_proof[index] = parallel[index].stage_a_roots_equal;
        result.statement_identities_equal[index] = std.meta.eql(
            serial_raw[index].statement.identity,
            parallel_raw[index].statement.identity,
        );
        result.native_claims_equal[index] = std.meta.eql(
            serial[index].claim.native_claim,
            parallel[index].claim.native_claim,
        );
        result.ordered_claims_equal[index] = std.meta.eql(
            serial[index].claim.ordered_call_claim,
            parallel[index].claim.ordered_call_claim,
        );
    }
    result.stage_a_serial_parallel_roots_equal = true;
    return result;
}

fn allCorrect(value: receipt.Correctness) bool {
    return value.stage_a_serial_parallel_roots_equal and
        value.serial_canonical_proof_bytes_equal[0] and
        value.serial_canonical_proof_bytes_equal[1] and
        value.parallel_canonical_proof_bytes_equal[0] and
        value.parallel_canonical_proof_bytes_equal[1] and
        value.serial_fresh_verified[0] and value.serial_fresh_verified[1] and
        value.parallel_fresh_verified[0] and value.parallel_fresh_verified[1] and
        value.serial_roots_equal_proof[0] and value.serial_roots_equal_proof[1] and
        value.parallel_roots_equal_proof[0] and value.parallel_roots_equal_proof[1] and
        value.statement_identities_equal[0] and value.statement_identities_equal[1] and
        value.native_claims_equal[0] and value.native_claims_equal[1] and
        value.ordered_claims_equal[0] and value.ordered_claims_equal[1];
}

fn rawAdmission(options: Options, cpu_workers: u32, jobs: u32) !hpc.RawWorkerAdmissionV1 {
    return hpc.RawWorkerAdmissionV1.create(.{
        .requested_concurrent_jobs = jobs,
        .available_cpu_workers = cpu_workers,
        .work_items = 2,
        .per_job_engine_workers = options.per_job_engine_workers,
        .host_byte_budget = options.host_byte_budget,
        .controller_reserve_bytes = options.controller_reserve_bytes,
        .per_job_rss_budget_bytes = options.per_job_rss_budget_bytes,
    });
}

pub const Options = struct {
    call_artifact: []u8,
    serial_proof_0: []u8,
    serial_proof_1: []u8,
    parallel_proof_0: []u8,
    parallel_proof_1: []u8,
    receipt: []u8,
    power_classification: []u8,
    log_size: u32 = 16,
    slice_offset: usize = 0,
    per_job_engine_workers: u32 = 4,
    host_byte_budget: u64 = hpc.default_host_byte_budget,
    controller_reserve_bytes: u64 = hpc.default_controller_reserve_bytes,
    per_job_rss_budget_bytes: u64 = hpc.default_worker_rss_budget_bytes,

    fn parse(allocator: std.mem.Allocator, arguments: []const []const u8) !Options {
        var paths: [6]?[]const u8 = .{null} ** 6;
        var power: ?[]const u8 = null;
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
            if (std.mem.eql(u8, name, "--call-artifact")) paths[0] = value else if (std.mem.eql(u8, name, "--serial-proof-0")) paths[1] = value else if (std.mem.eql(u8, name, "--serial-proof-1")) paths[2] = value else if (std.mem.eql(u8, name, "--parallel-proof-0")) paths[3] = value else if (std.mem.eql(u8, name, "--parallel-proof-1")) paths[4] = value else if (std.mem.eql(u8, name, "--receipt")) paths[5] = value else if (std.mem.eql(u8, name, "--power-classification")) power = value else if (std.mem.eql(u8, name, "--log-size"))
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
        for (paths) |path| if (path == null) return error.InvalidArguments;
        const power_value = power orelse return error.InvalidArguments;
        if (result.log_size < 4 or result.log_size > 18 or
            result.per_job_engine_workers == 0 or
            result.per_job_engine_workers > 8 or
            (!std.mem.eql(u8, power_value, "ac-high-power-pinned") and
                !std.mem.eql(u8, power_value, "battery-diagnostic")))
        {
            return error.InvalidArguments;
        }
        for (paths, 0..) |path, path_index| {
            if (!std.fs.path.isAbsolute(path.?)) return error.InvalidArguments;
            for (paths[0..path_index]) |previous| {
                if (std.mem.eql(u8, path.?, previous.?))
                    return error.InvalidArguments;
            }
        }
        result.call_artifact = try allocator.dupe(u8, paths[0].?);
        errdefer allocator.free(result.call_artifact);
        result.serial_proof_0 = try allocator.dupe(u8, paths[1].?);
        errdefer allocator.free(result.serial_proof_0);
        result.serial_proof_1 = try allocator.dupe(u8, paths[2].?);
        errdefer allocator.free(result.serial_proof_1);
        result.parallel_proof_0 = try allocator.dupe(u8, paths[3].?);
        errdefer allocator.free(result.parallel_proof_0);
        result.parallel_proof_1 = try allocator.dupe(u8, paths[4].?);
        errdefer allocator.free(result.parallel_proof_1);
        result.receipt = try allocator.dupe(u8, paths[5].?);
        errdefer allocator.free(result.receipt);
        result.power_classification = try allocator.dupe(u8, power_value);
        return result;
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.power_classification);
        allocator.free(self.receipt);
        allocator.free(self.parallel_proof_1);
        allocator.free(self.parallel_proof_0);
        allocator.free(self.serial_proof_1);
        allocator.free(self.serial_proof_0);
        allocator.free(self.call_artifact);
        self.* = undefined;
    }
};

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
