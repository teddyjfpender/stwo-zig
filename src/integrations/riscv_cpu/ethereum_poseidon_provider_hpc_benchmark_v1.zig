//! Bounded retained-call provider benchmark. It never executes a guest block.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const call_artifact = @import("ethereum_poseidon_provider_call_artifact_v1.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const geometry_snapshot = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");
const hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");
const receipt_v1 = @import("ethereum_poseidon_provider_hpc_receipt_v1.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const resource_usage = @import("resource_usage.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const harness = frontend.testing.narrow_memory_provider_proof_harness;
const joint = frontend.testing.narrow_memory_provider_joint_protocol;

pub const execute_flag = "--run-retained-provider-slice";
pub const default_log_size: u32 = 16;
pub const default_shard_count: u32 = 4;

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var options = try Options.parse(allocator, arguments);
    defer options.deinit(allocator);
    var total_timer = try std.time.Timer.start();
    const usage_before = resource_usage.capture();

    const artifact_bytes = try artifact_io.readFileBounded(
        allocator,
        options.call_artifact,
        call_artifact.max_metadata_bytes,
    );
    defer allocator.free(artifact_bytes);
    var parsed_artifact = try call_artifact.parse(allocator, artifact_bytes);
    defer parsed_artifact.deinit();
    const artifact_file = evidence.identity(
        options.call_artifact,
        artifact_bytes,
    );

    const geometry_bytes = try support.readIdentity(
        allocator,
        parsed_artifact.value.geometry_snapshot,
        geometry_snapshot.max_snapshot_bytes,
    );
    defer allocator.free(geometry_bytes);
    var geometry = try geometry_snapshot.parse(allocator, geometry_bytes);
    defer geometry.deinit();
    const geometry_file = evidence.identity(
        parsed_artifact.value.geometry_snapshot.path,
        geometry_bytes,
    );
    const whole_resource = try resource.ProviderResourcePlanV1.create(
        &geometry.value,
        geometry_file.sha256,
    );
    var reopened = try call_artifact.reopen(
        allocator,
        parsed_artifact.value,
        &whole_resource,
    );
    defer reopened.deinit(allocator);

    const rows_per_shard = try powerOfTwo(options.log_size);
    const slice_count = std.math.mul(
        usize,
        rows_per_shard,
        options.shard_count,
    ) catch return error.ProviderBenchmarkSliceOverflow;
    const slice_end = std.math.add(
        usize,
        options.slice_offset,
        slice_count,
    ) catch return error.ProviderBenchmarkSliceOverflow;
    if (slice_end > reopened.calls.len)
        return error.ProviderBenchmarkSliceOutOfRange;
    const calls = reopened.calls[options.slice_offset..slice_end];
    const cpu_workers = std.math.cast(
        u32,
        try std.Thread.getCpuCount(),
    ) orelse std.math.maxInt(u32);
    const admission = try hpc.WorkerAdmissionV1.create(.{
        .requested_workers = options.requested_workers,
        .available_cpu_workers = cpu_workers,
        .work_items = options.shard_count,
        .host_byte_budget = options.host_byte_budget,
        .controller_reserve_bytes = options.controller_reserve_bytes,
        .worker_rss_budget_bytes = options.worker_rss_budget_bytes,
    });
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
            .requested_parallel_shards = admission.admitted_workers,
        },
    );
    defer plan.deinit(allocator);
    if (plan.shard_count != options.shard_count)
        return error.ProviderBenchmarkShardCountMismatch;

    const serial_roots = try allocator.alloc(
        harness.StageACommitment(hpc.Engine),
        plan.shards.len,
    );
    defer allocator.free(serial_roots);
    var serial_stage_a_clock = try evidence.Clock.start();
    for (serial_roots, 0..) |*roots, index| {
        roots.* = try harness.commitStageA(
            hpc.Engine,
            allocator,
            support.recursive_pcs_config,
            &plan,
            calls,
            @intCast(index),
        );
    }
    const serial_stage_a = try serial_stage_a_clock.finish();

    var parallel_stage_a_clock = try evidence.Clock.start();
    const parallel_roots = try hpc.commitStageAParallel(
        hpc.Engine,
        allocator,
        support.recursive_pcs_config,
        &plan,
        calls,
        admission,
    );
    defer allocator.free(parallel_roots);
    const parallel_stage_a = try parallel_stage_a_clock.finish();
    const roots_equal = rootsEqual(serial_roots, parallel_roots);
    if (!roots_equal) return error.ProviderStageAParallelRootMismatch;

    const zero_root = std.mem.zeroes(hpc.Engine.Hasher.Hash);
    var manifest = try joint.JointManifest(hpc.Engine).create(
        allocator,
        &plan,
        calls,
        .{
            .preprocessed_root = zero_root,
            .main_root = zero_root,
        },
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
    const prove_admission = try hpc.WorkerAdmissionV1.create(.{
        .requested_workers = 1,
        .available_cpu_workers = cpu_workers,
        .work_items = 1,
        .host_byte_budget = options.host_byte_budget,
        .controller_reserve_bytes = options.controller_reserve_bytes,
        .worker_rss_budget_bytes = options.worker_rss_budget_bytes,
    });
    const jobs = [_]hpc.RawProviderJobV1{.{
        .ordinal = options.proved_ordinal,
        .proof_path = options.proof,
    }};
    const raw = try hpc.proveJointRawParallel(
        allocator,
        source,
        &jobs,
        prove_admission,
    );
    defer allocator.free(raw);
    const fresh = try hpc.verifyJointRawFresh(allocator, source, raw[0]);
    try fresh.validate();

    const total_wall_ns = total_timer.read();
    const usage_after = resource_usage.capture();
    const usage = resource_usage.report(usage_before, usage_after);
    const executable_sha256 = try support.executableSha256(allocator);
    const bytes = try encodeReceipt(
        allocator,
        options,
        parsed_artifact.value,
        artifact_file,
        plan,
        admission,
        raw[0],
        fresh,
        roots_equal,
        serial_stage_a,
        parallel_stage_a,
        total_wall_ns,
        usage,
        executable_sha256,
    );
    defer allocator.free(bytes);
    try receipt_v1.publishCreateOnly(options.receipt, bytes);
}

fn encodeReceipt(
    allocator: std.mem.Allocator,
    options: Options,
    artifact: call_artifact.Artifact,
    artifact_file: evidence.FileIdentity,
    plan: authority.ProviderShardPlanV1,
    admission: hpc.WorkerAdmissionV1,
    raw: hpc.RawProviderPublicationV1,
    fresh: hpc.FreshProviderCheckV1,
    roots_equal: bool,
    serial_stage_a: evidence.Timing,
    parallel_stage_a: evidence.Timing,
    total_wall_ns: u64,
    usage: resource_usage.Report,
    executable_sha256: [32]u8,
) ![]u8 {
    const placeholder = [_]u8{'0'} ** 64;
    const executable = hex(executable_sha256);
    const admission_identity = hex(admission.identity);
    const artifact_sha = hex(artifact_file.sha256);
    const proof_sha = hex(raw.proof.sha256);
    const statement_identity = hex(raw.statement.identity);
    const claim_identity = hex(fresh.claim.identity);
    const slice_commitment = hex(plan.call_list_commitment);
    const serial_batch_wall = std.math.mul(
        u64,
        raw.prove_wall_ns,
        plan.shard_count,
    ) catch std.math.maxInt(u64);
    const ideal_wall = divCeil(serial_batch_wall, admission.admitted_workers);
    const parallel_stage_a_speedup = ratioMilli(
        serial_stage_a.wall_ns,
        parallel_stage_a.wall_ns,
    );
    const usage_value: receipt_v1.ResourceUsage = if (usage.availability == .available) .{
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
    const correct = fresh.canonical_proof_bytes_equal and
        fresh.stage_a_roots_equal and fresh.statement_identity_equal and
        fresh.native_claim_equal and fresh.ordered_claim_equal and roots_equal;
    const eligible = correct and
        total_wall_ns <= receipt_v1.performance_time_budget_ns and
        std.mem.eql(
            u8,
            options.power_classification,
            "ac-high-power-pinned",
        );
    return receipt_v1.encode(allocator, .{
        .content_sha256 = &placeholder,
        .admission = .{
            .admitted_workers = admission.admitted_workers,
            .available_cpu_workers = admission.available_cpu_workers,
            .concurrent_worker_reservation_bytes = admission.concurrent_worker_reservation_bytes,
            .controller_reserve_bytes = admission.controller_reserve_bytes,
            .host_byte_budget = admission.host_byte_budget,
            .identity_sha256 = &admission_identity,
            .requested_workers = admission.requested_workers,
            .worker_rss_budget_bytes = admission.worker_rss_budget_bytes,
            .work_items = admission.work_items,
        },
        .benchmark_executable_sha256 = &executable,
        .candidate = .{
            .ideal_parallel_batch_wall_ns = ideal_wall,
            .ideal_parallel_speedup_milli = admission.admitted_workers * 1000,
            .model = "single-shard-linear-upper-bound",
            .parallel_stage_a_speedup_milli = parallel_stage_a_speedup,
        },
        .correctness = .{
            .canonical_proof_bytes_equal = fresh.canonical_proof_bytes_equal,
            .fresh_verified = true,
            .native_claim_equal = fresh.native_claim_equal,
            .ordered_claim_equal = fresh.ordered_claim_equal,
            .stage_a_parallel_roots_equal = roots_equal,
            .stage_a_roots_equal_proof = fresh.stage_a_roots_equal,
            .statement_identity_equal = fresh.statement_identity_equal,
        },
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
        .proof = .{
            .bytes = raw.proof.bytes,
            .path = raw.proof.path,
            .sha256 = &proof_sha,
        },
        .proof_statement_identity_sha256 = &statement_identity,
        .provider_claim_identity_sha256 = &claim_identity,
        .recursive_admissible = false,
        .resource_usage = usage_value,
        .schema = receipt_v1.schema,
        .status = if (eligible)
            receipt_v1.status_fresh
        else
            receipt_v1.status_nonranking,
        .timing_scope = receipt_v1.timing_scope,
        .timings = .{
            .cold_verify = fresh.verify_timing,
            .parallel_stage_a = parallel_stage_a,
            .provider_prove_wall_ns = raw.prove_wall_ns,
            .serial_stage_a = serial_stage_a,
            .total_wall_ns = total_wall_ns,
        },
        .workload = .{
            .call_artifact = .{
                .bytes = artifact_file.bytes,
                .path = artifact_file.path,
                .sha256 = &artifact_sha,
            },
            .call_artifact_content_sha256 = artifact.content_sha256,
            .full_call_count = artifact.call_count,
            .full_call_list_commitment_sha256 = artifact.call_list_commitment_sha256,
            .log_size = options.log_size,
            .proved_ordinal = options.proved_ordinal,
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

pub const Options = struct {
    call_artifact: []u8,
    proof: []u8,
    receipt: []u8,
    power_classification: []u8,
    log_size: u32 = default_log_size,
    shard_count: u32 = default_shard_count,
    slice_offset: usize = 0,
    proved_ordinal: u32 = 0,
    requested_workers: u32 = hpc.max_workers,
    host_byte_budget: u64 = hpc.default_host_byte_budget,
    controller_reserve_bytes: u64 = hpc.default_controller_reserve_bytes,
    worker_rss_budget_bytes: u64 = hpc.default_worker_rss_budget_bytes,

    fn parse(
        allocator: std.mem.Allocator,
        arguments: []const []const u8,
    ) !Options {
        var call_path: ?[]const u8 = null;
        var proof_path: ?[]const u8 = null;
        var receipt_path: ?[]const u8 = null;
        var power: ?[]const u8 = null;
        var result: Options = undefined;
        result.log_size = default_log_size;
        result.shard_count = default_shard_count;
        result.slice_offset = 0;
        result.proved_ordinal = 0;
        result.requested_workers = hpc.max_workers;
        result.host_byte_budget = hpc.default_host_byte_budget;
        result.controller_reserve_bytes = hpc.default_controller_reserve_bytes;
        result.worker_rss_budget_bytes = hpc.default_worker_rss_budget_bytes;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 >= arguments.len) return error.InvalidArguments;
            const name = arguments[index];
            const value = arguments[index + 1];
            if (std.mem.eql(u8, name, "--call-artifact"))
                call_path = value
            else if (std.mem.eql(u8, name, "--proof"))
                proof_path = value
            else if (std.mem.eql(u8, name, "--receipt"))
                receipt_path = value
            else if (std.mem.eql(u8, name, "--power-classification"))
                power = value
            else if (std.mem.eql(u8, name, "--log-size"))
                result.log_size = try parseInt(u32, value)
            else if (std.mem.eql(u8, name, "--shard-count"))
                result.shard_count = try parseInt(u32, value)
            else if (std.mem.eql(u8, name, "--slice-offset"))
                result.slice_offset = try parseInt(usize, value)
            else if (std.mem.eql(u8, name, "--proved-ordinal"))
                result.proved_ordinal = try parseInt(u32, value)
            else if (std.mem.eql(u8, name, "--requested-workers"))
                result.requested_workers = try parseInt(u32, value)
            else if (std.mem.eql(u8, name, "--host-byte-budget"))
                result.host_byte_budget = try parseInt(u64, value)
            else if (std.mem.eql(u8, name, "--controller-reserve-bytes"))
                result.controller_reserve_bytes = try parseInt(u64, value)
            else if (std.mem.eql(u8, name, "--worker-rss-budget-bytes"))
                result.worker_rss_budget_bytes = try parseInt(u64, value)
            else
                return error.InvalidArguments;
        }
        if (result.log_size < 4 or result.log_size > 18 or
            result.shard_count == 0 or result.shard_count > 16 or
            result.proved_ordinal >= result.shard_count)
        {
            return error.InvalidProviderBenchmarkGeometry;
        }
        const raw_call = call_path orelse return error.InvalidArguments;
        const raw_proof = proof_path orelse return error.InvalidArguments;
        const raw_receipt = receipt_path orelse return error.InvalidArguments;
        const raw_power = power orelse return error.InvalidArguments;
        if ((!std.mem.eql(u8, raw_power, "ac-high-power-pinned") and
            !std.mem.eql(u8, raw_power, "battery-diagnostic")) or
            !std.fs.path.isAbsolute(raw_call) or
            !std.fs.path.isAbsolute(raw_proof) or
            !std.fs.path.isAbsolute(raw_receipt) or
            std.mem.eql(u8, raw_call, raw_proof) or
            std.mem.eql(u8, raw_call, raw_receipt) or
            std.mem.eql(u8, raw_proof, raw_receipt))
        {
            return error.InvalidArguments;
        }
        result.call_artifact = try allocator.dupe(u8, raw_call);
        errdefer allocator.free(result.call_artifact);
        result.proof = try allocator.dupe(u8, raw_proof);
        errdefer allocator.free(result.proof);
        result.receipt = try allocator.dupe(u8, raw_receipt);
        errdefer allocator.free(result.receipt);
        result.power_classification = try allocator.dupe(u8, raw_power);
        return result;
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.power_classification);
        allocator.free(self.receipt);
        allocator.free(self.proof);
        allocator.free(self.call_artifact);
        self.* = undefined;
    }
};

fn parseInt(comptime T: type, bytes: []const u8) !T {
    return std.fmt.parseUnsigned(T, bytes, 10) catch
        return error.InvalidArguments;
}

fn powerOfTwo(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize))
        return error.InvalidProviderBenchmarkGeometry;
    return @as(usize, 1) << @intCast(log_size);
}

fn ratioMilli(numerator: u64, denominator: u64) u32 {
    if (denominator == 0) return 0;
    const scaled = std.math.mul(u64, numerator, 1000) catch
        return std.math.maxInt(u32);
    return std.math.cast(u32, scaled / denominator) orelse
        std.math.maxInt(u32);
}

fn divCeil(numerator: u64, denominator: u32) u64 {
    return std.math.divCeil(u64, numerator, denominator) catch
        std.math.maxInt(u64);
}

fn rootsEqual(
    left: []const harness.StageACommitment(hpc.Engine),
    right: []const harness.StageACommitment(hpc.Engine),
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (!std.meta.eql(a, b)) return false;
    }
    return true;
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

pub const testing = struct {
    pub fn parse(
        allocator: std.mem.Allocator,
        arguments: []const []const u8,
    ) !Options {
        return Options.parse(allocator, arguments);
    }
};
