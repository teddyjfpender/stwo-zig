//! Opt-in concurrent-only provider batch with retention-aware RSS admission.
//!
//! Existing serial, raw-pair, raw-batch, topology, and retention-sweep routes
//! remain unchanged.  This route admits `.always` first, falls back to
//! `.never` only when required by the explicit per-job cap, and binds that
//! decision into both the provider statement and a sealed V3 receipt.

const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const call_artifact = @import("ethereum_poseidon_provider_call_artifact_v1.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const geometry_snapshot = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");
const hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");
const base_receipt = @import("ethereum_poseidon_provider_hpc_receipt_v1.zig");
const proof_artifact = @import("ethereum_poseidon_provider_proof_artifact_v1.zig");
const receipt = @import("ethereum_poseidon_provider_retained_batch_receipt_v3.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const resource_usage = @import("resource_usage.zig");
const retention = @import("ethereum_poseidon_provider_retention_admission_v2.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const joint = frontend.testing.narrow_memory_provider_joint_protocol;

pub const execute_flag = "--run-retained-provider-retained-batch-v3";

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
    const admission = try retention.AdmissionV2.create(.{
        .max_shard_log_size = options.log_size,
        .log_blowup_factor = support.recursive_pcs_config
            .fri_config.log_blowup_factor,
        .requested_concurrent_jobs = options.batch_size,
        .available_cpu_workers = cpu_workers,
        .work_items = options.batch_size,
        .per_job_engine_workers = options.per_job_engine_workers,
        .host_byte_budget = options.host_byte_budget,
        .controller_reserve_bytes = options.controller_reserve_bytes,
        .per_job_rss_cap_bytes = options.per_job_rss_cap_bytes,
        .per_job_non_column_reserve_bytes = options.per_job_non_column_reserve_bytes,
    });
    var plan = try authority.ProviderShardPlanV1.create(
        allocator,
        reopened.session,
        calls,
        admission.providerShardRequest(calls.len),
    );
    defer plan.deinit(allocator);
    try admission.validateAgainstPlan(&plan);
    if (plan.shard_count != options.batch_size)
        return error.ProviderBenchmarkShardCountMismatch;

    var stage_clock = try evidence.Clock.start();
    const stage_roots = try hpc.commitStageAParallelBounded(
        hpc.Engine,
        allocator,
        support.recursive_pcs_config,
        &plan,
        calls,
        admission.worker,
    );
    defer allocator.free(stage_roots);
    const stage_timing = try stage_clock.finish();
    try requireWithin(total_timer.read(), options.hard_cap_ns);

    const zero_root = std.mem.zeroes(hpc.Engine.Hasher.Hash);
    var manifest = try joint.JointManifest(hpc.Engine).create(
        allocator,
        &plan,
        calls,
        .{ .preprocessed_root = zero_root, .main_root = zero_root },
        stage_roots,
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
    const jobs = try jobsFor(allocator, paths.proofs);
    defer allocator.free(jobs);

    var proof_timer = try std.time.Timer.start();
    const raw = try retention.proveJointRawParallelBounded(
        allocator,
        source,
        jobs,
        admission,
    );
    defer allocator.free(raw);
    const proof_wall_ns = proof_timer.read();
    try requireWithin(total_timer.read(), options.hard_cap_ns);

    const checks = try allocator.alloc(hpc.FreshProviderCheckV1, raw.len);
    defer allocator.free(checks);
    var verify_timer = try std.time.Timer.start();
    for (checks, raw) |*check, publication| {
        check.* = try hpc.verifyJointRawFresh(
            allocator,
            source,
            publication,
        );
    }
    const verify_wall_ns = verify_timer.read();
    const total_wall_ns = total_timer.read();
    try requireWithin(total_wall_ns, options.hard_cap_ns);

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
    const receipt_bytes = try encodeReceipt(
        allocator,
        options,
        parsed.value,
        metadata_identity,
        plan,
        admission,
        raw,
        checks,
        stage_timing,
        proof_wall_ns,
        verify_wall_ns,
        total_wall_ns,
        usage,
        self_path,
        self_stat.size,
        executable_sha256,
    );
    defer allocator.free(receipt_bytes);
    try receipt.publishCreateOnly(paths.receipt_path, receipt_bytes);
}

fn encodeReceipt(
    allocator: std.mem.Allocator,
    options: Options,
    artifact: call_artifact.Artifact,
    metadata: evidence.FileIdentity,
    plan: authority.ProviderShardPlanV1,
    admission: retention.AdmissionV2,
    raw: []const hpc.RawProviderPublicationV1,
    checks: []const hpc.FreshProviderCheckV1,
    stage_timing: evidence.Timing,
    proof_wall_ns: u64,
    verify_wall_ns: u64,
    total_wall_ns: u64,
    usage: resource_usage.Report,
    executable_path: []const u8,
    executable_bytes: u64,
    executable_sha256: [32]u8,
) ![]u8 {
    if (raw.len != checks.len) return error.ProviderBatchLengthMismatch;
    const count = raw.len;
    const correctness_storage = try allocator.alloc(bool, 6 * count);
    defer allocator.free(correctness_storage);
    const correctness = correctnessValue(correctness_storage, checks);
    const ordinals = try allocator.alloc(u32, count);
    defer allocator.free(ordinals);
    for (ordinals, 0..) |*ordinal, index| ordinal.* = @intCast(index);
    const proof_hashes = try allocator.alloc([64]u8, count);
    defer allocator.free(proof_hashes);
    const proofs = try proofWires(allocator, raw, proof_hashes);
    defer allocator.free(proofs);
    const authority_value = admission.receiptAuthority();
    const admission_identity = hex(authority_value.identity);
    const worker_identity = hex(authority_value.worker_admission_identity);
    const executable_hex = hex(executable_sha256);
    const metadata_hex = hex(metadata.sha256);
    const slice_commitment = hex(plan.call_list_commitment);
    const placeholder = [_]u8{'0'} ** 64;
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
        total_wall_ns <= receipt.performance_time_budget_ns and
        std.mem.eql(
            u8,
            options.power_classification,
            "ac-high-power-pinned",
        ) and usage.availability == .available;
    return receipt.encode(allocator, .{
        .content_sha256 = &placeholder,
        .admission = .{
            .admitted_concurrent_jobs = authority_value.admitted_concurrent_jobs,
            .aggregate_rss_reservation_bytes = authority_value.aggregate_rss_reservation_bytes,
            .always_admitted_peak_bytes = authority_value.always_admitted_peak_bytes,
            .fell_back_to_never = authority_value.fell_back_to_never,
            .format = authority_value.format,
            .identity_sha256 = &admission_identity,
            .never_admitted_peak_bytes = authority_value.never_admitted_peak_bytes,
            .request = .{
                .available_cpu_workers = admission.request.available_cpu_workers,
                .controller_reserve_bytes = admission.request.controller_reserve_bytes,
                .host_byte_budget = admission.request.host_byte_budget,
                .log_blowup_factor = admission.request.log_blowup_factor,
                .max_shard_log_size = admission.request.max_shard_log_size,
                .per_job_engine_workers = admission.request.per_job_engine_workers,
                .per_job_non_column_reserve_bytes = admission.request.per_job_non_column_reserve_bytes,
                .per_job_rss_cap_bytes = admission.request.per_job_rss_cap_bytes,
                .requested_concurrent_jobs = admission.request.requested_concurrent_jobs,
                .work_items = admission.request.work_items,
            },
            .selected_coefficient_retention = authority_value.selected_coefficient_retention,
            .worker_admission_identity_sha256 = &worker_identity,
        },
        .benchmark_executable = .{
            .bytes = executable_bytes,
            .path = executable_path,
            .sha256 = &executable_hex,
        },
        .correctness = correctness,
        .performance_claim_eligible = eligible,
        .production_eligible = false,
        .profile = .{
            .build_mode = @tagName(builtin.mode),
            .composition_columns = 8,
            .coefficient_retention = authority_value.selected_coefficient_retention,
            .host_power_classification = options.power_classification,
            .main_columns = 445,
            .preprocessed_columns = 2,
            .provider_profile = "ordered-provider-v2",
            .synthetic_core_stage_a = true,
            .tree2_columns = 12,
        },
        .proofs = proofs,
        .recursive_admissible = false,
        .resource_usage = resource_value,
        .schema = receipt.schema,
        .status = if (eligible) receipt.status_fresh else receipt.status_nonranking,
        .timing_scope = receipt.timing_scope,
        .timings = .{
            .cold_verify_wall_ns = verify_wall_ns,
            .proof_batch_wall_ns = proof_wall_ns,
            .stage_a = stage_timing,
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

fn correctnessValue(
    storage: []bool,
    checks: []const hpc.FreshProviderCheckV1,
) receipt.Correctness {
    const count = checks.len;
    std.debug.assert(storage.len == 6 * count);
    const canonical = storage[0 * count .. 1 * count];
    const fresh = storage[1 * count .. 2 * count];
    const native = storage[2 * count .. 3 * count];
    const ordered = storage[3 * count .. 4 * count];
    const roots = storage[4 * count .. 5 * count];
    const statements = storage[5 * count .. 6 * count];
    for (checks, 0..) |check, index| {
        canonical[index] = check.canonical_proof_bytes_equal;
        fresh[index] = check.claim.fresh_provider_stark_verified;
        native[index] = check.native_claim_equal;
        ordered[index] = check.ordered_claim_equal;
        roots[index] = check.stage_a_roots_equal;
        statements[index] = check.statement_identity_equal;
    }
    return .{
        .canonical_proof_bytes_equal = canonical,
        .fresh_verified = fresh,
        .native_claims_equal = native,
        .ordered_claims_equal = ordered,
        .stage_a_roots_equal = roots,
        .statement_identities_equal = statements,
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

const OutputPaths = struct {
    proofs: [][]u8,
    receipt_path: []u8,

    fn init(
        allocator: std.mem.Allocator,
        root: []const u8,
        count: u32,
    ) !OutputPaths {
        const proofs = try allocator.alloc([]u8, count);
        errdefer allocator.free(proofs);
        var initialized: usize = 0;
        errdefer for (proofs[0..initialized]) |path| allocator.free(path);
        for (proofs, 0..) |*path, index| {
            const name = try std.fmt.allocPrint(
                allocator,
                "retained-ordinal{d}.stw",
                .{index},
            );
            defer allocator.free(name);
            path.* = try artifact_io.resolveCreateOnlyChild(
                allocator,
                root,
                name,
            );
            initialized += 1;
        }
        const receipt_path = try artifact_io.resolveCreateOnlyChild(
            allocator,
            root,
            "retained-batch-v3-receipt.json",
        );
        return .{ .proofs = proofs, .receipt_path = receipt_path };
    }

    fn requireFresh(self: OutputPaths) !void {
        for (self.proofs) |path| try requireAbsent(path);
        try requireAbsent(self.receipt_path);
    }

    fn deinit(self: *OutputPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.receipt_path);
        for (self.proofs) |path| allocator.free(path);
        allocator.free(self.proofs);
        self.* = undefined;
    }
};

pub const Options = struct {
    batch_size: u32,
    call_artifact: []u8,
    controller_reserve_bytes: u64 = hpc.default_controller_reserve_bytes,
    hard_cap_ns: u64 = receipt.performance_time_budget_ns,
    host_byte_budget: u64 = hpc.default_host_byte_budget,
    log_size: u32 = 16,
    output_root: []u8,
    per_job_engine_workers: u32 = 4,
    per_job_non_column_reserve_bytes: u64 =
        retention.default_per_job_non_column_reserve_bytes,
    per_job_rss_cap_bytes: u64 = hpc.default_worker_rss_budget_bytes,
    power_classification: []u8,
    slice_offset: usize = 0,

    fn parse(allocator: std.mem.Allocator, arguments: []const []const u8) !Options {
        var call_path: ?[]const u8 = null;
        var output_root: ?[]const u8 = null;
        var power: ?[]const u8 = null;
        var batch_size: ?u32 = null;
        var result: Options = undefined;
        result.controller_reserve_bytes = hpc.default_controller_reserve_bytes;
        result.hard_cap_ns = receipt.performance_time_budget_ns;
        result.host_byte_budget = hpc.default_host_byte_budget;
        result.log_size = 16;
        result.per_job_engine_workers = 4;
        result.per_job_non_column_reserve_bytes =
            retention.default_per_job_non_column_reserve_bytes;
        result.per_job_rss_cap_bytes = hpc.default_worker_rss_budget_bytes;
        result.slice_offset = 0;
        var seen: u16 = 0;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 >= arguments.len) return error.InvalidArguments;
            const name = arguments[index];
            const value = arguments[index + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(u8, name, "--call-artifact")) {
                try markSeen(&seen, 0);
                call_path = value;
            } else if (std.mem.eql(u8, name, "--output-root")) {
                try markSeen(&seen, 1);
                output_root = value;
            } else if (std.mem.eql(u8, name, "--power-classification")) {
                try markSeen(&seen, 2);
                power = value;
            } else if (std.mem.eql(u8, name, "--batch-size")) {
                try markSeen(&seen, 3);
                batch_size = try parseInt(u32, value);
            } else if (std.mem.eql(u8, name, "--log-size")) {
                try markSeen(&seen, 4);
                result.log_size = try parseInt(u32, value);
            } else if (std.mem.eql(u8, name, "--slice-offset")) {
                try markSeen(&seen, 5);
                result.slice_offset = try parseInt(usize, value);
            } else if (std.mem.eql(u8, name, "--per-job-engine-workers")) {
                try markSeen(&seen, 6);
                result.per_job_engine_workers = try parseInt(u32, value);
            } else if (std.mem.eql(u8, name, "--host-byte-budget")) {
                try markSeen(&seen, 7);
                result.host_byte_budget = try parseInt(u64, value);
            } else if (std.mem.eql(u8, name, "--controller-reserve-bytes")) {
                try markSeen(&seen, 8);
                result.controller_reserve_bytes = try parseInt(u64, value);
            } else if (std.mem.eql(u8, name, "--per-job-rss-cap-bytes")) {
                try markSeen(&seen, 9);
                result.per_job_rss_cap_bytes = try parseInt(u64, value);
            } else if (std.mem.eql(u8, name, "--per-job-non-column-reserve-bytes")) {
                try markSeen(&seen, 10);
                result.per_job_non_column_reserve_bytes =
                    try parseInt(u64, value);
            } else if (std.mem.eql(u8, name, "--hard-cap-seconds")) {
                try markSeen(&seen, 11);
                result.hard_cap_ns = try secondsToNs(value);
            } else {
                return error.InvalidArguments;
            }
        }
        const raw_call = call_path orelse return error.InvalidArguments;
        const raw_root = output_root orelse return error.InvalidArguments;
        const raw_power = power orelse return error.InvalidArguments;
        result.batch_size = batch_size orelse return error.InvalidArguments;
        if (result.batch_size == 0 or
            result.batch_size > receipt.max_batch_size or
            result.log_size < 4 or result.log_size > 20 or
            result.per_job_engine_workers == 0 or
            result.per_job_engine_workers > 8 or result.hard_cap_ns == 0 or
            result.hard_cap_ns > receipt.performance_time_budget_ns or
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

fn requireWithin(elapsed_ns: u64, hard_cap_ns: u64) !void {
    if (elapsed_ns > hard_cap_ns) return error.ProviderBenchmarkTimeBudgetExceeded;
}

fn markSeen(seen: *u16, index: u4) !void {
    const mask: u16 = @as(u16, 1) << index;
    if (seen.* & mask != 0) return error.DuplicateArgument;
    seen.* |= mask;
}

fn parseInt(comptime T: type, value: []const u8) !T {
    return std.fmt.parseUnsigned(T, value, 10) catch
        return error.InvalidArguments;
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
    pub fn parseOptions(allocator: std.mem.Allocator) !void {
        var options = try Options.parse(allocator, &.{
            "--call-artifact",
            "/retained/calls.json",
            "--output-root",
            "/fresh/retained-batch-v3",
            "--power-classification",
            "battery-diagnostic",
            "--batch-size",
            "4",
            "--log-size",
            "16",
            "--hard-cap-seconds",
            "60",
        });
        defer options.deinit(allocator);
        try std.testing.expectEqual(@as(u32, 4), options.batch_size);
        try std.testing.expectEqual(
            receipt.performance_time_budget_ns,
            options.hard_cap_ns,
        );
        try std.testing.expectError(
            error.InvalidArguments,
            Options.parse(allocator, &.{
                "--call-artifact",
                "/retained/calls.json",
                "--output-root",
                "/fresh/retained-batch-v3",
                "--power-classification",
                "battery-diagnostic",
                "--batch-size",
                "4",
                "--hard-cap-seconds",
                "61",
            }),
        );
    }
};

comptime {
    if (authority.main_column_count != retention.provider_main_columns)
        @compileError("retention-aware provider geometry drifted");
    _ = proof_artifact.max_proof_bytes;
}
