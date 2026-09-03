//! Canonical telemetry for configurable serial-vs-concurrent provider proofs.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");
const receipt_v1 = @import("ethereum_poseidon_provider_hpc_receipt_v1.zig");

pub const schema = "stwo.ethereum.poseidon-provider-raw-batch-hpc-benchmark.v2";
pub const timing_scope = "retained-provider-batch-self-process";
pub const status_fresh = "diagnostic-batch-fresh-verified";
pub const status_nonranking = "diagnostic-batch-fresh-verified-nonranking";
pub const max_batch_size: u32 = 4;
pub const max_receipt_bytes: usize = 2 * 1024 * 1024;

pub const RawAdmission = struct {
    admitted_concurrent_jobs: u32,
    aggregate_engine_stack_reservation_bytes: u64,
    aggregate_engine_workers: u32,
    aggregate_rss_reservation_bytes: u64,
    available_cpu_workers: u32,
    controller_reserve_bytes: u64,
    host_byte_budget: u64,
    identity_sha256: []const u8,
    per_job_engine_workers: u32,
    per_job_rss_budget_bytes: u64,
    requested_concurrent_jobs: u32,
    work_items: u32,
};

pub const Correctness = struct {
    exact_serial_parallel_proof_bytes_equal: []const bool,
    parallel_canonical_proof_bytes_equal: []const bool,
    parallel_fresh_verified: []const bool,
    parallel_roots_equal_proof: []const bool,
    serial_canonical_proof_bytes_equal: []const bool,
    serial_fresh_verified: []const bool,
    serial_roots_equal_proof: []const bool,
    stage_a_serial_parallel_roots_equal: bool,
    statement_identities_equal: []const bool,
    native_claims_equal: []const bool,
    ordered_claims_equal: []const bool,
};

pub const Timings = struct {
    concurrent_cold_verify_wall_ns: u64,
    concurrent_proof_batch_wall_ns: u64,
    concurrent_stage_a: evidence.Timing,
    serial_cold_verify_wall_ns: u64,
    serial_proof_batch_wall_ns: u64,
    serial_stage_a: evidence.Timing,
    total_wall_ns: u64,
};

pub const ProofBatch = struct {
    concurrent: []const receipt_v1.FileIdentity,
    serial: []const receipt_v1.FileIdentity,
};

pub const Workload = struct {
    batch_size: u32,
    call_artifact: receipt_v1.FileIdentity,
    call_artifact_content_sha256: []const u8,
    full_call_count: u64,
    full_call_list_commitment_sha256: []const u8,
    log_size: u32,
    ordinals: []const u32,
    raw_call_file: receipt_v1.FileIdentity,
    session_sha256: []const u8,
    shard_count: u32,
    slice_call_count: u64,
    slice_call_list_commitment_sha256: []const u8,
    slice_offset: u64,
    source_producer_sha256: []const u8,
};

pub const Receipt = struct {
    content_sha256: []const u8,
    benchmark_executable: receipt_v1.FileIdentity,
    concurrent_admission: RawAdmission,
    correctness: Correctness,
    parallel_proof_speedup_milli: u32,
    parallel_stage_a_speedup_milli: u32,
    performance_claim_eligible: bool,
    production_eligible: bool,
    profile: receipt_v1.Profile,
    proofs: ProofBatch,
    recursive_admissible: bool,
    resource_usage: receipt_v1.ResourceUsage,
    schema: []const u8,
    serial_admission: RawAdmission,
    status: []const u8,
    timing_scope: []const u8,
    timings: Timings,
    workload: Workload,

    pub fn validate(self: Receipt) !void {
        const count: usize = @intCast(self.workload.batch_size);
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.timing_scope, timing_scope) or
            self.production_eligible or self.recursive_admissible or
            self.workload.batch_size == 0 or
            self.workload.batch_size > max_batch_size or
            self.workload.shard_count != self.workload.batch_size or
            self.workload.log_size < 4 or self.workload.log_size > 18 or
            self.workload.slice_call_count == 0 or
            self.timings.serial_proof_batch_wall_ns == 0 or
            self.timings.concurrent_proof_batch_wall_ns == 0 or
            self.timings.serial_stage_a.wall_ns == 0 or
            self.timings.concurrent_stage_a.wall_ns == 0 or
            self.timings.serial_cold_verify_wall_ns == 0 or
            self.timings.concurrent_cold_verify_wall_ns == 0 or
            self.timings.total_wall_ns == 0 or
            self.profile.preprocessed_columns != 2 or
            self.profile.main_columns != 445 or
            self.profile.tree2_columns != 12 or
            self.profile.composition_columns != 8 or
            !std.mem.eql(u8, self.profile.coefficient_retention, "never") or
            !std.mem.eql(u8, self.profile.provider_profile, "ordered-provider-v2") or
            !self.profile.synthetic_core_stage_a or
            self.proofs.serial.len != count or
            self.proofs.concurrent.len != count or
            self.workload.ordinals.len != count)
        {
            return error.InvalidProviderRawBatchReceipt;
        }
        try requireCorrectnessLengths(self.correctness, count);
        try validateAdmission(self.serial_admission, 1, self.workload.batch_size);
        try validateAdmission(
            self.concurrent_admission,
            self.workload.batch_size,
            self.workload.batch_size,
        );
        try validateFile(self.benchmark_executable);
        try validateFile(self.workload.call_artifact);
        try validateFile(self.workload.raw_call_file);
        for (self.proofs.serial) |proof| try validateFile(proof);
        for (self.proofs.concurrent) |proof| try validateFile(proof);
        inline for (.{
            self.content_sha256,
            self.workload.call_artifact_content_sha256,
            self.workload.full_call_list_commitment_sha256,
            self.workload.session_sha256,
            self.workload.slice_call_list_commitment_sha256,
            self.workload.source_producer_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        for (self.workload.ordinals, 0..) |ordinal, index| {
            if (ordinal != index) return error.InvalidProviderRawBatchReceipt;
        }
        const expected_count = std.math.mul(
            u64,
            @as(u64, 1) << @intCast(self.workload.log_size),
            self.workload.shard_count,
        ) catch return error.InvalidProviderRawBatchReceipt;
        const slice_end = std.math.add(
            u64,
            self.workload.slice_offset,
            self.workload.slice_call_count,
        ) catch return error.InvalidProviderRawBatchReceipt;
        if (expected_count != self.workload.slice_call_count or
            slice_end > self.workload.full_call_count or
            self.parallel_proof_speedup_milli != ratioMilli(
                self.timings.serial_proof_batch_wall_ns,
                self.timings.concurrent_proof_batch_wall_ns,
            ) or self.parallel_stage_a_speedup_milli != ratioMilli(
            self.timings.serial_stage_a.wall_ns,
            self.timings.concurrent_stage_a.wall_ns,
        )) {
            return error.InvalidProviderRawBatchReceipt;
        }
        const correct = try allCorrect(self.correctness);
        const eligible = correct and
            self.timings.total_wall_ns <= receipt_v1.performance_time_budget_ns and
            std.mem.eql(u8, self.profile.host_power_classification, "ac-high-power-pinned") and
            std.mem.eql(u8, self.resource_usage.availability, "available") and
            self.resource_usage.lifetime_peak_physical_footprint_bytes != null;
        if (self.performance_claim_eligible != eligible or
            !std.mem.eql(u8, self.status, if (eligible) status_fresh else status_nonranking))
        {
            return error.InvalidProviderRawBatchReceipt;
        }
    }
};

pub fn encode(allocator: std.mem.Allocator, value: Receipt) ![]u8 {
    try value.validate();
    const placeholder = [_]u8{'0'} ** 64;
    var temporary = value;
    temporary.content_sha256 = &placeholder;
    const canonical = try std.json.Stringify.valueAlloc(allocator, temporary, .{});
    defer allocator.free(canonical);
    const unsigned = try removeContent(allocator, canonical);
    defer allocator.free(unsigned);
    const bytes = try evidence.seal(allocator, unsigned);
    errdefer allocator.free(bytes);
    var parsed = try parse(allocator, bytes);
    parsed.deinit();
    return bytes;
}

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Receipt) {
    if (bytes.len == 0 or bytes.len > max_receipt_bytes or
        bytes[bytes.len - 1] != '\n') return error.InvalidCanonicalJson;
    var parsed = try std.json.parseFromSlice(Receipt, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(canonical);
    if (canonical.len + 1 != bytes.len or
        !std.mem.eql(u8, canonical, bytes[0..canonical.len]))
    {
        return error.InvalidCanonicalJson;
    }
    try parsed.value.validate();
    try validateContent(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn publishCreateOnly(path: []const u8, bytes: []const u8) !void {
    return artifact_io.publishCreateOnlyDurable(path, bytes);
}

pub fn allCorrect(value: Correctness) !bool {
    const count = value.exact_serial_parallel_proof_bytes_equal.len;
    try requireCorrectnessLengths(value, count);
    if (!value.stage_a_serial_parallel_roots_equal) return false;
    inline for (.{
        value.exact_serial_parallel_proof_bytes_equal,
        value.parallel_canonical_proof_bytes_equal,
        value.parallel_fresh_verified,
        value.parallel_roots_equal_proof,
        value.serial_canonical_proof_bytes_equal,
        value.serial_fresh_verified,
        value.serial_roots_equal_proof,
        value.statement_identities_equal,
        value.native_claims_equal,
        value.ordered_claims_equal,
    }) |values| for (values) |item| if (!item) return false;
    return true;
}

fn requireCorrectnessLengths(value: Correctness, expected: usize) !void {
    inline for (.{
        value.exact_serial_parallel_proof_bytes_equal,
        value.parallel_canonical_proof_bytes_equal,
        value.parallel_fresh_verified,
        value.parallel_roots_equal_proof,
        value.serial_canonical_proof_bytes_equal,
        value.serial_fresh_verified,
        value.serial_roots_equal_proof,
        value.statement_identities_equal,
        value.native_claims_equal,
        value.ordered_claims_equal,
    }) |values| if (values.len != expected)
        return error.InvalidProviderRawBatchReceipt;
}

fn validateAdmission(
    value: RawAdmission,
    expected_jobs: u32,
    expected_work_items: u32,
) !void {
    const identity = try contract.parseSha256(value.identity_sha256);
    const admitted = try hpc.RawWorkerAdmissionV1.create(.{
        .requested_concurrent_jobs = value.requested_concurrent_jobs,
        .available_cpu_workers = value.available_cpu_workers,
        .work_items = value.work_items,
        .per_job_engine_workers = value.per_job_engine_workers,
        .host_byte_budget = value.host_byte_budget,
        .controller_reserve_bytes = value.controller_reserve_bytes,
        .per_job_rss_budget_bytes = value.per_job_rss_budget_bytes,
    });
    if (value.work_items != expected_work_items or
        admitted.admitted_concurrent_jobs != expected_jobs or
        admitted.admitted_concurrent_jobs != value.admitted_concurrent_jobs or
        admitted.aggregate_engine_workers != value.aggregate_engine_workers or
        admitted.aggregate_rss_reservation_bytes != value.aggregate_rss_reservation_bytes or
        admitted.aggregate_engine_stack_reservation_bytes !=
            value.aggregate_engine_stack_reservation_bytes or
        !std.mem.eql(u8, &admitted.identity, &identity))
    {
        return error.InvalidProviderRawBatchReceipt;
    }
}

fn validateFile(value: receipt_v1.FileIdentity) !void {
    if (value.bytes == 0 or !std.fs.path.isAbsolute(value.path))
        return error.InvalidProviderRawBatchReceipt;
    _ = try contract.parseSha256(value.sha256);
}

fn ratioMilli(numerator: u64, denominator: u64) u32 {
    if (denominator == 0) return 0;
    const scaled = std.math.mul(u64, numerator, 1000) catch
        return std.math.maxInt(u32);
    return std.math.cast(u32, scaled / denominator) orelse
        std.math.maxInt(u32);
}

fn removeContent(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidProviderRawBatchReceipt;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',')
        return error.InvalidProviderRawBatchReceipt;
    return std.fmt.allocPrint(allocator, "{{{s}", .{bytes[end + 2 ..]});
}

fn validateContent(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try contract.parseSha256(expected);
    const prefix = "{\"content_sha256\":\"";
    const end = prefix.len + 64;
    if (!std.mem.startsWith(u8, bytes, prefix) or end + 1 >= bytes.len or
        bytes[end] != '"' or bytes[end + 1] != ',' or
        !std.mem.eql(u8, bytes[prefix.len..end], expected))
    {
        return error.InvalidContentSha256;
    }
    const unsigned = try std.fmt.allocPrint(allocator, "{{{s}", .{bytes[end + 2 ..]});
    defer allocator.free(unsigned);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(unsigned, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &actual, expected)) return error.InvalidContentSha256;
}
