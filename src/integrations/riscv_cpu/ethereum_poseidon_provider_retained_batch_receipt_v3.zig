//! Canonical receipt for the additive retention-aware raw-provider scheduler.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const base_receipt = @import("ethereum_poseidon_provider_hpc_receipt_v1.zig");
const retention = @import("ethereum_poseidon_provider_retention_admission_v2.zig");

pub const schema =
    "stwo.ethereum.poseidon-provider-retained-raw-batch.v3";
pub const timing_scope = "retained-provider-concurrent-batch-self-process";
pub const status_fresh = "diagnostic-retained-batch-fresh-verified";
pub const status_nonranking =
    "diagnostic-retained-batch-fresh-verified-nonranking";
pub const max_batch_size: u32 = 4;
pub const performance_time_budget_ns: u64 = 60 * std.time.ns_per_s;
pub const max_receipt_bytes: usize = 2 * 1024 * 1024;

pub const AdmissionRequest = struct {
    available_cpu_workers: u32,
    controller_reserve_bytes: u64,
    host_byte_budget: u64,
    log_blowup_factor: u32,
    max_shard_log_size: u32,
    per_job_engine_workers: u32,
    per_job_non_column_reserve_bytes: u64,
    per_job_rss_cap_bytes: u64,
    requested_concurrent_jobs: u32,
    work_items: u32,

    fn value(self: AdmissionRequest) retention.RequestV2 {
        return .{
            .max_shard_log_size = self.max_shard_log_size,
            .log_blowup_factor = self.log_blowup_factor,
            .requested_concurrent_jobs = self.requested_concurrent_jobs,
            .available_cpu_workers = self.available_cpu_workers,
            .work_items = self.work_items,
            .per_job_engine_workers = self.per_job_engine_workers,
            .host_byte_budget = self.host_byte_budget,
            .controller_reserve_bytes = self.controller_reserve_bytes,
            .per_job_rss_cap_bytes = self.per_job_rss_cap_bytes,
            .per_job_non_column_reserve_bytes = self.per_job_non_column_reserve_bytes,
        };
    }
};

pub const Admission = struct {
    admitted_concurrent_jobs: u32,
    aggregate_rss_reservation_bytes: u64,
    always_admitted_peak_bytes: u64,
    fell_back_to_never: bool,
    format: u32,
    identity_sha256: []const u8,
    never_admitted_peak_bytes: u64,
    request: AdmissionRequest,
    selected_coefficient_retention: []const u8,
    worker_admission_identity_sha256: []const u8,

    pub fn validate(self: Admission) !retention.AdmissionV2 {
        const expected = try retention.AdmissionV2.create(self.request.value());
        const authority = expected.receiptAuthority();
        if (self.format != authority.format or
            self.admitted_concurrent_jobs != authority.admitted_concurrent_jobs or
            self.aggregate_rss_reservation_bytes !=
                authority.aggregate_rss_reservation_bytes or
            self.always_admitted_peak_bytes !=
                authority.always_admitted_peak_bytes or
            self.fell_back_to_never != authority.fell_back_to_never or
            self.never_admitted_peak_bytes !=
                authority.never_admitted_peak_bytes or
            !std.mem.eql(
                u8,
                self.selected_coefficient_retention,
                authority.selected_coefficient_retention,
            ) or !std.meta.eql(
            try contract.parseSha256(self.worker_admission_identity_sha256),
            authority.worker_admission_identity,
        ) or !std.meta.eql(
            try contract.parseSha256(self.identity_sha256),
            authority.identity,
        )) return error.InvalidProviderRetainedBatchReceipt;
        return expected;
    }
};

pub const Correctness = struct {
    canonical_proof_bytes_equal: []const bool,
    fresh_verified: []const bool,
    native_claims_equal: []const bool,
    ordered_claims_equal: []const bool,
    stage_a_roots_equal: []const bool,
    statement_identities_equal: []const bool,
};

pub const Timings = struct {
    cold_verify_wall_ns: u64,
    proof_batch_wall_ns: u64,
    stage_a: evidence.Timing,
    total_wall_ns: u64,
};

pub const Workload = struct {
    batch_size: u32,
    call_artifact: base_receipt.FileIdentity,
    call_artifact_content_sha256: []const u8,
    full_call_count: u64,
    full_call_list_commitment_sha256: []const u8,
    log_size: u32,
    ordinals: []const u32,
    raw_call_file: base_receipt.FileIdentity,
    session_sha256: []const u8,
    shard_count: u32,
    slice_call_count: u64,
    slice_call_list_commitment_sha256: []const u8,
    slice_offset: u64,
    source_producer_sha256: []const u8,
};

pub const Receipt = struct {
    content_sha256: []const u8,
    admission: Admission,
    benchmark_executable: base_receipt.FileIdentity,
    correctness: Correctness,
    performance_claim_eligible: bool,
    production_eligible: bool,
    profile: base_receipt.Profile,
    proofs: []const base_receipt.FileIdentity,
    recursive_admissible: bool,
    resource_usage: base_receipt.ResourceUsage,
    schema: []const u8,
    status: []const u8,
    timing_scope: []const u8,
    timings: Timings,
    workload: Workload,

    pub fn validate(self: Receipt) !void {
        const admission = try self.admission.validate();
        const count: usize = @intCast(self.workload.batch_size);
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.timing_scope, timing_scope) or
            self.production_eligible or self.recursive_admissible or
            self.workload.batch_size == 0 or
            self.workload.batch_size > max_batch_size or
            self.workload.shard_count != self.workload.batch_size or
            self.workload.log_size < 4 or self.workload.log_size > 20 or
            self.workload.slice_call_count == 0 or
            self.timings.proof_batch_wall_ns == 0 or
            self.timings.cold_verify_wall_ns == 0 or
            self.timings.stage_a.wall_ns == 0 or
            self.timings.total_wall_ns == 0 or
            self.profile.preprocessed_columns != 2 or
            self.profile.main_columns != 445 or
            self.profile.tree2_columns != 12 or
            self.profile.composition_columns != 8 or
            !std.mem.eql(
                u8,
                self.profile.coefficient_retention,
                retention.policyName(admission.selected_policy),
            ) or !std.mem.eql(
            u8,
            self.profile.provider_profile,
            "ordered-provider-v2",
        ) or !self.profile.synthetic_core_stage_a or
            self.proofs.len != count or self.workload.ordinals.len != count or
            self.admission.request.work_items != self.workload.batch_size or
            self.admission.request.requested_concurrent_jobs !=
                self.workload.batch_size or
            self.admission.request.max_shard_log_size != self.workload.log_size)
        {
            return error.InvalidProviderRetainedBatchReceipt;
        }
        try requireCorrectnessLengths(self.correctness, count);
        try validateFile(self.benchmark_executable);
        try validateFile(self.workload.call_artifact);
        try validateFile(self.workload.raw_call_file);
        for (self.proofs) |proof| try validateFile(proof);
        inline for (.{
            self.content_sha256,
            self.workload.call_artifact_content_sha256,
            self.workload.full_call_list_commitment_sha256,
            self.workload.session_sha256,
            self.workload.slice_call_list_commitment_sha256,
            self.workload.source_producer_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        for (self.workload.ordinals, 0..) |ordinal, index|
            if (ordinal != index)
                return error.InvalidProviderRetainedBatchReceipt;
        const expected_count = std.math.mul(
            u64,
            @as(u64, 1) << @intCast(self.workload.log_size),
            self.workload.shard_count,
        ) catch return error.InvalidProviderRetainedBatchReceipt;
        const slice_end = std.math.add(
            u64,
            self.workload.slice_offset,
            self.workload.slice_call_count,
        ) catch return error.InvalidProviderRetainedBatchReceipt;
        if (expected_count != self.workload.slice_call_count or
            slice_end > self.workload.full_call_count)
        {
            return error.InvalidProviderRetainedBatchReceipt;
        }
        const correct = try allCorrect(self.correctness);
        const eligible = correct and
            self.timings.total_wall_ns <= performance_time_budget_ns and
            std.mem.eql(
                u8,
                self.profile.host_power_classification,
                "ac-high-power-pinned",
            ) and std.mem.eql(
            u8,
            self.resource_usage.availability,
            "available",
        ) and self.resource_usage.lifetime_peak_physical_footprint_bytes != null;
        if (self.performance_claim_eligible != eligible or
            !std.mem.eql(
                u8,
                self.status,
                if (eligible) status_fresh else status_nonranking,
            ))
        {
            return error.InvalidProviderRetainedBatchReceipt;
        }
    }
};

pub fn encode(allocator: std.mem.Allocator, value: Receipt) ![]u8 {
    try value.validate();
    const placeholder = [_]u8{'0'} ** 64;
    var temporary = value;
    temporary.content_sha256 = &placeholder;
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        temporary,
        .{},
    );
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
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
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
    const count = value.canonical_proof_bytes_equal.len;
    try requireCorrectnessLengths(value, count);
    inline for (.{
        value.canonical_proof_bytes_equal,
        value.fresh_verified,
        value.native_claims_equal,
        value.ordered_claims_equal,
        value.stage_a_roots_equal,
        value.statement_identities_equal,
    }) |items| for (items) |item| if (!item) return false;
    return true;
}

fn requireCorrectnessLengths(value: Correctness, expected: usize) !void {
    inline for (.{
        value.canonical_proof_bytes_equal,
        value.fresh_verified,
        value.native_claims_equal,
        value.ordered_claims_equal,
        value.stage_a_roots_equal,
        value.statement_identities_equal,
    }) |items| if (items.len != expected)
        return error.InvalidProviderRetainedBatchReceipt;
}

fn validateFile(value: base_receipt.FileIdentity) !void {
    if (value.bytes == 0 or !std.fs.path.isAbsolute(value.path))
        return error.InvalidProviderRetainedBatchReceipt;
    _ = try contract.parseSha256(value.sha256);
}

fn removeContent(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidProviderRetainedBatchReceipt;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',')
        return error.InvalidProviderRetainedBatchReceipt;
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
    const unsigned = try std.fmt.allocPrint(
        allocator,
        "{{{s}",
        .{bytes[end + 2 ..]},
    );
    defer allocator.free(unsigned);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(unsigned, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &actual, expected)) return error.InvalidContentSha256;
}

pub const testing = struct {
    pub fn canonicalRoundTrip(allocator: std.mem.Allocator) !void {
        const request = AdmissionRequest{
            .available_cpu_workers = 18,
            .controller_reserve_bytes = 8 * 1024 * 1024 * 1024,
            .host_byte_budget = 48 * 1024 * 1024 * 1024,
            .log_blowup_factor = 1,
            .max_shard_log_size = 16,
            .per_job_engine_workers = 4,
            .per_job_non_column_reserve_bytes = retention.default_per_job_non_column_reserve_bytes,
            .per_job_rss_cap_bytes = 10 * 1024 * 1024 * 1024,
            .requested_concurrent_jobs = 2,
            .work_items = 2,
        };
        const selected = try retention.AdmissionV2.create(request.value());
        const authority = selected.receiptAuthority();
        const identity = hex(authority.identity);
        const worker = hex(authority.worker_admission_identity);
        const digest = [_]u8{'1'} ** 64;
        const placeholder = [_]u8{'0'} ** 64;
        const correctness = [_]bool{true} ** 2;
        const ordinals = [_]u32{ 0, 1 };
        const proofs = [_]base_receipt.FileIdentity{
            .{ .bytes = 10, .path = "/fresh/0.stw", .sha256 = &digest },
            .{ .bytes = 11, .path = "/fresh/1.stw", .sha256 = &digest },
        };
        const timing = evidence.Timing{
            .wall_ns = 7,
            .user_ns = 5,
            .system_ns = 1,
        };
        const value = Receipt{
            .content_sha256 = &placeholder,
            .admission = .{
                .admitted_concurrent_jobs = authority.admitted_concurrent_jobs,
                .aggregate_rss_reservation_bytes = authority.aggregate_rss_reservation_bytes,
                .always_admitted_peak_bytes = authority.always_admitted_peak_bytes,
                .fell_back_to_never = authority.fell_back_to_never,
                .format = authority.format,
                .identity_sha256 = &identity,
                .never_admitted_peak_bytes = authority.never_admitted_peak_bytes,
                .request = request,
                .selected_coefficient_retention = authority.selected_coefficient_retention,
                .worker_admission_identity_sha256 = &worker,
            },
            .benchmark_executable = .{
                .bytes = 12,
                .path = "/retained/benchmark",
                .sha256 = &digest,
            },
            .correctness = .{
                .canonical_proof_bytes_equal = &correctness,
                .fresh_verified = &correctness,
                .native_claims_equal = &correctness,
                .ordered_claims_equal = &correctness,
                .stage_a_roots_equal = &correctness,
                .statement_identities_equal = &correctness,
            },
            .performance_claim_eligible = false,
            .production_eligible = false,
            .profile = .{
                .build_mode = "Debug",
                .composition_columns = 8,
                .coefficient_retention = authority.selected_coefficient_retention,
                .host_power_classification = "battery-diagnostic",
                .main_columns = 445,
                .preprocessed_columns = 2,
                .provider_profile = "ordered-provider-v2",
                .synthetic_core_stage_a = true,
                .tree2_columns = 12,
            },
            .proofs = &proofs,
            .recursive_admissible = false,
            .resource_usage = .{
                .availability = "unavailable",
                .cycles = null,
                .energy_nj = null,
                .instructions = null,
                .lifetime_peak_physical_footprint_bytes = null,
                .source = "synthetic-test",
            },
            .schema = schema,
            .status = status_nonranking,
            .timing_scope = timing_scope,
            .timings = .{
                .cold_verify_wall_ns = 8,
                .proof_batch_wall_ns = 9,
                .stage_a = timing,
                .total_wall_ns = 24,
            },
            .workload = .{
                .batch_size = 2,
                .call_artifact = .{
                    .bytes = 13,
                    .path = "/retained/calls.json",
                    .sha256 = &digest,
                },
                .call_artifact_content_sha256 = &digest,
                .full_call_count = 131_072,
                .full_call_list_commitment_sha256 = &digest,
                .log_size = 16,
                .ordinals = &ordinals,
                .raw_call_file = .{
                    .bytes = 14,
                    .path = "/retained/calls.stw",
                    .sha256 = &digest,
                },
                .session_sha256 = &digest,
                .shard_count = 2,
                .slice_call_count = 131_072,
                .slice_call_list_commitment_sha256 = &digest,
                .slice_offset = 0,
                .source_producer_sha256 = &digest,
            },
        };
        const bytes = try encode(allocator, value);
        defer allocator.free(bytes);
        var parsed = try parse(allocator, bytes);
        defer parsed.deinit();
        try std.testing.expectEqualStrings(
            "always",
            parsed.value.admission.selected_coefficient_retention,
        );

        var mutated = value;
        mutated.admission.fell_back_to_never = true;
        try std.testing.expectError(
            error.InvalidProviderRetainedBatchReceipt,
            encode(allocator, mutated),
        );
    }
};

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}
