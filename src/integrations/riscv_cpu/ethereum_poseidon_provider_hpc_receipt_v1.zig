//! Canonical diagnostic receipt for one retained-call provider microbenchmark.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");

pub const schema = "stwo.ethereum.poseidon-provider-hpc-benchmark.v1";
pub const status_fresh = "diagnostic-fresh-verified";
pub const status_nonranking = "diagnostic-fresh-verified-nonranking";
pub const timing_scope = "retained-provider-slice-self-process";
pub const performance_time_budget_ns: u64 = 120 * std.time.ns_per_s;
pub const max_receipt_bytes: usize = 1024 * 1024;

pub const FileIdentity = struct {
    bytes: u64,
    path: []const u8,
    sha256: []const u8,

    fn validate(self: FileIdentity) !void {
        if (self.bytes == 0 or !std.fs.path.isAbsolute(self.path))
            return error.InvalidProviderHpcReceipt;
        _ = try contract.parseSha256(self.sha256);
    }
};

pub const Admission = struct {
    admitted_workers: u32,
    available_cpu_workers: u32,
    concurrent_worker_reservation_bytes: u64,
    controller_reserve_bytes: u64,
    host_byte_budget: u64,
    identity_sha256: []const u8,
    requested_workers: u32,
    worker_rss_budget_bytes: u64,
    work_items: u32,
};

pub const Correctness = struct {
    canonical_proof_bytes_equal: bool,
    fresh_verified: bool,
    native_claim_equal: bool,
    ordered_claim_equal: bool,
    stage_a_parallel_roots_equal: bool,
    stage_a_roots_equal_proof: bool,
    statement_identity_equal: bool,
};

pub const Profile = struct {
    build_mode: []const u8,
    composition_columns: u32,
    coefficient_retention: []const u8,
    host_power_classification: []const u8,
    main_columns: u32,
    preprocessed_columns: u32,
    provider_profile: []const u8,
    synthetic_core_stage_a: bool,
    tree2_columns: u32,
};

pub const ResourceUsage = struct {
    availability: []const u8,
    cycles: ?u64,
    energy_nj: ?u64,
    instructions: ?u64,
    lifetime_peak_physical_footprint_bytes: ?u64,
    source: []const u8,
};

pub const Timings = struct {
    cold_verify: evidence.Timing,
    parallel_stage_a: evidence.Timing,
    provider_prove_wall_ns: u64,
    serial_stage_a: evidence.Timing,
    total_wall_ns: u64,
};

pub const Candidate = struct {
    ideal_parallel_batch_wall_ns: u64,
    ideal_parallel_speedup_milli: u32,
    model: []const u8,
    parallel_stage_a_speedup_milli: u32,
};

pub const Workload = struct {
    call_artifact: FileIdentity,
    call_artifact_content_sha256: []const u8,
    full_call_count: u64,
    full_call_list_commitment_sha256: []const u8,
    log_size: u32,
    proved_ordinal: u32,
    raw_call_file: FileIdentity,
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
    benchmark_executable_sha256: []const u8,
    candidate: Candidate,
    correctness: Correctness,
    performance_claim_eligible: bool,
    production_eligible: bool,
    profile: Profile,
    proof: FileIdentity,
    proof_statement_identity_sha256: []const u8,
    provider_claim_identity_sha256: []const u8,
    recursive_admissible: bool,
    resource_usage: ResourceUsage,
    schema: []const u8,
    status: []const u8,
    timing_scope: []const u8,
    timings: Timings,
    workload: Workload,

    pub fn validate(self: Receipt) !void {
        const power_is_pinned = std.mem.eql(
            u8,
            self.profile.host_power_classification,
            "ac-high-power-pinned",
        );
        const power_is_diagnostic = std.mem.eql(
            u8,
            self.profile.host_power_classification,
            "battery-diagnostic",
        );
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.timing_scope, timing_scope) or
            self.production_eligible or self.recursive_admissible or
            self.timings.total_wall_ns == 0 or
            self.timings.provider_prove_wall_ns == 0 or
            self.timings.serial_stage_a.wall_ns == 0 or
            self.timings.parallel_stage_a.wall_ns == 0 or
            self.timings.cold_verify.wall_ns == 0 or
            self.workload.slice_call_count == 0 or
            self.workload.shard_count == 0 or
            self.workload.proved_ordinal >= self.workload.shard_count or
            self.workload.log_size < 4 or self.workload.log_size > 18 or
            self.workload.slice_offset > self.workload.full_call_count or
            (!power_is_pinned and !power_is_diagnostic) or
            self.profile.build_mode.len == 0 or
            self.profile.preprocessed_columns != 2 or
            self.profile.main_columns != 445 or
            self.profile.tree2_columns != 12 or
            self.profile.composition_columns != 8 or
            !std.mem.eql(u8, self.profile.coefficient_retention, "never") or
            !std.mem.eql(
                u8,
                self.profile.provider_profile,
                "ordered-provider-v2",
            ) or !self.profile.synthetic_core_stage_a)
        {
            return error.InvalidProviderHpcReceipt;
        }
        try self.proof.validate();
        try self.workload.call_artifact.validate();
        try self.workload.raw_call_file.validate();
        inline for (.{
            self.content_sha256,
            self.benchmark_executable_sha256,
            self.proof_statement_identity_sha256,
            self.provider_claim_identity_sha256,
            self.workload.call_artifact_content_sha256,
            self.workload.full_call_list_commitment_sha256,
            self.workload.session_sha256,
            self.workload.slice_call_list_commitment_sha256,
            self.workload.source_producer_sha256,
            self.admission.identity_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        const slice_capacity = std.math.mul(
            u64,
            @as(u64, 1) << @intCast(self.workload.log_size),
            self.workload.shard_count,
        ) catch return error.InvalidProviderHpcReceipt;
        const slice_end = std.math.add(
            u64,
            self.workload.slice_offset,
            self.workload.slice_call_count,
        ) catch return error.InvalidProviderHpcReceipt;
        if (self.workload.slice_call_count != slice_capacity or
            slice_end > self.workload.full_call_count or
            !std.mem.eql(u8, self.candidate.model, "single-shard-linear-upper-bound") or
            self.candidate.ideal_parallel_batch_wall_ns == 0 or
            self.candidate.ideal_parallel_speedup_milli !=
                self.admission.admitted_workers * 1000)
        {
            return error.InvalidProviderHpcReceipt;
        }
        const admission_identity = try contract.parseSha256(
            self.admission.identity_sha256,
        );
        const admission = try hpc.WorkerAdmissionV1.create(.{
            .requested_workers = self.admission.requested_workers,
            .available_cpu_workers = self.admission.available_cpu_workers,
            .work_items = self.admission.work_items,
            .host_byte_budget = self.admission.host_byte_budget,
            .controller_reserve_bytes = self.admission.controller_reserve_bytes,
            .worker_rss_budget_bytes = self.admission.worker_rss_budget_bytes,
        });
        if (admission.admitted_workers != self.admission.admitted_workers or
            admission.concurrent_worker_reservation_bytes !=
                self.admission.concurrent_worker_reservation_bytes or
            !std.mem.eql(u8, &admission.identity, &admission_identity))
        {
            return error.InvalidProviderHpcReceipt;
        }
        const correct = self.correctness.canonical_proof_bytes_equal and
            self.correctness.fresh_verified and
            self.correctness.native_claim_equal and
            self.correctness.ordered_claim_equal and
            self.correctness.stage_a_parallel_roots_equal and
            self.correctness.stage_a_roots_equal_proof and
            self.correctness.statement_identity_equal;
        const eligible = correct and
            self.timings.total_wall_ns <= performance_time_budget_ns and
            power_is_pinned and
            std.mem.eql(u8, self.resource_usage.availability, "available") and
            self.resource_usage.lifetime_peak_physical_footprint_bytes != null;
        if (self.performance_claim_eligible != eligible or
            !std.mem.eql(
                u8,
                self.status,
                if (eligible) status_fresh else status_nonranking,
            ) or self.admission.admitted_workers == 0 or
            self.admission.admitted_workers > hpc.max_workers or
            self.admission.work_items != self.workload.shard_count)
        {
            return error.InvalidProviderHpcReceipt;
        }
    }
};

pub fn encode(allocator: std.mem.Allocator, value: Receipt) ![]u8 {
    try value.validate();
    const placeholder = [_]u8{'0'} ** 64;
    var with_placeholder = value;
    with_placeholder.content_sha256 = &placeholder;
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        with_placeholder,
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

pub const testing = struct {
    pub fn canonicalRoundTrip(allocator: std.mem.Allocator) !void {
        const digest = [_]u8{'1'} ** 64;
        const placeholder = [_]u8{'0'} ** 64;
        const admission = try hpc.WorkerAdmissionV1.create(.{
            .requested_workers = 2,
            .available_cpu_workers = 8,
            .work_items = 2,
            .host_byte_budget = hpc.default_host_byte_budget,
            .controller_reserve_bytes = hpc.default_controller_reserve_bytes,
            .worker_rss_budget_bytes = hpc.default_worker_rss_budget_bytes,
        });
        const admission_digest = std.fmt.bytesToHex(admission.identity, .lower);
        const timing = evidence.Timing{
            .wall_ns = 10,
            .user_ns = 8,
            .system_ns = 2,
        };
        const value = Receipt{
            .content_sha256 = &placeholder,
            .admission = .{
                .admitted_workers = admission.admitted_workers,
                .available_cpu_workers = admission.available_cpu_workers,
                .concurrent_worker_reservation_bytes = admission.concurrent_worker_reservation_bytes,
                .controller_reserve_bytes = admission.controller_reserve_bytes,
                .host_byte_budget = admission.host_byte_budget,
                .identity_sha256 = &admission_digest,
                .requested_workers = admission.requested_workers,
                .worker_rss_budget_bytes = admission.worker_rss_budget_bytes,
                .work_items = admission.work_items,
            },
            .benchmark_executable_sha256 = &digest,
            .candidate = .{
                .ideal_parallel_batch_wall_ns = 20,
                .ideal_parallel_speedup_milli = 2000,
                .model = "single-shard-linear-upper-bound",
                .parallel_stage_a_speedup_milli = 1500,
            },
            .correctness = .{
                .canonical_proof_bytes_equal = true,
                .fresh_verified = true,
                .native_claim_equal = true,
                .ordered_claim_equal = true,
                .stage_a_parallel_roots_equal = true,
                .stage_a_roots_equal_proof = true,
                .statement_identity_equal = true,
            },
            .performance_claim_eligible = false,
            .production_eligible = false,
            .profile = .{
                .build_mode = "Debug",
                .composition_columns = 8,
                .coefficient_retention = "never",
                .host_power_classification = "battery-diagnostic",
                .main_columns = 445,
                .preprocessed_columns = 2,
                .provider_profile = "ordered-provider-v2",
                .synthetic_core_stage_a = true,
                .tree2_columns = 12,
            },
            .proof = .{
                .bytes = 8,
                .path = "/retained/provider-proof.bin",
                .sha256 = &digest,
            },
            .proof_statement_identity_sha256 = &digest,
            .provider_claim_identity_sha256 = &digest,
            .recursive_admissible = false,
            .resource_usage = .{
                .availability = "available",
                .cycles = 100,
                .energy_nj = 200,
                .instructions = 300,
                .lifetime_peak_physical_footprint_bytes = 400,
                .source = "synthetic-test",
            },
            .schema = schema,
            .status = status_nonranking,
            .timing_scope = timing_scope,
            .timings = .{
                .cold_verify = timing,
                .parallel_stage_a = timing,
                .provider_prove_wall_ns = 10,
                .serial_stage_a = timing,
                .total_wall_ns = 50,
            },
            .workload = .{
                .call_artifact = .{
                    .bytes = 8,
                    .path = "/retained/call-artifact.json",
                    .sha256 = &digest,
                },
                .call_artifact_content_sha256 = &digest,
                .full_call_count = 100,
                .full_call_list_commitment_sha256 = &digest,
                .log_size = 4,
                .proved_ordinal = 0,
                .raw_call_file = .{
                    .bytes = 192,
                    .path = "/retained/provider-calls.stwepc01",
                    .sha256 = &digest,
                },
                .session_sha256 = &digest,
                .shard_count = 2,
                .slice_call_count = 32,
                .slice_call_list_commitment_sha256 = &digest,
                .slice_offset = 0,
                .source_producer_sha256 = &digest,
            },
        };
        const bytes = try encode(allocator, value);
        defer allocator.free(bytes);
        var parsed = try parse(allocator, bytes);
        defer parsed.deinit();
        try std.testing.expect(!parsed.value.performance_claim_eligible);

        const digest_start = "{\"content_sha256\":\"".len;
        const saved = bytes[digest_start];
        bytes[digest_start] = if (saved == '0') '1' else '0';
        try std.testing.expectError(
            error.InvalidContentSha256,
            parse(allocator, bytes),
        );
    }
};

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Receipt) {
    if (bytes.len == 0 or bytes.len > max_receipt_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
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

fn removeContent(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidProviderHpcReceipt;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',')
        return error.InvalidProviderHpcReceipt;
    return std.fmt.allocPrint(allocator, "{{{s}", .{bytes[end + 2 ..]});
}

fn validateContent(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try contract.parseSha256(expected);
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidContentSha256;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',' or
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
    if (!std.mem.eql(u8, &actual, expected))
        return error.InvalidContentSha256;
}
