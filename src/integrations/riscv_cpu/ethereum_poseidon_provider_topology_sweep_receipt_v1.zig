//! Canonical diagnostic receipt for concurrent-only provider topology sweeps.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const batch_v2 = @import("ethereum_poseidon_provider_raw_batch_receipt_v2.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");
const receipt_v1 = @import("ethereum_poseidon_provider_hpc_receipt_v1.zig");

pub const schema = "stwo.ethereum.poseidon-provider-topology-sweep.v1";
pub const timing_scope = "retained-provider-topology-sweep-self-process";
pub const rss_scope = "self-process-lifetime-peak-before-after-arm";
pub const status_fresh = "diagnostic-topology-sweep-fresh-verified";
pub const status_nonranking =
    "diagnostic-topology-sweep-fresh-verified-nonranking";
pub const max_receipt_bytes: usize = 4 * 1024 * 1024;
pub const arm_count: usize = 3;
pub const proof_count: usize = 4;
pub const total_time_budget_ns: u64 = 120 * std.time.ns_per_s;

pub const Topology = struct {
    concurrent_jobs: u32,
    per_job_engine_workers: u32,
    hard_cap_ns: u64,
};

pub const canonical_jobs = [_]u32{ 2, 3, 4 };
pub const canonical_engine_workers = [_]u32{ 8, 5, 4 };

pub const ArmResourceUsage = struct {
    availability: []const u8,
    cycles: ?u64,
    energy_nj: ?u64,
    instructions: ?u64,
    lifetime_peak_after_bytes: ?u64,
    lifetime_peak_before_bytes: ?u64,
    rss_scope: []const u8,
    source: []const u8,
};

pub const Proof = struct {
    canonical_proof_bytes_equal: bool,
    claim_identity_sha256: []const u8,
    cold_verify: evidence.Timing,
    exact_reference_proof_bytes_equal: bool,
    fresh_verified: bool,
    native_claim_equal_reference: bool,
    ordered_claim_equal_reference: bool,
    ordinal: u32,
    proof: receipt_v1.FileIdentity,
    prove_wall_ns: u64,
    roots_equal_proof: bool,
    statement_identity_equal_reference: bool,
    statement_identity_sha256: []const u8,
};

pub const Arm = struct {
    admission: batch_v2.RawAdmission,
    arm_index: u32,
    cold_verify_wall_ns: u64,
    configuration_index: u32,
    proof_batch_wall_ns: u64,
    proofs: []const Proof,
    resource_usage: ArmResourceUsage,
    stage_a: evidence.Timing,
    stage_a_roots_equal_reference: bool,
    total: evidence.Timing,
};

pub const Receipt = struct {
    content_sha256: []const u8,
    arms: []const Arm,
    benchmark_executable: receipt_v1.FileIdentity,
    configurations: []const Topology,
    performance_claim_eligible: bool,
    production_eligible: bool,
    profile: receipt_v1.Profile,
    recursive_admissible: bool,
    schema: []const u8,
    status: []const u8,
    timing_scope: []const u8,
    total_hard_cap_ns: u64,
    total_wall_ns: u64,
    workload: batch_v2.Workload,

    pub fn validate(self: Receipt) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.timing_scope, timing_scope) or
            self.production_eligible or self.recursive_admissible or
            self.configurations.len != arm_count or self.arms.len != arm_count or
            self.total_hard_cap_ns == 0 or
            self.total_hard_cap_ns > total_time_budget_ns or
            self.total_wall_ns == 0 or
            self.workload.batch_size != proof_count or
            self.workload.shard_count != proof_count or
            self.workload.ordinals.len != proof_count or
            self.profile.preprocessed_columns != 2 or
            self.profile.main_columns != 445 or
            self.profile.tree2_columns != 12 or
            self.profile.composition_columns != 8 or
            !std.mem.eql(u8, self.profile.coefficient_retention, "never") or
            !std.mem.eql(u8, self.profile.provider_profile, "ordered-provider-v2") or
            !self.profile.synthetic_core_stage_a)
        {
            return error.InvalidProviderTopologySweepReceipt;
        }
        try validateFile(self.benchmark_executable);
        try validateWorkload(self.workload);
        var cap_sum: u64 = 0;
        for (self.configurations, 0..) |configuration, index| {
            if (configuration.concurrent_jobs != canonical_jobs[index] or
                configuration.per_job_engine_workers !=
                    canonical_engine_workers[index] or
                configuration.hard_cap_ns == 0)
            {
                return error.InvalidProviderTopologySweepReceipt;
            }
            cap_sum = std.math.add(
                u64,
                cap_sum,
                configuration.hard_cap_ns,
            ) catch return error.InvalidProviderTopologySweepReceipt;
        }
        if (cap_sum > self.total_hard_cap_ns)
            return error.InvalidProviderTopologySweepReceipt;
        for (self.arms, 0..) |arm, index| {
            const configuration = self.configurations[index];
            const expected_index: u32 = @intCast(index);
            if (arm.arm_index != expected_index or
                arm.configuration_index != expected_index or
                arm.proofs.len != proof_count or
                arm.stage_a.wall_ns == 0 or arm.proof_batch_wall_ns == 0 or
                arm.cold_verify_wall_ns == 0 or arm.total.wall_ns == 0 or
                arm.total.wall_ns > configuration.hard_cap_ns or
                !arm.stage_a_roots_equal_reference)
            {
                return error.InvalidProviderTopologySweepReceipt;
            }
            try validateAdmission(arm.admission, configuration);
            try validateResource(arm.resource_usage);
            for (arm.proofs, 0..) |proof, ordinal| {
                const expected_ordinal: u32 = @intCast(ordinal);
                if (proof.ordinal != expected_ordinal or
                    proof.prove_wall_ns == 0 or
                    proof.cold_verify.wall_ns == 0 or
                    !proof.canonical_proof_bytes_equal or
                    !proof.exact_reference_proof_bytes_equal or
                    !proof.fresh_verified or !proof.roots_equal_proof or
                    !proof.statement_identity_equal_reference or
                    !proof.native_claim_equal_reference or
                    !proof.ordered_claim_equal_reference)
                {
                    return error.InvalidProviderTopologySweepReceipt;
                }
                try validateFile(proof.proof);
                _ = try contract.parseSha256(proof.statement_identity_sha256);
                _ = try contract.parseSha256(proof.claim_identity_sha256);
                if (index != 0) {
                    const reference = self.arms[0].proofs[ordinal];
                    if (proof.proof.bytes != reference.proof.bytes or
                        !std.mem.eql(u8, proof.proof.sha256, reference.proof.sha256) or
                        !std.mem.eql(
                            u8,
                            proof.statement_identity_sha256,
                            reference.statement_identity_sha256,
                        ) or !std.mem.eql(
                        u8,
                        proof.claim_identity_sha256,
                        reference.claim_identity_sha256,
                    )) return error.InvalidProviderTopologySweepReceipt;
                }
            }
        }
        const eligible = allCorrect(self) and
            self.total_wall_ns <= self.total_hard_cap_ns and
            std.mem.eql(
                u8,
                self.profile.host_power_classification,
                "ac-high-power-pinned",
            ) and resourcesAvailable(self);
        if (self.performance_claim_eligible != eligible or
            !std.mem.eql(
                u8,
                self.status,
                if (eligible) status_fresh else status_nonranking,
            )) return error.InvalidProviderTopologySweepReceipt;
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

fn allCorrect(value: Receipt) bool {
    for (value.arms) |arm| {
        if (!arm.stage_a_roots_equal_reference) return false;
        for (arm.proofs) |proof| {
            if (!proof.canonical_proof_bytes_equal or
                !proof.exact_reference_proof_bytes_equal or
                !proof.fresh_verified or !proof.roots_equal_proof or
                !proof.statement_identity_equal_reference or
                !proof.native_claim_equal_reference or
                !proof.ordered_claim_equal_reference) return false;
        }
    }
    return true;
}

fn resourcesAvailable(value: Receipt) bool {
    for (value.arms) |arm| {
        if (!std.mem.eql(u8, arm.resource_usage.availability, "available") or
            arm.resource_usage.cycles == null or
            arm.resource_usage.energy_nj == null or
            arm.resource_usage.instructions == null or
            arm.resource_usage.lifetime_peak_before_bytes == null or
            arm.resource_usage.lifetime_peak_after_bytes == null)
        {
            return false;
        }
    }
    return true;
}

fn validateWorkload(value: batch_v2.Workload) !void {
    try validateFile(value.call_artifact);
    try validateFile(value.raw_call_file);
    inline for (.{
        value.call_artifact_content_sha256,
        value.full_call_list_commitment_sha256,
        value.session_sha256,
        value.slice_call_list_commitment_sha256,
        value.source_producer_sha256,
    }) |digest| _ = try contract.parseSha256(digest);
    if (value.log_size < 4 or value.log_size > 18 or
        value.slice_call_count == 0) return error.InvalidProviderTopologySweepReceipt;
    const expected = std.math.mul(
        u64,
        @as(u64, 1) << @intCast(value.log_size),
        value.shard_count,
    ) catch return error.InvalidProviderTopologySweepReceipt;
    const end = std.math.add(
        u64,
        value.slice_offset,
        value.slice_call_count,
    ) catch return error.InvalidProviderTopologySweepReceipt;
    if (expected != value.slice_call_count or end > value.full_call_count)
        return error.InvalidProviderTopologySweepReceipt;
    for (value.ordinals, 0..) |ordinal, index| {
        const expected_ordinal: u32 = @intCast(index);
        if (ordinal != expected_ordinal)
            return error.InvalidProviderTopologySweepReceipt;
    }
}

fn validateAdmission(
    value: batch_v2.RawAdmission,
    topology: Topology,
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
    if (value.requested_concurrent_jobs != topology.concurrent_jobs or
        value.per_job_engine_workers != topology.per_job_engine_workers or
        value.work_items != proof_count or
        admitted.admitted_concurrent_jobs != topology.concurrent_jobs or
        admitted.admitted_concurrent_jobs != value.admitted_concurrent_jobs or
        admitted.aggregate_engine_workers != value.aggregate_engine_workers or
        admitted.aggregate_rss_reservation_bytes !=
            value.aggregate_rss_reservation_bytes or
        admitted.aggregate_engine_stack_reservation_bytes !=
            value.aggregate_engine_stack_reservation_bytes or
        !std.mem.eql(u8, &admitted.identity, &identity))
    {
        return error.InvalidProviderTopologySweepReceipt;
    }
}

fn validateResource(value: ArmResourceUsage) !void {
    if (!std.mem.eql(u8, value.rss_scope, rss_scope) or value.source.len == 0)
        return error.InvalidProviderTopologySweepReceipt;
    const available = std.mem.eql(u8, value.availability, "available");
    const unavailable = std.mem.eql(u8, value.availability, "unavailable");
    if ((!available and !unavailable) or (available and
        (value.cycles == null or value.energy_nj == null or
            value.instructions == null or
            value.lifetime_peak_before_bytes == null or
            value.lifetime_peak_after_bytes == null or
            value.lifetime_peak_after_bytes.? <
                value.lifetime_peak_before_bytes.?)))
    {
        return error.InvalidProviderTopologySweepReceipt;
    }
}

fn validateFile(value: receipt_v1.FileIdentity) !void {
    if (value.bytes == 0 or !std.fs.path.isAbsolute(value.path))
        return error.InvalidProviderTopologySweepReceipt;
    _ = try contract.parseSha256(value.sha256);
}

fn removeContent(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidProviderTopologySweepReceipt;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',')
        return error.InvalidProviderTopologySweepReceipt;
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
        const digest = [_]u8{'0'} ** 64;
        const ordinals = [_]u32{ 0, 1, 2, 3 };
        const configurations = [_]Topology{
            .{ .concurrent_jobs = 2, .per_job_engine_workers = 8, .hard_cap_ns = 1_000 },
            .{ .concurrent_jobs = 3, .per_job_engine_workers = 5, .hard_cap_ns = 1_000 },
            .{ .concurrent_jobs = 4, .per_job_engine_workers = 4, .hard_cap_ns = 1_000 },
        };
        var admissions: [arm_count]batch_v2.RawAdmission = undefined;
        var admission_digests: [arm_count][64]u8 = undefined;
        var proofs: [arm_count][proof_count]Proof = undefined;
        var arms: [arm_count]Arm = undefined;
        for (0..arm_count) |arm_index| {
            const admitted = try hpc.RawWorkerAdmissionV1.create(.{
                .requested_concurrent_jobs = configurations[arm_index].concurrent_jobs,
                .available_cpu_workers = 18,
                .work_items = proof_count,
                .per_job_engine_workers = configurations[arm_index].per_job_engine_workers,
                .host_byte_budget = 48 * 1024 * 1024 * 1024,
                .controller_reserve_bytes = 8 * 1024 * 1024 * 1024,
                .per_job_rss_budget_bytes = 8 * 1024 * 1024 * 1024,
            });
            admission_digests[arm_index] = std.fmt.bytesToHex(
                admitted.identity,
                .lower,
            );
            admissions[arm_index] = .{
                .admitted_concurrent_jobs = admitted.admitted_concurrent_jobs,
                .aggregate_engine_stack_reservation_bytes = admitted.aggregate_engine_stack_reservation_bytes,
                .aggregate_engine_workers = admitted.aggregate_engine_workers,
                .aggregate_rss_reservation_bytes = admitted.aggregate_rss_reservation_bytes,
                .available_cpu_workers = admitted.available_cpu_workers,
                .controller_reserve_bytes = admitted.controller_reserve_bytes,
                .host_byte_budget = admitted.host_byte_budget,
                .identity_sha256 = &admission_digests[arm_index],
                .per_job_engine_workers = admitted.per_job_engine_workers,
                .per_job_rss_budget_bytes = admitted.per_job_rss_budget_bytes,
                .requested_concurrent_jobs = admitted.requested_concurrent_jobs,
                .work_items = admitted.work_items,
            };
            for (0..proof_count) |ordinal| proofs[arm_index][ordinal] = .{
                .canonical_proof_bytes_equal = true,
                .claim_identity_sha256 = &digest,
                .cold_verify = .{ .wall_ns = 1, .user_ns = 1, .system_ns = 1 },
                .exact_reference_proof_bytes_equal = true,
                .fresh_verified = true,
                .native_claim_equal_reference = true,
                .ordered_claim_equal_reference = true,
                .ordinal = @intCast(ordinal),
                .proof = .{
                    .bytes = 1,
                    .path = "/retained/provider.stw",
                    .sha256 = &digest,
                },
                .prove_wall_ns = 1,
                .roots_equal_proof = true,
                .statement_identity_equal_reference = true,
                .statement_identity_sha256 = &digest,
            };
            arms[arm_index] = .{
                .admission = admissions[arm_index],
                .arm_index = @intCast(arm_index),
                .cold_verify_wall_ns = 1,
                .configuration_index = @intCast(arm_index),
                .proof_batch_wall_ns = 1,
                .proofs = &proofs[arm_index],
                .resource_usage = .{
                    .availability = "available",
                    .cycles = 1,
                    .energy_nj = 1,
                    .instructions = 1,
                    .lifetime_peak_after_bytes = 2,
                    .lifetime_peak_before_bytes = 1,
                    .rss_scope = rss_scope,
                    .source = "synthetic",
                },
                .stage_a = .{ .wall_ns = 1, .user_ns = 1, .system_ns = 1 },
                .stage_a_roots_equal_reference = true,
                .total = .{ .wall_ns = 10, .user_ns = 2, .system_ns = 1 },
            };
        }
        const bytes = try encode(allocator, .{
            .content_sha256 = &digest,
            .arms = &arms,
            .benchmark_executable = .{
                .bytes = 1,
                .path = "/retained/benchmark",
                .sha256 = &digest,
            },
            .configurations = &configurations,
            .performance_claim_eligible = true,
            .production_eligible = false,
            .profile = .{
                .build_mode = "ReleaseFast",
                .composition_columns = 8,
                .coefficient_retention = "never",
                .host_power_classification = "ac-high-power-pinned",
                .main_columns = 445,
                .preprocessed_columns = 2,
                .provider_profile = "ordered-provider-v2",
                .synthetic_core_stage_a = true,
                .tree2_columns = 12,
            },
            .recursive_admissible = false,
            .schema = schema,
            .status = status_fresh,
            .timing_scope = timing_scope,
            .total_hard_cap_ns = 3_000,
            .total_wall_ns = 30,
            .workload = .{
                .batch_size = proof_count,
                .call_artifact = .{
                    .bytes = 1,
                    .path = "/retained/calls.json",
                    .sha256 = &digest,
                },
                .call_artifact_content_sha256 = &digest,
                .full_call_count = 64,
                .full_call_list_commitment_sha256 = &digest,
                .log_size = 4,
                .ordinals = &ordinals,
                .raw_call_file = .{
                    .bytes = 1,
                    .path = "/retained/calls.bin",
                    .sha256 = &digest,
                },
                .session_sha256 = &digest,
                .shard_count = proof_count,
                .slice_call_count = 64,
                .slice_call_list_commitment_sha256 = &digest,
                .slice_offset = 0,
                .source_producer_sha256 = &digest,
            },
        });
        defer allocator.free(bytes);
        var parsed = try parse(allocator, bytes);
        defer parsed.deinit();
        try std.testing.expectEqual(@as(usize, arm_count), parsed.value.arms.len);
    }
};
