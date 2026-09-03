//! Canonical telemetry for four-way provider coefficient-retention sweeps.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const batch_v2 = @import("ethereum_poseidon_provider_raw_batch_receipt_v2.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");
const receipt_v1 = @import("ethereum_poseidon_provider_hpc_receipt_v1.zig");
const topology_v1 = @import("ethereum_poseidon_provider_topology_sweep_receipt_v1.zig");

pub const schema = "stwo.ethereum.poseidon-provider-retention-sweep.v1";
pub const timing_scope = "retained-provider-retention-sweep-self-process";
pub const status_fresh = "diagnostic-retention-sweep-fresh-verified";
pub const status_nonranking =
    "diagnostic-retention-sweep-fresh-verified-nonranking";
pub const arm_count: usize = 2;
pub const proof_count: usize = 4;
pub const max_receipt_bytes: usize = 4 * 1024 * 1024;
pub const total_time_budget_ns: u64 = 120 * std.time.ns_per_s;

pub const Retention = enum {
    always,
    never,
};

pub const Proof = struct {
    canonical_proof_bytes_equal: bool,
    cold_verify: evidence.Timing,
    committed_column_count: u32,
    exact_cross_retention_proof_bytes_equal: bool,
    fresh_verified: bool,
    ordinal: u32,
    proof: receipt_v1.FileIdentity,
    prove_wall_ns: u64,
    retained_coefficient_columns: u32,
    roots_equal_cross_retention: bool,
    roots_equal_proof: bool,
    statement_identity_sha256: []const u8,
    statement_equal_cross_retention: bool,
};

pub const Arm = struct {
    arm_index: u32,
    cold_verify_wall_ns: u64,
    hard_cap_ns: u64,
    policy: []const u8,
    proof_batch_wall_ns: u64,
    proofs: []const Proof,
    resource_usage: topology_v1.ArmResourceUsage,
    total: evidence.Timing,
};

pub const Receipt = struct {
    content_sha256: []const u8,
    admission: batch_v2.RawAdmission,
    arms: []const Arm,
    benchmark_executable: receipt_v1.FileIdentity,
    performance_claim_eligible: bool,
    production_eligible: bool,
    profile: receipt_v1.Profile,
    recursive_admissible: bool,
    retention_speedup_milli: u32,
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
            self.arms.len != arm_count or self.total_hard_cap_ns == 0 or
            self.total_hard_cap_ns > total_time_budget_ns or
            self.total_wall_ns == 0 or self.workload.batch_size != proof_count or
            self.workload.shard_count != proof_count or
            self.workload.ordinals.len != proof_count or
            self.profile.preprocessed_columns != 2 or
            self.profile.main_columns != 445 or
            self.profile.tree2_columns != 8 or
            self.profile.composition_columns != 8 or
            !std.mem.eql(u8, self.profile.provider_profile, "standalone-provider-v1"))
        {
            return error.InvalidProviderRetentionSweepReceipt;
        }
        try validateFile(self.benchmark_executable);
        try validateAdmission(self.admission);
        try validateWorkload(self.workload);
        var cap_sum: u64 = 0;
        for (self.arms, 0..) |arm, index| {
            const expected_policy = if (index == 0) "always" else "never";
            const expected_index: u32 = @intCast(index);
            if (arm.arm_index != expected_index or
                !std.mem.eql(u8, arm.policy, expected_policy) or
                arm.hard_cap_ns == 0 or arm.proof_batch_wall_ns == 0 or
                arm.cold_verify_wall_ns == 0 or arm.total.wall_ns == 0 or
                arm.total.wall_ns > arm.hard_cap_ns or
                arm.proofs.len != proof_count)
            {
                return error.InvalidProviderRetentionSweepReceipt;
            }
            cap_sum = std.math.add(u64, cap_sum, arm.hard_cap_ns) catch
                return error.InvalidProviderRetentionSweepReceipt;
            try validateResource(arm.resource_usage);
            for (arm.proofs, 0..) |proof, ordinal| {
                const expected_ordinal: u32 = @intCast(ordinal);
                const expected_retained: u32 = if (index == 0)
                    proof.committed_column_count
                else
                    0;
                if (proof.ordinal != expected_ordinal or
                    proof.prove_wall_ns == 0 or proof.cold_verify.wall_ns == 0 or
                    proof.committed_column_count != 455 or
                    proof.retained_coefficient_columns != expected_retained or
                    !proof.canonical_proof_bytes_equal or
                    !proof.exact_cross_retention_proof_bytes_equal or
                    !proof.fresh_verified or !proof.roots_equal_cross_retention or
                    !proof.roots_equal_proof or
                    !proof.statement_equal_cross_retention)
                {
                    return error.InvalidProviderRetentionSweepReceipt;
                }
                try validateFile(proof.proof);
                _ = try contract.parseSha256(proof.statement_identity_sha256);
                if (index != 0) {
                    const reference = self.arms[0].proofs[ordinal];
                    if (proof.proof.bytes != reference.proof.bytes or
                        !std.mem.eql(u8, proof.proof.sha256, reference.proof.sha256) or
                        !std.mem.eql(
                            u8,
                            proof.statement_identity_sha256,
                            reference.statement_identity_sha256,
                        )) return error.InvalidProviderRetentionSweepReceipt;
                }
            }
        }
        if (cap_sum > self.total_hard_cap_ns or
            self.retention_speedup_milli != ratioMilli(
                self.arms[1].proof_batch_wall_ns,
                self.arms[0].proof_batch_wall_ns,
            )) return error.InvalidProviderRetentionSweepReceipt;
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
            )) return error.InvalidProviderRetentionSweepReceipt;
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
    for (value.arms) |arm| for (arm.proofs) |proof| {
        if (!proof.canonical_proof_bytes_equal or
            !proof.exact_cross_retention_proof_bytes_equal or
            !proof.fresh_verified or !proof.roots_equal_cross_retention or
            !proof.roots_equal_proof or
            !proof.statement_equal_cross_retention) return false;
    };
    return true;
}

fn resourcesAvailable(value: Receipt) bool {
    for (value.arms) |arm| if (!std.mem.eql(
        u8,
        arm.resource_usage.availability,
        "available",
    )) return false;
    return true;
}

fn validateAdmission(value: batch_v2.RawAdmission) !void {
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
    if (admitted.admitted_concurrent_jobs != proof_count or
        admitted.per_job_engine_workers != 4 or admitted.work_items != proof_count or
        admitted.admitted_concurrent_jobs != value.admitted_concurrent_jobs or
        admitted.aggregate_engine_workers != value.aggregate_engine_workers or
        admitted.aggregate_rss_reservation_bytes !=
            value.aggregate_rss_reservation_bytes or
        !std.mem.eql(u8, &admitted.identity, &identity))
    {
        return error.InvalidProviderRetentionSweepReceipt;
    }
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
        value.slice_call_count !=
            (@as(u64, 1) << @intCast(value.log_size)) * proof_count)
    {
        return error.InvalidProviderRetentionSweepReceipt;
    }
    for (value.ordinals, 0..) |ordinal, index| {
        const expected: u32 = @intCast(index);
        if (ordinal != expected) return error.InvalidProviderRetentionSweepReceipt;
    }
}

fn validateResource(value: topology_v1.ArmResourceUsage) !void {
    if (!std.mem.eql(u8, value.rss_scope, topology_v1.rss_scope) or
        value.source.len == 0) return error.InvalidProviderRetentionSweepReceipt;
    if (std.mem.eql(u8, value.availability, "available")) {
        if (value.cycles == null or value.energy_nj == null or
            value.instructions == null or
            value.lifetime_peak_before_bytes == null or
            value.lifetime_peak_after_bytes == null or
            value.lifetime_peak_after_bytes.? < value.lifetime_peak_before_bytes.?)
        {
            return error.InvalidProviderRetentionSweepReceipt;
        }
    } else if (!std.mem.eql(u8, value.availability, "unavailable")) {
        return error.InvalidProviderRetentionSweepReceipt;
    }
}

fn validateFile(value: receipt_v1.FileIdentity) !void {
    if (value.bytes == 0 or !std.fs.path.isAbsolute(value.path))
        return error.InvalidProviderRetentionSweepReceipt;
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
        return error.InvalidProviderRetentionSweepReceipt;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',')
        return error.InvalidProviderRetentionSweepReceipt;
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
