//! Additive memory admission for raw ordered-provider proofs.
//!
//! The V1 scheduler remains byte- and behavior-stable.  This authority first
//! tries coefficient retention `.always` against an explicit per-job RSS cap,
//! then falls back to `.never`.  The selected policy is also present in the
//! authenticated provider shard plan; the wrappers below require the two
//! authorities to agree before any proof worker starts.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const pcs = @import("stwo_prover_engine").pcs;

const hpc = @import("ethereum_poseidon_provider_hpc_v1.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const omitted_v1 = frontend.testing.narrow_memory_provider_ethereum_omit_proof_v1;
const residency = pcs.residency_estimate;
const shard_plan = pcs.residency_shard_plan;

pub const format_version: u32 = 2;
pub const identity_domain =
    "stwo-zig/ethereum/provider-raw-retention-admission/v2\x00";
pub const provider_preprocessed_columns: u64 = 2;
pub const provider_main_columns: u64 = 445;
pub const provider_interaction_columns: u64 = 12;
pub const provider_composition_columns: u64 = 8;
pub const default_per_job_non_column_reserve_bytes: u64 =
    2 * 1024 * 1024 * 1024;

pub const Digest = [32]u8;
pub const RetentionPolicy = residency.RetentionPolicy;

pub const RequestV2 = struct {
    max_shard_log_size: u32,
    log_blowup_factor: u32,
    requested_concurrent_jobs: u32,
    available_cpu_workers: u32,
    work_items: u32,
    per_job_engine_workers: u32,
    host_byte_budget: u64,
    controller_reserve_bytes: u64,
    per_job_rss_cap_bytes: u64,
    per_job_non_column_reserve_bytes: u64 =
        default_per_job_non_column_reserve_bytes,
};

/// Exact column lower bound plus an explicit non-column reserve.  Fitting is
/// necessary but not sufficient; `RawWorkerAdmissionV1` independently caps
/// aggregate process ownership at the caller's finite RSS budget.
pub const PolicyEstimateV2 = struct {
    policy: RetentionPolicy,
    tree0: residency.Estimate,
    tree1: residency.Estimate,
    tree2: residency.Estimate,
    composition: residency.Estimate,
    retained_opening_lower_bound_bytes: u64,
    commit_transient_lower_bound_bytes: u64,
    staged_peak_lower_bound_bytes: u64,
    non_column_reserve_bytes: u64,
    admitted_peak_bytes: u64,

    pub fn canonical(
        max_shard_log_size: u32,
        log_blowup_factor: u32,
        non_column_reserve_bytes: u64,
        policy: RetentionPolicy,
    ) !PolicyEstimateV2 {
        if (max_shard_log_size < 4 or max_shard_log_size >= 30 or
            log_blowup_factor == 0 or non_column_reserve_bytes == 0 or
            policy == .auto)
        {
            return error.InvalidProviderRetentionAdmission;
        }
        const composition_column_log_size = std.math.add(
            u32,
            max_shard_log_size,
            1,
        ) catch return error.ProviderRetentionAdmissionOverflow;
        const tree0 = try residency.estimateUniform(
            provider_preprocessed_columns,
            max_shard_log_size,
            log_blowup_factor,
            policy,
        );
        const tree1 = try residency.estimateUniform(
            provider_main_columns,
            max_shard_log_size,
            log_blowup_factor,
            policy,
        );
        const tree2 = try residency.estimateUniform(
            provider_interaction_columns,
            max_shard_log_size,
            log_blowup_factor,
            policy,
        );
        const composition = try residency.estimateUniform(
            provider_composition_columns,
            composition_column_log_size,
            log_blowup_factor,
            policy,
        );
        var retained_prior: u64 = 0;
        var transient_peak: u64 = 0;
        inline for (.{ tree0, tree1, tree2, composition }) |stage| {
            transient_peak = @max(
                transient_peak,
                try add(
                    retained_prior,
                    try add(stage.source_bytes, stage.extended_evaluation_bytes),
                ),
            );
            retained_prior = try add(
                retained_prior,
                stage.minimum_resident_bytes,
            );
        }
        const staged_peak = @max(retained_prior, transient_peak);
        return .{
            .policy = policy,
            .tree0 = tree0,
            .tree1 = tree1,
            .tree2 = tree2,
            .composition = composition,
            .retained_opening_lower_bound_bytes = retained_prior,
            .commit_transient_lower_bound_bytes = transient_peak,
            .staged_peak_lower_bound_bytes = staged_peak,
            .non_column_reserve_bytes = non_column_reserve_bytes,
            .admitted_peak_bytes = try add(
                staged_peak,
                non_column_reserve_bytes,
            ),
        };
    }
};

/// Receipt-ready selection telemetry.  Every field participates in the
/// `AdmissionV2.identity`; JSON producers must serialize these values rather
/// than infer policy from proof timing or host state.
pub const ReceiptAuthorityV2 = struct {
    format: u32,
    selected_coefficient_retention: []const u8,
    fell_back_to_never: bool,
    max_shard_log_size: u32,
    always_admitted_peak_bytes: u64,
    never_admitted_peak_bytes: u64,
    per_job_rss_cap_bytes: u64,
    admitted_concurrent_jobs: u32,
    aggregate_rss_reservation_bytes: u64,
    worker_admission_identity: Digest,
    identity: Digest,
};

pub const AdmissionV2 = struct {
    format: u32,
    request: RequestV2,
    always_estimate: PolicyEstimateV2,
    never_estimate: PolicyEstimateV2,
    selected_policy: RetentionPolicy,
    fell_back_to_never: bool,
    worker: hpc.RawWorkerAdmissionV1,
    identity: Digest,

    pub fn create(request: RequestV2) !AdmissionV2 {
        if (request.max_shard_log_size < 4 or
            request.max_shard_log_size >= 30 or
            request.log_blowup_factor == 0 or
            request.per_job_non_column_reserve_bytes == 0 or
            request.per_job_rss_cap_bytes == 0)
        {
            return error.InvalidProviderRetentionAdmission;
        }
        const worker = try hpc.RawWorkerAdmissionV1.create(.{
            .requested_concurrent_jobs = request.requested_concurrent_jobs,
            .available_cpu_workers = request.available_cpu_workers,
            .work_items = request.work_items,
            .per_job_engine_workers = request.per_job_engine_workers,
            .host_byte_budget = request.host_byte_budget,
            .controller_reserve_bytes = request.controller_reserve_bytes,
            .per_job_rss_budget_bytes = request.per_job_rss_cap_bytes,
        });
        const always_estimate = try PolicyEstimateV2.canonical(
            request.max_shard_log_size,
            request.log_blowup_factor,
            request.per_job_non_column_reserve_bytes,
            .always,
        );
        const never_estimate = try PolicyEstimateV2.canonical(
            request.max_shard_log_size,
            request.log_blowup_factor,
            request.per_job_non_column_reserve_bytes,
            .never,
        );
        const selected_policy: RetentionPolicy = if (always_estimate.admitted_peak_bytes <=
            request.per_job_rss_cap_bytes) .always else if (never_estimate.admitted_peak_bytes <=
            request.per_job_rss_cap_bytes) .never else return error.ProviderRetentionPolicyBudgetExceeded;
        const selected = if (selected_policy == .always)
            always_estimate
        else
            never_estimate;
        const aggregate_required = std.math.mul(
            u64,
            selected.admitted_peak_bytes,
            worker.admitted_concurrent_jobs,
        ) catch return error.ProviderRetentionAdmissionOverflow;
        const worker_budget = request.host_byte_budget -
            request.controller_reserve_bytes;
        if (aggregate_required > worker_budget)
            return error.ProviderRetentionPolicyBudgetExceeded;
        var result = AdmissionV2{
            .format = format_version,
            .request = request,
            .always_estimate = always_estimate,
            .never_estimate = never_estimate,
            .selected_policy = selected_policy,
            .fell_back_to_never = selected_policy == .never,
            .worker = worker,
            .identity = undefined,
        };
        result.identity = admissionIdentity(result);
        return result;
    }

    pub fn validate(self: AdmissionV2) !void {
        const expected = try create(self.request);
        if (!std.meta.eql(self, expected))
            return error.InvalidProviderRetentionAdmission;
    }

    pub fn validateAgainstPlan(
        self: AdmissionV2,
        plan: *const authority.ProviderShardPlanV1,
    ) !void {
        try self.validate();
        const expected = self.providerShardRequest(plan.total_call_count);
        if (!std.meta.eql(plan.residency.request, expected) or
            plan.residency.result.shard_log_size !=
                self.request.max_shard_log_size)
        {
            return error.ProviderRetentionPlanMismatch;
        }
    }

    pub fn providerShardRequest(
        self: AdmissionV2,
        logical_row_count: u64,
    ) shard_plan.Request {
        return .{
            .logical_row_count = logical_row_count,
            .column_count = provider_main_columns,
            .min_shard_log_size = self.request.max_shard_log_size,
            .max_shard_log_size = self.request.max_shard_log_size,
            .log_blowup_factor = self.request.log_blowup_factor,
            .retention_policy = self.selected_policy,
            .host_byte_budget = self.request.host_byte_budget,
            .reserved_host_bytes = self.request.controller_reserve_bytes,
            .requested_parallel_shards = self.worker.admitted_concurrent_jobs,
        };
    }

    pub fn receiptAuthority(self: AdmissionV2) ReceiptAuthorityV2 {
        return .{
            .format = format_version,
            .selected_coefficient_retention = policyName(self.selected_policy),
            .fell_back_to_never = self.fell_back_to_never,
            .max_shard_log_size = self.request.max_shard_log_size,
            .always_admitted_peak_bytes = self.always_estimate.admitted_peak_bytes,
            .never_admitted_peak_bytes = self.never_estimate.admitted_peak_bytes,
            .per_job_rss_cap_bytes = self.request.per_job_rss_cap_bytes,
            .admitted_concurrent_jobs = self.worker.admitted_concurrent_jobs,
            .aggregate_rss_reservation_bytes = self.worker.aggregate_rss_reservation_bytes,
            .worker_admission_identity = self.worker.identity,
            .identity = self.identity,
        };
    }
};

pub fn proveJointRawParallelBounded(
    allocator: std.mem.Allocator,
    source: hpc.JointSourceV1,
    jobs: []const hpc.RawProviderJobV1,
    admission: AdmissionV2,
) ![]hpc.RawProviderPublicationV1 {
    try admission.validateAgainstPlan(source.plan);
    return hpc.proveJointRawParallelBounded(
        allocator,
        source,
        jobs,
        admission.worker,
    );
}

pub fn proveOmittedRawParallelBounded(
    allocator: std.mem.Allocator,
    source: omitted_v1.Source(hpc.Engine),
    jobs: []const hpc.RawProviderJobV1,
    admission: AdmissionV2,
) ![]hpc.RawProviderPublicationV1 {
    try admission.validateAgainstPlan(source.plan);
    return hpc.proveOmittedRawParallelBounded(
        allocator,
        source,
        jobs,
        admission.worker,
    );
}

pub fn policyName(policy: RetentionPolicy) []const u8 {
    return switch (policy) {
        .always => "always",
        .never => "never",
        .auto => "auto",
    };
}

fn admissionIdentity(value: AdmissionV2) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(identity_domain);
    hashInt(&hash, u32, value.format);
    hashRequest(&hash, value.request);
    hashEstimate(&hash, value.always_estimate);
    hashEstimate(&hash, value.never_estimate);
    hashInt(&hash, u8, @intFromEnum(value.selected_policy));
    hashBool(&hash, value.fell_back_to_never);
    hash.update(&value.worker.identity);
    return hash.finalResult();
}

fn hashRequest(hash: anytype, value: RequestV2) void {
    hashInt(hash, u32, value.max_shard_log_size);
    hashInt(hash, u32, value.log_blowup_factor);
    hashInt(hash, u32, value.requested_concurrent_jobs);
    hashInt(hash, u32, value.available_cpu_workers);
    hashInt(hash, u32, value.work_items);
    hashInt(hash, u32, value.per_job_engine_workers);
    hashInt(hash, u64, value.host_byte_budget);
    hashInt(hash, u64, value.controller_reserve_bytes);
    hashInt(hash, u64, value.per_job_rss_cap_bytes);
    hashInt(hash, u64, value.per_job_non_column_reserve_bytes);
}

fn hashEstimate(hash: anytype, value: PolicyEstimateV2) void {
    hashInt(hash, u8, @intFromEnum(value.policy));
    inline for (.{ value.tree0, value.tree1, value.tree2, value.composition }) |stage| {
        hashInt(hash, u64, stage.column_count);
        hashInt(hash, u64, stage.source_bytes);
        hashInt(hash, u64, stage.retained_coefficient_bytes);
        hashInt(hash, u64, stage.extended_evaluation_bytes);
        hashInt(hash, u64, stage.minimum_resident_bytes);
        hashInt(hash, u32, stage.max_column_log_size);
        hashInt(hash, u32, stage.log_blowup_factor);
        hashInt(hash, u8, @intFromEnum(stage.retention_policy));
    }
    hashInt(hash, u64, value.retained_opening_lower_bound_bytes);
    hashInt(hash, u64, value.commit_transient_lower_bound_bytes);
    hashInt(hash, u64, value.staged_peak_lower_bound_bytes);
    hashInt(hash, u64, value.non_column_reserve_bytes);
    hashInt(hash, u64, value.admitted_peak_bytes);
}

fn hashBool(hash: anytype, value: bool) void {
    hash.update(&.{@intFromBool(value)});
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn add(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch
        error.ProviderRetentionAdmissionOverflow;
}

test "raw retention admission prefers always and fails closed to never" {
    const request = RequestV2{
        .max_shard_log_size = 20,
        .log_blowup_factor = 1,
        .requested_concurrent_jobs = 4,
        .available_cpu_workers = 18,
        .work_items = 4,
        .per_job_engine_workers = 4,
        .host_byte_budget = hpc.default_host_byte_budget,
        .controller_reserve_bytes = hpc.default_controller_reserve_bytes,
        .per_job_rss_cap_bytes = hpc.default_worker_rss_budget_bytes,
    };
    const preferred = try AdmissionV2.create(request);
    try preferred.validate();
    try std.testing.expectEqual(RetentionPolicy.always, preferred.selected_policy);
    try std.testing.expect(!preferred.fell_back_to_never);
    try std.testing.expect(
        preferred.always_estimate.admitted_peak_bytes <=
            request.per_job_rss_cap_bytes,
    );
    const wire = preferred.receiptAuthority();
    try std.testing.expectEqualStrings("always", wire.selected_coefficient_retention);
    try std.testing.expectEqualSlices(u8, &preferred.identity, &wire.identity);

    var fallback_request = request;
    fallback_request.per_job_rss_cap_bytes =
        preferred.always_estimate.admitted_peak_bytes - 1;
    const fallback = try AdmissionV2.create(fallback_request);
    try std.testing.expectEqual(RetentionPolicy.never, fallback.selected_policy);
    try std.testing.expect(fallback.fell_back_to_never);
    try std.testing.expect(
        fallback.never_estimate.admitted_peak_bytes <=
            fallback_request.per_job_rss_cap_bytes,
    );

    var mutated = preferred;
    mutated.selected_policy = .never;
    try std.testing.expectError(
        error.InvalidProviderRetentionAdmission,
        mutated.validate(),
    );
}

comptime {
    if (provider_main_columns != 445 or provider_interaction_columns != 12)
        @compileError("ordered-provider physical geometry drifted");
}
