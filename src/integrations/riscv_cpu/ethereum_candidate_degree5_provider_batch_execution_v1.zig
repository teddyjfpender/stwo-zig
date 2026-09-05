//! Process-local batch authority for candidate degree-five provider proofs.
//!
//! The shard plan remains transcript/call custody. CPU and RSS capacity are
//! runtime-only inputs and never alter provider statements or proof bytes.
//! This owner intersects the detected/caller-supplied host capacity with the
//! prover's fixed WorkPool capacity and the plan's authenticated residency
//! estimate. It does not inherit the historical N=4 matched-A/B fixture.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const prover_engine = @import("stwo_prover_engine");
const work_pool = prover_engine.work_pool;
const residency = prover_engine.pcs.residency_estimate;

const host_execution =
    @import("ethereum_incremental_full_leaf_throughput_execution_v1.zig");

const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const candidate_provider =
    frontend.testing.narrow_memory_provider_degree5_ethereum_candidate_v1;
const component = frontend.air.typed_poseidon2_degree5_component;
const provider_order = frontend.testing.narrow_memory_provider_order_component;
const recursive_protocol = frontend.recursion.protocol;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 3;
pub const PROTOCOL_BOUND = false;
pub const TRANSCRIPT_MIXED = false;
pub const SERIALIZABLE = false;
pub const MAX_ENGINE_WORKERS = work_pool.MAX_WORKERS;
pub const DEFAULT_NON_COLUMN_RESERVE_PER_OWNER: u64 = 512 * 1024 * 1024;
pub const MAX_CANONICAL_PROOF_BYTES_PER_SHARD: u64 = 128 * 1024 * 1024;
pub const Q193_POW_BITS: u32 = recursive_protocol.PCS_POW_BITS;
pub const Q193_QUERY_COUNT: u32 = @intCast(recursive_protocol.FRI_QUERY_COUNT);
pub const Q193_FRI_LOG_BLOWUP_FACTOR: u32 =
    recursive_protocol.FRI_LOG_BLOWUP_FACTOR;
pub const D5_QUOTIENT_EXPANSION_BITS: u32 =
    component.QUOTIENT_EXPANSION_BITS;
pub const D5_COMPOSITION_LOG_SPLIT: u32 =
    component.COMPOSITION_LOG_SPLIT;
pub const D5_PREPROCESSED_COLUMNS: u64 = 2;
pub const D5_MAIN_COLUMNS: u64 = component.MAIN_COLUMNS;
pub const D5_INTERACTION_COLUMNS: u64 = component.INTERACTION_COLUMNS +
    provider_order.interaction_column_count;
pub const D5_ACCELERATED_INTERACTION_COLUMNS: u64 = component.INTERACTION_COLUMNS;
pub const D5_COMPOSITION_DOMAIN_SCRATCH_COLUMNS: u64 =
    D5_PREPROCESSED_COLUMNS + D5_MAIN_COLUMNS +
    D5_ACCELERATED_INTERACTION_COLUMNS;
/// Resident composition-domain scratch owners that may hold their gigabyte
/// window at once.  Two windows let one shard's composition kernels run while
/// the next shard's coefficients are being expanded; the reservation below
/// scales with this count.
pub const D5_COMPOSITION_DOMAIN_SCRATCH_CONCURRENT_OWNERS: u16 = 2;
pub const D5_COMPOSITION_COLUMNS: u64 =
    4 * (@as(u64, 1) << @intCast(D5_COMPOSITION_LOG_SPLIT));

pub const HostCapacityV1 = host_execution.HostCapacityV1;

pub const RequestV1 = struct {
    concurrent_owners: usize,
    engine_workers_per_owner: usize,
    total_host_byte_budget: u64,
    controller_reserve_bytes: u64,
    non_column_reserve_per_owner: u64 =
        DEFAULT_NON_COLUMN_RESERVE_PER_OWNER,
};

/// Exact lower-bound PCS geometry for one retained D5 shard. The canonical
/// call-partition plan remains the legacy 445-column authority, while this
/// process-local sibling accounts for the columns the D5 prover actually
/// owns: 2/239/12/16 across Tree0/1/2/composition. The FRI LDE blowup and the
/// D5 quotient expansion are intentionally distinct fields. A separately
/// accounted one-owner scratch evaluates only the 2/239/8 accelerated inputs
/// on the composition domain; the four order columns in Tree2 remain host-side.
pub const ResourceEstimateV1 = struct {
    trace_log_size: u32,
    fri_log_blowup_factor: u32,
    quotient_expansion_bits: u32,
    composition_log_split: u32,
    composition_column_log_size: u32,
    tree0_minimum_resident_bytes: u64,
    tree1_minimum_resident_bytes: u64,
    tree2_minimum_resident_bytes: u64,
    composition_minimum_resident_bytes: u64,
    retained_opening_lower_bound_bytes: u64,
    commit_transient_lower_bound_bytes: u64,
    staged_peak_lower_bound_bytes: u64,
    identity_sha256: [32]u8,

    pub fn canonical(trace_log_size: u32) !ResourceEstimateV1 {
        const composition_log_size = std.math.add(
            u32,
            trace_log_size,
            D5_QUOTIENT_EXPANSION_BITS,
        ) catch return error.Degree5ProviderBatchExecutionOverflow;
        const composition_column_log_size = std.math.sub(
            u32,
            composition_log_size,
            D5_COMPOSITION_LOG_SPLIT,
        ) catch return error.Degree5ProviderBatchExecutionOverflow;
        const tree0 = try stageEstimate(
            D5_PREPROCESSED_COLUMNS,
            trace_log_size,
        );
        const tree1 = try stageEstimate(D5_MAIN_COLUMNS, trace_log_size);
        const tree2 = try stageEstimate(
            D5_INTERACTION_COLUMNS,
            trace_log_size,
        );
        const composition = try stageEstimate(
            D5_COMPOSITION_COLUMNS,
            composition_column_log_size,
        );
        const totals = try stagedTotals(.{ tree0, tree1, tree2, composition });
        var result = ResourceEstimateV1{
            .trace_log_size = trace_log_size,
            .fri_log_blowup_factor = Q193_FRI_LOG_BLOWUP_FACTOR,
            .quotient_expansion_bits = D5_QUOTIENT_EXPANSION_BITS,
            .composition_log_split = D5_COMPOSITION_LOG_SPLIT,
            .composition_column_log_size = composition_column_log_size,
            .tree0_minimum_resident_bytes = tree0.minimum_resident_bytes,
            .tree1_minimum_resident_bytes = tree1.minimum_resident_bytes,
            .tree2_minimum_resident_bytes = tree2.minimum_resident_bytes,
            .composition_minimum_resident_bytes = composition.minimum_resident_bytes,
            .retained_opening_lower_bound_bytes = totals.retained,
            .commit_transient_lower_bound_bytes = totals.transient,
            .staged_peak_lower_bound_bytes = totals.peak,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = resourceIdentity(&result);
        return result;
    }

    pub fn validate(self: ResourceEstimateV1) !void {
        const expected = try canonical(self.trace_log_size);
        if (!std.meta.eql(self, expected))
            return error.InvalidDegree5ProviderBatchResourceEstimate;
    }
};

pub const AuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    host: HostCapacityV1,
    plan_identity: [32]u8,
    shard_count: u32,
    concurrent_owners: u16,
    engine_workers_per_owner: u16,
    aggregate_worker_tokens: u16,
    total_host_byte_budget: u64,
    controller_reserve_bytes: u64,
    d5_resource: ResourceEstimateV1,
    non_column_reserve_per_owner: u64,
    admitted_bytes_per_owner: u64,
    retained_stage_a_column_reservation_bytes: u64,
    retained_stage_a_non_column_reservation_bytes: u64,
    active_post_stage_a_column_reservation_bytes: u64,
    composition_domain_scratch_concurrent_owners: u16,
    composition_domain_scratch_reservation_bytes: u64,
    encoded_proof_reservation_bytes: u64,
    aggregate_owner_reservation_bytes: u64,
    total_reservation_bytes: u64,
    wave_count: u32,
    identity_sha256: [32]u8,

    pub fn initAgainstPlan(
        host: HostCapacityV1,
        plan: *const provider_authority.ProviderShardPlanV1,
        request: RequestV1,
    ) !AuthorityV1 {
        try host.validate();
        try validateQ193Plan(plan);
        const shard_count = std.math.cast(u32, plan.shards.len) orelse
            return error.InvalidDegree5ProviderBatchExecution;
        const owners = std.math.cast(u16, request.concurrent_owners) orelse
            return error.InvalidDegree5ProviderBatchExecution;
        const engine_workers = std.math.cast(
            u16,
            request.engine_workers_per_owner,
        ) orelse return error.InvalidDegree5ProviderBatchExecution;
        const aggregate_workers_usize = std.math.mul(
            usize,
            request.concurrent_owners,
            request.engine_workers_per_owner,
        ) catch return error.Degree5ProviderBatchExecutionOverflow;
        const aggregate_workers = std.math.cast(
            u16,
            aggregate_workers_usize,
        ) orelse return error.Degree5ProviderBatchExecutionOverflow;
        const resource = try ResourceEstimateV1.canonical(
            plan.residency.result.shard_log_size,
        );
        const per_owner_bytes = std.math.add(
            u64,
            resource.staged_peak_lower_bound_bytes,
            request.non_column_reserve_per_owner,
        ) catch return error.Degree5ProviderBatchExecutionOverflow;
        const reservations = try batchReservations(
            plan,
            owners,
            request.non_column_reserve_per_owner,
        );
        const total_reserved = std.math.add(
            u64,
            request.controller_reserve_bytes,
            reservations.aggregate_owner,
        ) catch return error.Degree5ProviderBatchExecutionOverflow;
        if (total_reserved > request.total_host_byte_budget)
            return error.Degree5ProviderBatchHostBudgetExceeded;
        const waves = divCeil(shard_count, owners) catch
            return error.InvalidDegree5ProviderBatchExecution;

        var result = AuthorityV1{
            .host = host,
            .plan_identity = plan.identity,
            .shard_count = shard_count,
            .concurrent_owners = owners,
            .engine_workers_per_owner = engine_workers,
            .aggregate_worker_tokens = aggregate_workers,
            .total_host_byte_budget = request.total_host_byte_budget,
            .controller_reserve_bytes = request.controller_reserve_bytes,
            .d5_resource = resource,
            .non_column_reserve_per_owner = request.non_column_reserve_per_owner,
            .admitted_bytes_per_owner = per_owner_bytes,
            .retained_stage_a_column_reservation_bytes = reservations.retained_stage_a_columns,
            .retained_stage_a_non_column_reservation_bytes = reservations.retained_stage_a_non_column,
            .active_post_stage_a_column_reservation_bytes = reservations.active_post_stage_a_columns,
            .composition_domain_scratch_concurrent_owners = D5_COMPOSITION_DOMAIN_SCRATCH_CONCURRENT_OWNERS,
            .composition_domain_scratch_reservation_bytes = reservations.composition_domain_scratch,
            .encoded_proof_reservation_bytes = reservations.encoded_proofs,
            .aggregate_owner_reservation_bytes = reservations.aggregate_owner,
            .total_reservation_bytes = total_reserved,
            .wave_count = waves,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity(&result);
        try result.validateAgainstPlan(plan);
        return result;
    }

    pub fn validateAgainstPlan(
        self: *const AuthorityV1,
        plan: *const provider_authority.ProviderShardPlanV1,
    ) !void {
        try self.host.validate();
        try validateQ193Plan(plan);
        try self.d5_resource.validate();
        try plan.residency.validate();
        const host_worker_limit = try self.host.admittedWorkerLimit();
        const expected_aggregate_workers = std.math.mul(
            usize,
            self.concurrent_owners,
            self.engine_workers_per_owner,
        ) catch return error.Degree5ProviderBatchExecutionOverflow;
        const expected_per_owner = std.math.add(
            u64,
            self.d5_resource.staged_peak_lower_bound_bytes,
            self.non_column_reserve_per_owner,
        ) catch return error.Degree5ProviderBatchExecutionOverflow;
        const reservations = try batchReservations(
            plan,
            self.concurrent_owners,
            self.non_column_reserve_per_owner,
        );
        const expected_total = std.math.add(
            u64,
            self.controller_reserve_bytes,
            reservations.aggregate_owner,
        ) catch return error.Degree5ProviderBatchExecutionOverflow;
        const host_limit_u64 = std.math.cast(u64, self.host.host_byte_limit) orelse
            return error.Degree5ProviderBatchExecutionOverflow;
        if (self.format_version != FORMAT_VERSION or
            self.shard_count == 0 or self.shard_count != plan.shards.len or
            !std.mem.eql(u8, &self.plan_identity, &plan.identity) or
            self.concurrent_owners == 0 or
            self.concurrent_owners > self.shard_count or
            self.concurrent_owners != plan.residency.result.admitted_parallel_shards or
            self.engine_workers_per_owner == 0 or
            self.engine_workers_per_owner > MAX_ENGINE_WORKERS or
            expected_aggregate_workers != self.aggregate_worker_tokens or
            expected_aggregate_workers > host_worker_limit or
            self.total_host_byte_budget == 0 or
            self.total_host_byte_budget > host_limit_u64 or
            self.controller_reserve_bytes >= self.total_host_byte_budget or
            self.d5_resource.trace_log_size !=
                plan.residency.result.shard_log_size or
            self.non_column_reserve_per_owner == 0 or
            self.admitted_bytes_per_owner != expected_per_owner or
            self.retained_stage_a_column_reservation_bytes !=
                reservations.retained_stage_a_columns or
            self.retained_stage_a_non_column_reservation_bytes !=
                reservations.retained_stage_a_non_column or
            self.active_post_stage_a_column_reservation_bytes !=
                reservations.active_post_stage_a_columns or
            self.composition_domain_scratch_concurrent_owners !=
                D5_COMPOSITION_DOMAIN_SCRATCH_CONCURRENT_OWNERS or
            self.composition_domain_scratch_reservation_bytes !=
                reservations.composition_domain_scratch or
            self.encoded_proof_reservation_bytes !=
                reservations.encoded_proofs or
            self.aggregate_owner_reservation_bytes !=
                reservations.aggregate_owner or
            self.total_reservation_bytes != expected_total or
            expected_total > self.total_host_byte_budget or
            self.wave_count != try divCeil(
                self.shard_count,
                self.concurrent_owners,
            ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &identity(self),
        )) return error.InvalidDegree5ProviderBatchExecution;
    }

    pub fn executionProfile(
        self: *const AuthorityV1,
        program: candidate_provider.VerifierProgramAuthorityV2,
    ) !candidate_provider.ExecutionProfileV2 {
        const per_owner_host_budget = std.math.cast(
            u64,
            self.admitted_bytes_per_owner,
        ) orelse return error.Degree5ProviderBatchExecutionOverflow;
        return candidate_provider.ExecutionProfileV2.runtime(
            program.base,
            self.concurrent_owners,
            self.engine_workers_per_owner,
            per_owner_host_budget,
        );
    }
};

pub const TopologyReceiptV1 = struct {
    total_call_count: u64,
    pcs_pow_bits: u32,
    fri_query_count: u32,
    fri_log_blowup_factor: u32,
    quotient_expansion_bits: u32,
    planner_shard_log_size: u32,
    shard_count: u32,
    concurrent_owners: u16,
    wave_count: u32,
    minimum_descriptor_log_size: u32,
    maximum_descriptor_log_size: u32,
    committed_rows: u64,
    padding_rows: u64,
    plan_identity: [32]u8,
    resource_identity_sha256: [32]u8,
    execution_identity_sha256: [32]u8,
    max_canonical_proof_bytes_per_shard: u64,
    retained_stage_a_column_reservation_bytes: u64,
    retained_stage_a_non_column_reservation_bytes: u64,
    active_post_stage_a_column_reservation_bytes: u64,
    composition_domain_scratch_concurrent_owners: u16,
    composition_domain_scratch_reservation_bytes: u64,
    encoded_proof_reservation_bytes: u64,
    aggregate_owner_reservation_bytes: u64,
    controller_reserve_bytes: u64,
    total_reservation_bytes: u64,

    pub fn init(
        plan: *const provider_authority.ProviderShardPlanV1,
        execution: *const AuthorityV1,
    ) !TopologyReceiptV1 {
        try execution.validateAgainstPlan(plan);
        var minimum_log: u32 = std.math.maxInt(u32);
        var maximum_log: u32 = 0;
        var committed_rows: u64 = 0;
        for (plan.shards) |descriptor| {
            minimum_log = @min(minimum_log, descriptor.expected_log_size);
            maximum_log = @max(maximum_log, descriptor.expected_log_size);
            if (descriptor.expected_log_size >= 63)
                return error.Degree5ProviderBatchExecutionOverflow;
            committed_rows = std.math.add(
                u64,
                committed_rows,
                @as(u64, 1) << @intCast(descriptor.expected_log_size),
            ) catch return error.Degree5ProviderBatchExecutionOverflow;
        }
        if (committed_rows < plan.total_call_count)
            return error.InvalidDegree5ProviderBatchTopology;
        const result = TopologyReceiptV1{
            .total_call_count = plan.total_call_count,
            .pcs_pow_bits = Q193_POW_BITS,
            .fri_query_count = Q193_QUERY_COUNT,
            .fri_log_blowup_factor = Q193_FRI_LOG_BLOWUP_FACTOR,
            .quotient_expansion_bits = D5_QUOTIENT_EXPANSION_BITS,
            .planner_shard_log_size = plan.residency.result.shard_log_size,
            .shard_count = @intCast(plan.shards.len),
            .concurrent_owners = execution.concurrent_owners,
            .wave_count = execution.wave_count,
            .minimum_descriptor_log_size = minimum_log,
            .maximum_descriptor_log_size = maximum_log,
            .committed_rows = committed_rows,
            .padding_rows = committed_rows - plan.total_call_count,
            .plan_identity = plan.identity,
            .resource_identity_sha256 = execution.d5_resource.identity_sha256,
            .execution_identity_sha256 = execution.identity_sha256,
            .max_canonical_proof_bytes_per_shard = MAX_CANONICAL_PROOF_BYTES_PER_SHARD,
            .retained_stage_a_column_reservation_bytes = execution.retained_stage_a_column_reservation_bytes,
            .retained_stage_a_non_column_reservation_bytes = execution.retained_stage_a_non_column_reservation_bytes,
            .active_post_stage_a_column_reservation_bytes = execution.active_post_stage_a_column_reservation_bytes,
            .composition_domain_scratch_concurrent_owners = execution.composition_domain_scratch_concurrent_owners,
            .composition_domain_scratch_reservation_bytes = execution.composition_domain_scratch_reservation_bytes,
            .encoded_proof_reservation_bytes = execution.encoded_proof_reservation_bytes,
            .aggregate_owner_reservation_bytes = execution.aggregate_owner_reservation_bytes,
            .controller_reserve_bytes = execution.controller_reserve_bytes,
            .total_reservation_bytes = execution.total_reservation_bytes,
        };
        try result.validate(plan, execution);
        return result;
    }

    pub fn validate(
        self: TopologyReceiptV1,
        plan: *const provider_authority.ProviderShardPlanV1,
        execution: *const AuthorityV1,
    ) !void {
        try execution.validateAgainstPlan(plan);
        var minimum_log: u32 = std.math.maxInt(u32);
        var maximum_log: u32 = 0;
        var committed_rows: u64 = 0;
        for (plan.shards) |descriptor| {
            minimum_log = @min(minimum_log, descriptor.expected_log_size);
            maximum_log = @max(maximum_log, descriptor.expected_log_size);
            committed_rows = std.math.add(
                u64,
                committed_rows,
                @as(u64, 1) << @intCast(descriptor.expected_log_size),
            ) catch return error.Degree5ProviderBatchExecutionOverflow;
        }
        if (self.total_call_count != plan.total_call_count or
            self.pcs_pow_bits != Q193_POW_BITS or
            self.fri_query_count != Q193_QUERY_COUNT or
            self.fri_log_blowup_factor != Q193_FRI_LOG_BLOWUP_FACTOR or
            self.quotient_expansion_bits != D5_QUOTIENT_EXPANSION_BITS or
            self.planner_shard_log_size != plan.residency.result.shard_log_size or
            self.shard_count != plan.shards.len or
            self.concurrent_owners != execution.concurrent_owners or
            self.wave_count != execution.wave_count or
            self.minimum_descriptor_log_size != minimum_log or
            self.maximum_descriptor_log_size != maximum_log or
            self.committed_rows != committed_rows or
            self.padding_rows != committed_rows - plan.total_call_count or
            !std.mem.eql(u8, &self.plan_identity, &plan.identity) or
            !std.mem.eql(
                u8,
                &self.resource_identity_sha256,
                &execution.d5_resource.identity_sha256,
            ) or
            !std.mem.eql(
                u8,
                &self.execution_identity_sha256,
                &execution.identity_sha256,
            ) or self.max_canonical_proof_bytes_per_shard !=
            MAX_CANONICAL_PROOF_BYTES_PER_SHARD or
            self.retained_stage_a_column_reservation_bytes !=
                execution.retained_stage_a_column_reservation_bytes or
            self.retained_stage_a_non_column_reservation_bytes !=
                execution.retained_stage_a_non_column_reservation_bytes or
            self.active_post_stage_a_column_reservation_bytes !=
                execution.active_post_stage_a_column_reservation_bytes or
            self.composition_domain_scratch_concurrent_owners !=
                execution.composition_domain_scratch_concurrent_owners or
            self.composition_domain_scratch_reservation_bytes !=
                execution.composition_domain_scratch_reservation_bytes or
            self.encoded_proof_reservation_bytes !=
                execution.encoded_proof_reservation_bytes or
            self.aggregate_owner_reservation_bytes !=
                execution.aggregate_owner_reservation_bytes or
            self.controller_reserve_bytes != execution.controller_reserve_bytes or
            self.total_reservation_bytes != execution.total_reservation_bytes)
        {
            return error.InvalidDegree5ProviderBatchTopology;
        }
    }
};

fn identity(value: *const AuthorityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/ethereum-candidate-d5-provider-batch-execution/v3\x00");
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u64, value.host.logical_cpu_count);
    hashInt(&hash, u64, value.host.host_byte_limit);
    hash.update(&value.plan_identity);
    hashInt(&hash, u32, value.shard_count);
    hashInt(&hash, u16, value.concurrent_owners);
    hashInt(&hash, u16, value.engine_workers_per_owner);
    hashInt(&hash, u16, value.aggregate_worker_tokens);
    hashInt(&hash, u64, value.total_host_byte_budget);
    hashInt(&hash, u64, value.controller_reserve_bytes);
    hash.update(&value.d5_resource.identity_sha256);
    hashInt(&hash, u64, value.non_column_reserve_per_owner);
    hashInt(&hash, u64, value.admitted_bytes_per_owner);
    hashInt(&hash, u64, value.retained_stage_a_column_reservation_bytes);
    hashInt(&hash, u64, value.retained_stage_a_non_column_reservation_bytes);
    hashInt(&hash, u64, value.active_post_stage_a_column_reservation_bytes);
    hashInt(&hash, u16, value.composition_domain_scratch_concurrent_owners);
    hashInt(&hash, u64, value.composition_domain_scratch_reservation_bytes);
    hashInt(&hash, u64, value.encoded_proof_reservation_bytes);
    hashInt(&hash, u64, value.aggregate_owner_reservation_bytes);
    hashInt(&hash, u64, value.total_reservation_bytes);
    hashInt(&hash, u32, value.wave_count);
    return hash.finalResult();
}

pub fn validateQ193Plan(
    plan: *const provider_authority.ProviderShardPlanV1,
) !void {
    try plan.residency.validate();
    const request = plan.residency.request;
    if (Q193_POW_BITS != 16 or Q193_QUERY_COUNT != 193 or
        Q193_FRI_LOG_BLOWUP_FACTOR != 1 or
        D5_QUOTIENT_EXPANSION_BITS != 2 or
        D5_COMPOSITION_LOG_SPLIT != 2 or
        D5_PREPROCESSED_COLUMNS != 2 or D5_MAIN_COLUMNS != 239 or
        D5_INTERACTION_COLUMNS != 12 or
        D5_ACCELERATED_INTERACTION_COLUMNS != 8 or
        D5_COMPOSITION_DOMAIN_SCRATCH_COLUMNS != 249 or
        D5_COMPOSITION_DOMAIN_SCRATCH_CONCURRENT_OWNERS != 2 or
        D5_COMPOSITION_COLUMNS != 16 or
        request.log_blowup_factor != Q193_FRI_LOG_BLOWUP_FACTOR or
        request.retention_policy != .always)
    {
        return error.InvalidDegree5ProviderQ193Plan;
    }
}

fn stageEstimate(
    column_count: u64,
    log_size: u32,
) !residency.Estimate {
    return residency.estimateUniform(
        column_count,
        log_size,
        Q193_FRI_LOG_BLOWUP_FACTOR,
        .always,
    );
}

const StagedTotalsV1 = struct { retained: u64, transient: u64, peak: u64 };

const BatchReservationsV1 = struct {
    retained_stage_a_columns: u64,
    retained_stage_a_non_column: u64,
    active_post_stage_a_columns: u64,
    composition_domain_scratch: u64,
    encoded_proofs: u64,
    aggregate_owner: u64,
};

/// Accounts for the actual lifecycle used by `OwnedPreparedBatchV1`: every
/// shard retains its Tree0/Tree1 Stage-A owner until the shared manifest is
/// complete, while at most `concurrent_owners` continue through the remaining
/// trees/proof construction. Canonical proof bytes accumulate for every shard
/// and therefore have a separate all-shard reservation. A process-global lease
/// admits exactly one largest-shard composition-domain scratch at a time.
fn batchReservations(
    plan: *const provider_authority.ProviderShardPlanV1,
    concurrent_owners: u16,
    non_column_reserve_per_owner: u64,
) !BatchReservationsV1 {
    var retained_stage_a_columns: u64 = 0;
    var maximum_post_stage_a_columns: u64 = 0;
    var maximum_composition_domain_scratch: u64 = 0;
    for (plan.shards) |descriptor| {
        const resource = try ResourceEstimateV1.canonical(
            descriptor.expected_log_size,
        );
        const retained_stage_a = try add(
            resource.tree0_minimum_resident_bytes,
            resource.tree1_minimum_resident_bytes,
        );
        retained_stage_a_columns = try add(
            retained_stage_a_columns,
            retained_stage_a,
        );
        maximum_post_stage_a_columns = @max(
            maximum_post_stage_a_columns,
            std.math.sub(
                u64,
                resource.staged_peak_lower_bound_bytes,
                retained_stage_a,
            ) catch return error.Degree5ProviderBatchExecutionOverflow,
        );
        maximum_composition_domain_scratch = @max(
            maximum_composition_domain_scratch,
            try compositionDomainScratchBytes(descriptor.expected_log_size),
        );
    }
    const retained_stage_a_non_column = std.math.mul(
        u64,
        non_column_reserve_per_owner,
        plan.shards.len,
    ) catch return error.Degree5ProviderBatchExecutionOverflow;
    const active_post_stage_a_columns = std.math.mul(
        u64,
        maximum_post_stage_a_columns,
        concurrent_owners,
    ) catch return error.Degree5ProviderBatchExecutionOverflow;
    const encoded_proofs = std.math.mul(
        u64,
        MAX_CANONICAL_PROOF_BYTES_PER_SHARD,
        plan.shards.len,
    ) catch return error.Degree5ProviderBatchExecutionOverflow;
    var aggregate = try add(
        retained_stage_a_columns,
        retained_stage_a_non_column,
    );
    aggregate = try add(aggregate, active_post_stage_a_columns);
    const composition_domain_scratch = std.math.mul(
        u64,
        maximum_composition_domain_scratch,
        D5_COMPOSITION_DOMAIN_SCRATCH_CONCURRENT_OWNERS,
    ) catch return error.Degree5ProviderBatchExecutionOverflow;
    aggregate = try add(aggregate, composition_domain_scratch);
    aggregate = try add(aggregate, encoded_proofs);
    return .{
        .retained_stage_a_columns = retained_stage_a_columns,
        .retained_stage_a_non_column = retained_stage_a_non_column,
        .active_post_stage_a_columns = active_post_stage_a_columns,
        .composition_domain_scratch = composition_domain_scratch,
        .encoded_proofs = encoded_proofs,
        .aggregate_owner = aggregate,
    };
}

fn compositionDomainScratchBytes(trace_log_size: u32) !u64 {
    const evaluation_log_size = std.math.add(
        u32,
        trace_log_size,
        D5_QUOTIENT_EXPANSION_BITS,
    ) catch return error.Degree5ProviderBatchExecutionOverflow;
    if (evaluation_log_size >= 63)
        return error.Degree5ProviderBatchExecutionOverflow;
    const rows = @as(u64, 1) << @intCast(evaluation_log_size);
    return std.math.mul(
        u64,
        try std.math.mul(
            u64,
            D5_COMPOSITION_DOMAIN_SCRATCH_COLUMNS,
            rows,
        ),
        @sizeOf(u32),
    ) catch error.Degree5ProviderBatchExecutionOverflow;
}

fn stagedTotals(stages: anytype) !StagedTotalsV1 {
    var retained: u64 = 0;
    var transient: u64 = 0;
    inline for (stages) |stage| {
        const current_transient = try add(
            stage.source_bytes,
            stage.extended_evaluation_bytes,
        );
        transient = @max(transient, try add(retained, current_transient));
        retained = try add(retained, stage.minimum_resident_bytes);
    }
    return .{
        .retained = retained,
        .transient = transient,
        .peak = @max(retained, transient),
    };
}

fn add(left: u64, right: u64) !u64 {
    return std.math.add(u64, left, right) catch
        error.Degree5ProviderBatchExecutionOverflow;
}

fn resourceIdentity(value: *const ResourceEstimateV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/ethereum-candidate-d5-provider-resource/v1\x00");
    hashInt(&hash, u32, value.trace_log_size);
    hashInt(&hash, u32, value.fri_log_blowup_factor);
    hashInt(&hash, u32, value.quotient_expansion_bits);
    hashInt(&hash, u32, value.composition_log_split);
    hashInt(&hash, u32, value.composition_column_log_size);
    hashInt(&hash, u64, value.tree0_minimum_resident_bytes);
    hashInt(&hash, u64, value.tree1_minimum_resident_bytes);
    hashInt(&hash, u64, value.tree2_minimum_resident_bytes);
    hashInt(&hash, u64, value.composition_minimum_resident_bytes);
    hashInt(&hash, u64, value.retained_opening_lower_bound_bytes);
    hashInt(&hash, u64, value.commit_transient_lower_bound_bytes);
    hashInt(&hash, u64, value.staged_peak_lower_bound_bytes);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn divCeil(numerator: u32, denominator: u16) !u32 {
    if (denominator == 0) return error.InvalidDegree5ProviderBatchExecution;
    const adjusted = std.math.add(
        u32,
        numerator,
        @as(u32, denominator) - 1,
    ) catch return error.Degree5ProviderBatchExecutionOverflow;
    return adjusted / denominator;
}

comptime {
    if (FORMAT_VERSION != 3 or PROTOCOL_BOUND or TRANSCRIPT_MIXED or
        SERIALIZABLE or MAX_ENGINE_WORKERS != 32 or Q193_POW_BITS != 16 or
        Q193_QUERY_COUNT != 193 or Q193_FRI_LOG_BLOWUP_FACTOR != 1 or
        D5_QUOTIENT_EXPANSION_BITS != 2 or D5_COMPOSITION_LOG_SPLIT != 2 or
        D5_PREPROCESSED_COLUMNS != 2 or D5_MAIN_COLUMNS != 239 or
        D5_INTERACTION_COLUMNS != 12 or
        D5_ACCELERATED_INTERACTION_COLUMNS != 8 or
        D5_COMPOSITION_DOMAIN_SCRATCH_COLUMNS != 249 or
        D5_COMPOSITION_DOMAIN_SCRATCH_CONCURRENT_OWNERS != 2 or
        D5_COMPOSITION_COLUMNS != 16 or
        MAX_CANONICAL_PROOF_BYTES_PER_SHARD != 128 * 1024 * 1024)
    {
        @compileError("candidate D5 provider batch execution contract drifted");
    }
}
