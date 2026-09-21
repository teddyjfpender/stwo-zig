//! Typed non-production authority for a matched baseline/candidate corpus.
//!
//! The controller deliberately separates three transactions: both execution
//! captures, a request-independent legacy geometry audit, and only then the
//! ordered request publications.  This module owns the fixed 2^20/48-GiB
//! policy and the exact allocation-free PCS staged-residency arithmetic used
//! by that audit.  It never proves a leaf and cannot activate production.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const prover_engine = @import("stwo_prover_engine");

const base = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");

const GeometrySnapshot = frontend.prover_mod.EthereumSegmentGeometrySnapshot;
const omitted_policy = frontend.prover_mod.guest_precompile
    .ethereum_matched_ab_omitted_provider_policy_v1;
const residency = prover_engine.pcs.residency_estimate;

pub const schema =
    "stwo.ethereum.matched-ab-rematerialization-authority.v1";
pub const geometry_schema =
    "stwo.ethereum.matched-ab-legacy-geometry-audit.v1";
pub const status = "captured-audited-requests-minted-non-production";
pub const geometry_status = "all-legacy-leaves-staged-fit";
pub const geometry_v2_schema =
    "stwo.ethereum.matched-ab-omitted-provider-geometry-audit.v2";
pub const geometry_v2_status =
    "all-baseline-leaves-omitted-core-and-provider-resource-fit";
pub const production_active = false;
pub const proof_or_fresh_verification = false;
pub const default_routes_unchanged = true;

pub const segment_step_budget: usize = 1 << 20;
pub const target_provider_log_size: u32 = 22;
pub const host_byte_budget: u64 = 48 * 1024 * 1024 * 1024;
pub const log_blowup_factor: u32 = 1;
pub const legacy_composition_log_split: u32 = 1;
pub const legacy_composition_column_count: u64 = 8;
pub const legacy_provider_main_column_count: u64 = 445;
pub const retention_policy: residency.RetentionPolicy = .never;
pub const maximum_authority_bytes: usize = 16 * 1024 * 1024;
pub const provider_shard_log_size: u32 = omitted_policy.provider_shard_log_size;
pub const provider_shard_capacity: u32 =
    @as(u32, 1) << @intCast(provider_shard_log_size);

pub const OmittedCoreEstimateV1 = omitted_policy.OmittedCoreEstimateV1;
pub const ProviderResourceEstimateV1 = omitted_policy.ProviderResourceEstimateV1;
pub const MatchedExecutionAuthorityV1 =
    omitted_policy.MatchedExecutionAuthorityV1;

pub const Digest = [32]u8;

pub const Stage = struct {
    column_count: u64,
    source_cells: u64,
    extended_cells: u64,
    source_bytes: u64,
    retained_coefficient_bytes: u64,
    extended_evaluation_bytes: u64,
    minimum_resident_bytes: u64,

    fn fromEstimate(value: residency.Estimate) Stage {
        return .{
            .column_count = value.column_count,
            .source_cells = value.source_cells,
            .extended_cells = value.extended_cells,
            .source_bytes = value.source_bytes,
            .retained_coefficient_bytes = value.retained_coefficient_bytes,
            .extended_evaluation_bytes = value.extended_evaluation_bytes,
            .minimum_resident_bytes = value.minimum_resident_bytes,
        };
    }

    fn combine(left: Stage, right: Stage) !Stage {
        return .{
            .column_count = try add(left.column_count, right.column_count),
            .source_cells = try add(left.source_cells, right.source_cells),
            .extended_cells = try add(left.extended_cells, right.extended_cells),
            .source_bytes = try add(left.source_bytes, right.source_bytes),
            .retained_coefficient_bytes = try add(
                left.retained_coefficient_bytes,
                right.retained_coefficient_bytes,
            ),
            .extended_evaluation_bytes = try add(
                left.extended_evaluation_bytes,
                right.extended_evaluation_bytes,
            ),
            .minimum_resident_bytes = try add(
                left.minimum_resident_bytes,
                right.minimum_resident_bytes,
            ),
        };
    }

    fn commitTransient(self: Stage) !u64 {
        return add(self.source_bytes, self.extended_evaluation_bytes);
    }
};

pub const LegacyEstimate = struct {
    tree0: Stage,
    tree1: Stage,
    tree2: Stage,
    composition: Stage,
    composition_column_log_size: u32,
    retained_opening_lower_bound_bytes: u64,
    commit_transient_lower_bound_bytes: u64,
    staged_peak_lower_bound_bytes: u64,

    pub fn validate(self: LegacyEstimate) !void {
        if (self.tree0.column_count == 0 or self.tree1.column_count == 0 or
            self.tree2.column_count == 0 or
            self.composition.column_count != legacy_composition_column_count or
            self.composition_column_log_size == 0 or
            self.tree1.retained_coefficient_bytes != 0 or
            self.retained_opening_lower_bound_bytes == 0 or
            self.commit_transient_lower_bound_bytes == 0 or
            self.staged_peak_lower_bound_bytes != @max(
                self.retained_opening_lower_bound_bytes,
                self.commit_transient_lower_bound_bytes,
            ))
        {
            return error.InvalidMatchedAbLegacyEstimate;
        }
    }

    pub fn requireWithinMatchedBudget(self: LegacyEstimate) !void {
        try self.validate();
        if (self.staged_peak_lower_bound_bytes > host_byte_budget)
            return error.PcsResidentBudgetExceeded;
    }
};

pub const GeometryEntry = struct {
    segment_index: u32,
    source_segment: base.Identity,
    legacy_poseidon_log_size: u32,
    legacy_poseidon_n_rows: u32,
    tree0_log_sizes_sha256: []const u8,
    tree1_non_provider_log_sizes_sha256: []const u8,
    tree2_log_sizes_sha256: []const u8,
    estimate: LegacyEstimate,

    pub fn validate(self: GeometryEntry, expected_index: usize) !void {
        const index = std.math.cast(u32, expected_index) orelse
            return error.InvalidMatchedAbGeometryEntry;
        if (self.segment_index != index or
            self.legacy_poseidon_log_size > target_provider_log_size or
            self.legacy_poseidon_n_rows == 0 or
            @as(u64, self.legacy_poseidon_n_rows) >
                (@as(u64, 1) << @intCast(target_provider_log_size)))
        {
            return error.InvalidMatchedAbGeometryEntry;
        }
        try self.source_segment.validate(false);
        inline for (.{
            self.tree0_log_sizes_sha256,
            self.tree1_non_provider_log_sizes_sha256,
            self.tree2_log_sizes_sha256,
        }) |digest| _ = try base.parseSha256(digest);
        try self.estimate.requireWithinMatchedBudget();
    }
};

pub const GeometryAudit = struct {
    content_sha256: []const u8,
    schema: []const u8,
    status: []const u8,
    production_active: bool,
    proof_or_fresh_verification: bool,
    segment_step_budget: u64,
    host_byte_budget: u64,
    target_provider_log_size: u32,
    retention_policy: []const u8,
    baseline_materialization: base.Identity,
    baseline_source_request: base.TypedIdentity,
    candidate_capture: base.Identity,
    input: base.Identity,
    expected_output: base.Identity,
    producer_executable: base.Identity,
    entries: []const GeometryEntry,
    maximum_staged_peak_lower_bound_bytes: u64,

    pub fn validate(self: GeometryAudit) !void {
        if (!std.mem.eql(u8, self.schema, geometry_schema) or
            !std.mem.eql(u8, self.status, geometry_status) or
            self.production_active or self.proof_or_fresh_verification or
            self.segment_step_budget != segment_step_budget or
            self.host_byte_budget != host_byte_budget or
            self.target_provider_log_size != target_provider_log_size or
            !std.mem.eql(u8, self.retention_policy, "never") or
            self.entries.len < 2)
        {
            return error.InvalidMatchedAbGeometryAudit;
        }
        _ = try base.parseSha256(self.content_sha256);
        try self.baseline_materialization.validate(false);
        try self.baseline_source_request.validate();
        inline for (.{
            self.candidate_capture,
            self.input,
            self.expected_output,
            self.producer_executable,
        }) |file| try file.validate(false);
        var maximum: u64 = 0;
        for (self.entries, 0..) |entry, index| {
            try entry.validate(index);
            maximum = @max(
                maximum,
                entry.estimate.staged_peak_lower_bound_bytes,
            );
        }
        if (maximum != self.maximum_staged_peak_lower_bound_bytes or
            maximum > host_byte_budget)
        {
            return error.InvalidMatchedAbGeometryAudit;
        }
    }
};

pub fn encodeGeometryAudit(
    allocator: std.mem.Allocator,
    value: GeometryAudit,
) ![]u8 {
    try value.validate();
    const canonical = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(canonical);
    const unsigned = try removeContentSha256(allocator, canonical);
    defer allocator.free(unsigned);
    return evidence.seal(allocator, unsigned);
}

pub fn parseGeometryAudit(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(GeometryAudit) {
    if (bytes.len == 0 or bytes.len > maximum_authority_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(GeometryAudit, allocator, bytes, .{
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
    const unsigned = try removeContentSha256(allocator, canonical);
    defer allocator.free(unsigned);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(unsigned);
    hash.update("\n");
    const digest = hash.finalResult();
    if (!std.mem.eql(
        u8,
        &digest,
        &try base.parseSha256(parsed.value.content_sha256),
    )) return error.InvalidMatchedAbGeometryAuditSeal;
    return parsed;
}

/// Request-independent deterministic provider partition. This binds only the
/// exact call count and the fixed max-log20 shard shape; it is not a call-list
/// commitment, provider plan, closure, or proof claim. The real leaf producer
/// must later mint all four from the witness it actually proves.
pub const ProviderShardShapeV2 = struct {
    call_count: u32,
    shard_log_size: u32,
    shard_capacity: u32,
    shard_count: u32,
    tail_rows: u32,
    identity: Digest,

    pub fn canonical(call_count: u32) !ProviderShardShapeV2 {
        if (call_count == 0) return error.InvalidMatchedAbProviderShardShape;
        const shard_count_u64 = std.math.divCeil(
            u64,
            call_count,
            provider_shard_capacity,
        ) catch unreachable;
        const shard_count = std.math.cast(u32, shard_count_u64) orelse
            return error.InvalidMatchedAbProviderShardShape;
        const preceding = std.math.mul(
            u64,
            shard_count - 1,
            provider_shard_capacity,
        ) catch return error.InvalidMatchedAbProviderShardShape;
        const tail = std.math.sub(u64, call_count, preceding) catch
            return error.InvalidMatchedAbProviderShardShape;
        var result = ProviderShardShapeV2{
            .call_count = call_count,
            .shard_log_size = provider_shard_log_size,
            .shard_capacity = provider_shard_capacity,
            .shard_count = shard_count,
            .tail_rows = @intCast(tail),
            .identity = undefined,
        };
        result.identity = providerShardShapeIdentity(result);
        try result.validate();
        return result;
    }

    pub fn validate(self: ProviderShardShapeV2) !void {
        const expected = try canonicalUnchecked(self.call_count);
        if (!std.meta.eql(self, expected))
            return error.InvalidMatchedAbProviderShardShape;
    }
};

pub const GeometryEntryV2 = struct {
    segment_index: u32,
    source_segment: base.Identity,
    execution_inventory_identity: Digest,
    tree0_log_sizes_sha256: []const u8,
    tree1_non_provider_log_sizes_sha256: []const u8,
    tree2_log_sizes_sha256: []const u8,
    provider: ProviderShardShapeV2,
    omitted_core: OmittedCoreEstimateV1,

    pub fn validate(
        self: GeometryEntryV2,
        expected_index: usize,
        execution: MatchedExecutionAuthorityV1,
    ) !void {
        const index = std.math.cast(u32, expected_index) orelse
            return error.InvalidMatchedAbGeometryEntryV2;
        if (self.segment_index != index or
            isZeroDigest(self.execution_inventory_identity))
        {
            return error.InvalidMatchedAbGeometryEntryV2;
        }
        try self.source_segment.validate(false);
        inline for (.{
            self.tree0_log_sizes_sha256,
            self.tree1_non_provider_log_sizes_sha256,
            self.tree2_log_sizes_sha256,
        }) |digest| _ = try base.parseSha256(digest);
        try self.provider.validate();
        try self.omitted_core.validate();
        try self.omitted_core.requireWithinMatchedBudget();
        if (self.provider.call_count != self.omitted_core.legacy_provider_rows or
            self.omitted_core.legacy_provider_log_size !=
                expectedProviderLog(self.provider.call_count) or
            !std.meta.eql(
                self.omitted_core.execution_authority_identity,
                execution.identity,
            ))
        {
            return error.InvalidMatchedAbGeometryEntryV2;
        }
    }
};

/// Seal-last request-independent audit for the omitted-provider matched path.
/// It proves exact core/provider geometry and finite resource bounds only. The
/// three explicit deferrals prevent a later request publisher from relabeling
/// call-count geometry as call custody, a provider plan, or fresh closure.
pub const GeometryAuditV2 = struct {
    content_sha256: []const u8,
    schema: []const u8,
    status: []const u8,
    production_active: bool,
    proof_or_fresh_verification: bool,
    segment_step_budget: u64,
    host_byte_budget: u64,
    omitted_core_retention_policy: []const u8,
    provider_shard_log_size: u32,
    provider_retention_policy: []const u8,
    provider_call_commitment_deferred_to_leaf_producer: bool,
    provider_plan_deferred_to_leaf_producer: bool,
    fresh_closure_deferred_to_leaf_producer: bool,
    matched_execution: MatchedExecutionAuthorityV1,
    provider_resource: ProviderResourceEstimateV1,
    baseline_materialization: base.Identity,
    baseline_source_request: base.TypedIdentity,
    candidate_capture: base.Identity,
    input: base.Identity,
    expected_output: base.Identity,
    producer_executable: base.Identity,
    entries: []const GeometryEntryV2,
    total_provider_calls: u64,
    maximum_provider_shard_count: u32,
    maximum_omitted_core_staged_peak_lower_bound_bytes: u64,

    pub fn validate(self: GeometryAuditV2) !void {
        if (!std.mem.eql(u8, self.schema, geometry_v2_schema) or
            !std.mem.eql(u8, self.status, geometry_v2_status) or
            self.production_active or self.proof_or_fresh_verification or
            self.segment_step_budget != segment_step_budget or
            self.host_byte_budget != host_byte_budget or
            !std.mem.eql(u8, self.omitted_core_retention_policy, "never") or
            self.provider_shard_log_size != provider_shard_log_size or
            !std.mem.eql(u8, self.provider_retention_policy, "always") or
            !self.provider_call_commitment_deferred_to_leaf_producer or
            !self.provider_plan_deferred_to_leaf_producer or
            !self.fresh_closure_deferred_to_leaf_producer or
            self.entries.len < 2)
        {
            return error.InvalidMatchedAbGeometryAuditV2;
        }
        _ = try base.parseSha256(self.content_sha256);
        try self.matched_execution.validate();
        try self.provider_resource.validate();
        try self.baseline_materialization.validate(false);
        try self.baseline_source_request.validate();
        inline for (.{
            self.candidate_capture,
            self.input,
            self.expected_output,
            self.producer_executable,
        }) |file| try file.validate(false);

        var total_calls: u64 = 0;
        var maximum_shards: u32 = 0;
        var maximum_core: u64 = 0;
        for (self.entries, 0..) |entry, index| {
            try entry.validate(index, self.matched_execution);
            total_calls = std.math.add(
                u64,
                total_calls,
                entry.provider.call_count,
            ) catch return error.InvalidMatchedAbGeometryAuditV2;
            maximum_shards = @max(maximum_shards, entry.provider.shard_count);
            maximum_core = @max(
                maximum_core,
                entry.omitted_core.staged_peak_lower_bound_bytes,
            );
        }
        if (total_calls != self.total_provider_calls or
            maximum_shards != self.maximum_provider_shard_count or
            maximum_core !=
                self.maximum_omitted_core_staged_peak_lower_bound_bytes or
            maximum_core > host_byte_budget)
        {
            return error.InvalidMatchedAbGeometryAuditV2;
        }
    }
};

pub fn encodeGeometryAuditV2(
    allocator: std.mem.Allocator,
    value: GeometryAuditV2,
) ![]u8 {
    try value.validate();
    const canonical = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(canonical);
    const unsigned = try removeContentSha256(allocator, canonical);
    defer allocator.free(unsigned);
    return evidence.seal(allocator, unsigned);
}

pub fn parseGeometryAuditV2(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(GeometryAuditV2) {
    if (bytes.len == 0 or bytes.len > maximum_authority_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(GeometryAuditV2, allocator, bytes, .{
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
    const unsigned = try removeContentSha256(allocator, canonical);
    defer allocator.free(unsigned);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(unsigned);
    hash.update("\n");
    const digest = hash.finalResult();
    if (!std.mem.eql(
        u8,
        &digest,
        &try base.parseSha256(parsed.value.content_sha256),
    )) return error.InvalidMatchedAbGeometryAuditSealV2;
    return parsed;
}

pub const ArmCapture = struct {
    arm: []const u8,
    executable: base.Identity,
    input: base.Identity,
    expected_output: base.Identity,
    terminal_result: base.Identity,
    execution_journal: base.Identity,
    segment_step_budget: u64,
    segment_count: u32,
    total_cycles: u64,
    output_closed: bool,
    adjacency_closed: bool,
    journal_closed: bool,

    pub fn validate(self: ArmCapture, expected_arm: []const u8) !void {
        if (!std.mem.eql(u8, self.arm, expected_arm) or
            self.segment_step_budget != segment_step_budget or
            self.segment_count < 2 or self.total_cycles == 0 or
            !self.output_closed or !self.adjacency_closed or
            !self.journal_closed)
        {
            return error.InvalidMatchedAbArmCapture;
        }
        inline for (.{
            self.executable,
            self.input,
            self.expected_output,
            self.terminal_result,
            self.execution_journal,
        }) |file| try file.validate(false);
    }
};

pub const RequestSet = struct {
    arm: []const u8,
    manifest: base.Identity,
    request_count: u32,
    segment_step_budget: u64,
    source_capture_result: base.Identity,

    pub fn validate(
        self: RequestSet,
        expected_arm: []const u8,
        expected_count: u32,
        expected_capture: base.Identity,
    ) !void {
        if (!std.mem.eql(u8, self.arm, expected_arm) or
            self.request_count != expected_count or
            self.segment_step_budget != segment_step_budget or
            !identityEql(self.source_capture_result, expected_capture))
        {
            return error.InvalidMatchedAbRequestSet;
        }
        try self.manifest.validate(false);
        try self.source_capture_result.validate(false);
    }
};

pub const Result = struct {
    content_sha256: []const u8,
    schema: []const u8,
    status: []const u8,
    production_active: bool,
    proof_or_fresh_verification: bool,
    default_routes_unchanged: bool,
    segment_step_budget: u64,
    host_byte_budget: u64,
    target_provider_log_size: u32,
    baseline: ArmCapture,
    candidate: ArmCapture,
    geometry_audit: base.Identity,
    geometry_audit_content_sha256: []const u8,
    baseline_requests: RequestSet,
    candidate_requests: RequestSet,

    pub fn validate(self: Result) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            self.production_active or self.proof_or_fresh_verification or
            !self.default_routes_unchanged or
            self.segment_step_budget != segment_step_budget or
            self.host_byte_budget != host_byte_budget or
            self.target_provider_log_size != target_provider_log_size)
        {
            return error.InvalidMatchedAbRematerializationAuthority;
        }
        _ = try base.parseSha256(self.content_sha256);
        _ = try base.parseSha256(self.geometry_audit_content_sha256);
        try self.baseline.validate("baseline");
        try self.candidate.validate("candidate");
        try self.geometry_audit.validate(false);
        if (!identityEql(self.baseline.input, self.candidate.input) or
            !identityEql(
                self.baseline.expected_output,
                self.candidate.expected_output,
            ))
        {
            return error.MatchedAbSemanticInputOutputMismatch;
        }
        try self.baseline_requests.validate(
            "baseline",
            self.baseline.segment_count,
            self.baseline.terminal_result,
        );
        try self.candidate_requests.validate(
            "candidate",
            self.candidate.segment_count,
            self.candidate.terminal_result,
        );
    }
};

pub fn estimateLegacy(
    snapshot: *const GeometrySnapshot,
) !LegacyEstimate {
    if (snapshot.legacy_poseidon.main_column_count !=
        legacy_provider_main_column_count)
    {
        return error.InvalidMatchedAbLegacyGeometry;
    }
    const tree0 = Stage.fromEstimate(try residency.estimate(
        snapshot.tree0_log_sizes,
        log_blowup_factor,
        retention_policy,
    ));
    const tree1_non_provider = Stage.fromEstimate(try residency.estimate(
        snapshot.tree1_non_candidate_log_sizes,
        log_blowup_factor,
        retention_policy,
    ));
    const tree1_provider = Stage.fromEstimate(try residency.estimateUniform(
        legacy_provider_main_column_count,
        snapshot.legacy_poseidon.log_size,
        log_blowup_factor,
        retention_policy,
    ));
    const tree1 = try Stage.combine(tree1_non_provider, tree1_provider);
    const tree2 = Stage.fromEstimate(try residency.estimate(
        snapshot.tree2_log_sizes,
        log_blowup_factor,
        retention_policy,
    ));
    const composition_log_size = @max(
        snapshot.legacy_poseidon.log_size,
        @max(
            maximumLogSize(snapshot.tree0_log_sizes),
            @max(
                maximumLogSize(snapshot.tree1_non_candidate_log_sizes),
                maximumLogSize(snapshot.tree2_log_sizes),
            ),
        ),
    );
    const composition = Stage.fromEstimate(try residency.estimateUniform(
        legacy_composition_column_count,
        composition_log_size,
        log_blowup_factor,
        retention_policy,
    ));

    var retained_prior: u64 = 0;
    var transient_peak: u64 = 0;
    inline for (.{ tree0, tree1, tree2, composition }) |stage| {
        transient_peak = @max(
            transient_peak,
            try add(retained_prior, try stage.commitTransient()),
        );
        retained_prior = try add(
            retained_prior,
            stage.minimum_resident_bytes,
        );
    }
    const result = LegacyEstimate{
        .tree0 = tree0,
        .tree1 = tree1,
        .tree2 = tree2,
        .composition = composition,
        .composition_column_log_size = composition_log_size,
        .retained_opening_lower_bound_bytes = retained_prior,
        .commit_transient_lower_bound_bytes = transient_peak,
        .staged_peak_lower_bound_bytes = @max(retained_prior, transient_peak),
    };
    try result.validate();
    return result;
}

pub fn logSizesIdentity(log_sizes: []const u32) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.ethereum.matched-ab-log-sizes.v1\x00");
    hashInt(&hash, u64, @intCast(log_sizes.len));
    for (log_sizes) |log_size| hashInt(&hash, u32, log_size);
    return hash.finalResult();
}

fn maximumLogSize(values: []const u32) u32 {
    var result: u32 = 0;
    for (values) |value| result = @max(result, value);
    return result;
}

fn canonicalUnchecked(call_count: u32) !ProviderShardShapeV2 {
    if (call_count == 0) return error.InvalidMatchedAbProviderShardShape;
    const shard_count_u64 = std.math.divCeil(
        u64,
        call_count,
        provider_shard_capacity,
    ) catch unreachable;
    const shard_count = std.math.cast(u32, shard_count_u64) orelse
        return error.InvalidMatchedAbProviderShardShape;
    const preceding = std.math.mul(
        u64,
        shard_count - 1,
        provider_shard_capacity,
    ) catch return error.InvalidMatchedAbProviderShardShape;
    const tail = std.math.sub(u64, call_count, preceding) catch
        return error.InvalidMatchedAbProviderShardShape;
    var result = ProviderShardShapeV2{
        .call_count = call_count,
        .shard_log_size = provider_shard_log_size,
        .shard_capacity = provider_shard_capacity,
        .shard_count = shard_count,
        .tail_rows = @intCast(tail),
        .identity = undefined,
    };
    result.identity = providerShardShapeIdentity(result);
    return result;
}

fn expectedProviderLog(rows: u32) u32 {
    return @max(
        @as(u32, 4),
        if (rows <= 1) 1 else std.math.log2_int_ceil(u32, rows),
    );
}

fn providerShardShapeIdentity(value: ProviderShardShapeV2) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.ethereum.matched-ab-provider-shard-shape.v2\x00");
    hashInt(&hash, u32, value.call_count);
    hashInt(&hash, u32, value.shard_log_size);
    hashInt(&hash, u32, value.shard_capacity);
    hashInt(&hash, u32, value.shard_count);
    hashInt(&hash, u32, value.tail_rows);
    return hash.finalResult();
}

fn isZeroDigest(value: Digest) bool {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    return aggregate == 0;
}

fn removeContentSha256(
    allocator: std.mem.Allocator,
    canonical: []const u8,
) ![]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, canonical, prefix))
        return error.InvalidMatchedAbGeometryAuditSeal;
    const digest_end = prefix.len + 64;
    if (digest_end + 1 >= canonical.len or canonical[digest_end] != '"' or
        canonical[digest_end + 1] != ',')
    {
        return error.InvalidMatchedAbGeometryAuditSeal;
    }
    return std.fmt.allocPrint(
        allocator,
        "{{{s}",
        .{canonical[digest_end + 2 ..]},
    );
}

fn identityEql(left: base.Identity, right: base.Identity) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.sha256, right.sha256);
}

fn add(left: u64, right: u64) !u64 {
    return std.math.add(u64, left, right) catch
        error.MatchedAbResidencyEstimateOverflow;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    if (production_active or proof_or_fresh_verification or
        segment_step_budget != 1_048_576 or
        target_provider_log_size != 22 or
        provider_shard_log_size != 20 or provider_shard_capacity != 1_048_576 or
        host_byte_budget != 51_539_607_552 or
        legacy_composition_log_split != 1 or
        legacy_composition_column_count != 8 or
        legacy_provider_main_column_count != 445)
    {
        @compileError("matched A/B rematerialization policy drifted");
    }
}

test "legacy staged estimator rejects log24 and admits target log22" {
    const tree0 = [_]u32{16};
    const tree1_non_provider = [_]u32{15};
    const tree2 = [_]u32{14};

    // Pin the exact real-segment-0 Tree0/non-provider/Tree2 aggregate math
    // independently of the large retained arrays.
    const real_tree0 = Stage{
        .column_count = 256,
        .source_cells = 104_067_036,
        .extended_cells = 208_134_072,
        .source_bytes = 416_268_144,
        .retained_coefficient_bytes = 0,
        .extended_evaluation_bytes = 832_536_288,
        .minimum_resident_bytes = 832_536_288,
    };
    const real_non_provider = Stage{
        .column_count = 9_374,
        .source_cells = 444_837_218,
        .extended_cells = 889_674_436,
        .source_bytes = 1_779_348_872,
        .retained_coefficient_bytes = 0,
        .extended_evaluation_bytes = 3_558_697_744,
        .minimum_resident_bytes = 3_558_697_744,
    };
    const log24_provider = Stage.fromEstimate(try residency.estimateUniform(
        legacy_provider_main_column_count,
        24,
        log_blowup_factor,
        retention_policy,
    ));
    const log24_tree1 = try Stage.combine(real_non_provider, log24_provider);
    try std.testing.expectEqual(
        @as(u64, 95_760_916_344),
        try add(real_tree0.minimum_resident_bytes, try log24_tree1.commitTransient()),
    );

    const log22_provider = Stage.fromEstimate(try residency.estimateUniform(
        legacy_provider_main_column_count,
        target_provider_log_size,
        log_blowup_factor,
        retention_policy,
    ));
    const log22_tree1 = try Stage.combine(real_non_provider, log22_provider);
    const log22_peak = try add(
        real_tree0.minimum_resident_bytes,
        try log22_tree1.commitTransient(),
    );
    try std.testing.expectEqual(@as(u64, 28_568_166_264), log22_peak);
    try std.testing.expect(log22_peak < host_byte_budget);

    // Keep the compact synthetic arrays live in this test so their hash wire
    // is also covered without manufacturing the retained 9k-column vectors.
    try std.testing.expect(!std.mem.eql(
        u8,
        &logSizesIdentity(&tree0),
        &logSizesIdentity(&tree1_non_provider),
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &logSizesIdentity(&tree1_non_provider),
        &logSizesIdentity(&tree2),
    ));
}

test "legacy staged budget is fail closed at one byte over matched cap" {
    const nonempty = Stage{
        .column_count = 1,
        .source_cells = 1,
        .extended_cells = 2,
        .source_bytes = 4,
        .retained_coefficient_bytes = 0,
        .extended_evaluation_bytes = 8,
        .minimum_resident_bytes = 8,
    };
    const estimate = LegacyEstimate{
        .tree0 = nonempty,
        .tree1 = nonempty,
        .tree2 = nonempty,
        .composition = .{
            .column_count = legacy_composition_column_count,
            .source_cells = 8,
            .extended_cells = 16,
            .source_bytes = 32,
            .retained_coefficient_bytes = 0,
            .extended_evaluation_bytes = 64,
            .minimum_resident_bytes = 64,
        },
        .composition_column_log_size = 1,
        .retained_opening_lower_bound_bytes = host_byte_budget + 1,
        .commit_transient_lower_bound_bytes = 1,
        .staged_peak_lower_bound_bytes = host_byte_budget + 1,
    };
    try estimate.validate();
    try std.testing.expectError(
        error.PcsResidentBudgetExceeded,
        estimate.requireWithinMatchedBudget(),
    );
}

test "omitted provider shard shape pins log20 partition and mutation" {
    const one = try ProviderShardShapeV2.canonical(1);
    try std.testing.expectEqual(@as(u32, 1), one.shard_count);
    try std.testing.expectEqual(@as(u32, 1), one.tail_rows);

    const exact = try ProviderShardShapeV2.canonical(provider_shard_capacity);
    try std.testing.expectEqual(@as(u32, 1), exact.shard_count);
    try std.testing.expectEqual(provider_shard_capacity, exact.tail_rows);

    const spill = try ProviderShardShapeV2.canonical(
        provider_shard_capacity + 1,
    );
    try std.testing.expectEqual(@as(u32, 2), spill.shard_count);
    try std.testing.expectEqual(@as(u32, 1), spill.tail_rows);
    var mutated = spill;
    mutated.tail_rows = 2;
    try std.testing.expectError(
        error.InvalidMatchedAbProviderShardShape,
        mutated.validate(),
    );
}

test "geometry audit seal round trips and rejects mutation" {
    const entries = [_]GeometryEntry{
        geometryEntryFixture(0, "/private/tmp/source-0.stw"),
        geometryEntryFixture(1, "/private/tmp/source-1.stw"),
    };
    const zero_sha = "0000000000000000000000000000000000000000000000000000000000000000";
    const value = GeometryAudit{
        .content_sha256 = zero_sha,
        .schema = geometry_schema,
        .status = geometry_status,
        .production_active = false,
        .proof_or_fresh_verification = false,
        .segment_step_budget = segment_step_budget,
        .host_byte_budget = host_byte_budget,
        .target_provider_log_size = target_provider_log_size,
        .retention_policy = "never",
        .baseline_materialization = identityFixture(
            "/private/tmp/materialization.json",
        ),
        .baseline_source_request = .{
            .bytes = 1,
            .path = "/private/tmp/source-request.json",
            .schema = base.recursive_source_schema,
            .sha256 = zero_sha,
        },
        .candidate_capture = identityFixture(
            "/private/tmp/candidate-capture.json",
        ),
        .input = identityFixture("/private/tmp/input.bin"),
        .expected_output = identityFixture("/private/tmp/output.bin"),
        .producer_executable = identityFixture("/private/tmp/producer"),
        .entries = &entries,
        .maximum_staged_peak_lower_bound_bytes = 64,
    };
    const encoded = try encodeGeometryAudit(std.testing.allocator, value);
    defer std.testing.allocator.free(encoded);
    var parsed = try parseGeometryAudit(std.testing.allocator, encoded);
    parsed.deinit();
    const mutated = try std.testing.allocator.dupe(u8, encoded);
    defer std.testing.allocator.free(mutated);
    mutated[mutated.len - 3] ^= 1;
    if (parseGeometryAudit(std.testing.allocator, mutated)) |accepted| {
        var owned = accepted;
        owned.deinit();
        return error.MatchedAbGeometryMutationAccepted;
    } else |_| {}
}

fn geometryEntryFixture(index: u32, path: []const u8) GeometryEntry {
    const zero_sha = "0000000000000000000000000000000000000000000000000000000000000000";
    const stage = Stage{
        .column_count = 1,
        .source_cells = 1,
        .extended_cells = 2,
        .source_bytes = 4,
        .retained_coefficient_bytes = 0,
        .extended_evaluation_bytes = 8,
        .minimum_resident_bytes = 8,
    };
    return .{
        .segment_index = index,
        .source_segment = identityFixture(path),
        .legacy_poseidon_log_size = target_provider_log_size,
        .legacy_poseidon_n_rows = 1,
        .tree0_log_sizes_sha256 = zero_sha,
        .tree1_non_provider_log_sizes_sha256 = zero_sha,
        .tree2_log_sizes_sha256 = zero_sha,
        .estimate = .{
            .tree0 = stage,
            .tree1 = stage,
            .tree2 = stage,
            .composition = .{
                .column_count = legacy_composition_column_count,
                .source_cells = 8,
                .extended_cells = 16,
                .source_bytes = 32,
                .retained_coefficient_bytes = 0,
                .extended_evaluation_bytes = 64,
                .minimum_resident_bytes = 64,
            },
            .composition_column_log_size = 1,
            .retained_opening_lower_bound_bytes = 32,
            .commit_transient_lower_bound_bytes = 64,
            .staged_peak_lower_bound_bytes = 64,
        },
    };
}

fn identityFixture(path: []const u8) base.Identity {
    return .{
        .bytes = 1,
        .path = path,
        .sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
    };
}
