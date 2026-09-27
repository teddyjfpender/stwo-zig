//! Internal fri profile frontier authority shard; use fri_profile_frontier.zig publicly.

const dependency_0 = @import("fri_profile_frontier_fri_path_dimensions_v1.zig");

const COMPARISON_DIGEST_DOMAIN = dependency_0.COMPARISON_DIGEST_DOMAIN;
const COMPARISON_FORMAT_VERSION = dependency_0.COMPARISON_FORMAT_VERSION;
const COMPARISON_SET_DIGEST_DOMAIN = dependency_0.COMPARISON_SET_DIGEST_DOMAIN;
const Error = dependency_0.Error;
const FROZEN_V1_MUTATED = dependency_0.FROZEN_V1_MUTATED;
const FriPathDimensionsV1 = dependency_0.FriPathDimensionsV1;
const HEAP_ALLOCATIONS_PER_COMPARISON = dependency_0.HEAP_ALLOCATIONS_PER_COMPARISON;
const HEAP_ALLOCATIONS_PER_INGEST = dependency_0.HEAP_ALLOCATIONS_PER_INGEST;
const HEAP_ALLOCATIONS_PER_OBSERVATION = dependency_0.HEAP_ALLOCATIONS_PER_OBSERVATION;
const MAX_COMPARISONS = dependency_0.MAX_COMPARISONS;
const MAX_OBSERVATIONS = dependency_0.MAX_OBSERVATIONS;
const MEASUREMENT_FORMAT_VERSION = dependency_0.MEASUREMENT_FORMAT_VERSION;
const MeasuredProfileV1 = dependency_0.MeasuredProfileV1;
const OBSERVATION_DIGEST_DOMAIN = dependency_0.OBSERVATION_DIGEST_DOMAIN;
const OBSERVATION_SET_DIGEST_DOMAIN = dependency_0.OBSERVATION_SET_DIGEST_DOMAIN;
const ObservationInputV1 = dependency_0.ObservationInputV1;
const ObservationSourceV1 = dependency_0.ObservationSourceV1;
const PROTOCOL_ACTIVATION = dependency_0.PROTOCOL_ACTIVATION;
const TreePathDimensionsV1 = dependency_0.TreePathDimensionsV1;
const VerifierWorkUnitV1 = dependency_0.VerifierWorkUnitV1;
const VerifierWorkV1 = dependency_0.VerifierWorkV1;
const allZero = dependency_0.allZero;
const hashFriPaths = dependency_0.hashFriPaths;
const hashInt = dependency_0.hashInt;
const hashMeasuredProfile = dependency_0.hashMeasuredProfile;
const hashOptionalU64 = dependency_0.hashOptionalU64;
const hashTreePaths = dependency_0.hashTreePaths;
const std = dependency_0.std;

pub const ObservationV1 = struct {
    format_version: u16 = MEASUREMENT_FORMAT_VERSION,
    protocol_activation: bool = PROTOCOL_ACTIVATION,
    source: ObservationSourceV1,
    profile: MeasuredProfileV1,
    canonical_proof_bytes: u64,
    fixed_wire_bytes: ?u64,
    tree_paths: TreePathDimensionsV1,
    fri_paths: FriPathDimensionsV1,
    verifier_work: VerifierWorkV1,
    poseidon2_provider_calls: u64,
    receipt_sha256: [32]u8,
    observation_id: [32]u8,

    pub fn seal(input: ObservationInputV1) Error!ObservationV1 {
        var result = ObservationV1{
            .source = input.source,
            .profile = input.profile,
            .canonical_proof_bytes = input.canonical_proof_bytes,
            .fixed_wire_bytes = input.fixed_wire_bytes,
            .tree_paths = input.tree_paths,
            .fri_paths = input.fri_paths,
            .verifier_work = input.verifier_work,
            .poseidon2_provider_calls = input.poseidon2_provider_calls,
            .receipt_sha256 = input.receipt_sha256,
            .observation_id = undefined,
        };
        try result.validatePayload();
        result.observation_id = observationIdentity(&result);
        return result;
    }

    pub fn validate(self: *const ObservationV1) Error!void {
        try self.validatePayload();
        if (!std.mem.eql(
            u8,
            &self.observation_id,
            &observationIdentity(self),
        )) return error.InvalidObservation;
    }

    fn validatePayload(self: *const ObservationV1) Error!void {
        if (self.format_version != MEASUREMENT_FORMAT_VERSION or
            self.protocol_activation != PROTOCOL_ACTIVATION or
            self.canonical_proof_bytes == 0 or
            self.poseidon2_provider_calls == 0)
        {
            return error.InvalidObservation;
        }
        if (self.fixed_wire_bytes) |bytes|
            if (bytes == 0) return error.InvalidObservation;
        if (allZero(&self.receipt_sha256))
            return error.EmptyReceiptIdentity;
        try self.profile.validate();
        const query_count = self.profile.candidate.n_queries;
        try self.tree_paths.validate(query_count);
        try self.fri_paths.validate(query_count);
        if (self.tree_paths.path_count !=
            self.profile.candidate.raw_trace_query_paths or
            self.fri_paths.layer_count != self.profile.candidate.fri_rounds or
            self.fri_paths.authentication_digest_count !=
                self.profile.candidate
                    .fri_authentication_digests_upper_bound or
            self.fri_paths.fold_value_count !=
                self.profile.candidate.fri_fold_values_upper_bound or
            self.fri_paths.terminal_value_count !=
                self.profile.candidate.terminal_domain_values)
        {
            return error.InvalidObservation;
        }
        try self.verifier_work.validate();
        const expected_work_unit: VerifierWorkUnitV1 = switch (self.source) {
            .native_leaf => .compiled_graph_nodes,
            .binary_outer => .air_constraints,
        };
        if (self.verifier_work.unit != expected_work_unit)
            return error.InvalidVerifierWork;
    }
};

pub const ObservationSetV1 = struct {
    observations: [MAX_OBSERVATIONS]ObservationV1,
    count: u8 = 0,

    pub fn init() ObservationSetV1 {
        var result: ObservationSetV1 = undefined;
        @memset(std.mem.asBytes(&result.observations), 0);
        result.count = 0;
        return result;
    }

    pub fn active(self: *const ObservationSetV1) []const ObservationV1 {
        return self.observations[0..self.count];
    }

    /// Sorted insertion makes the set and every emitted comparison invariant
    /// to process completion order. All checks occur before shifting, so a
    /// rejected receipt leaves the set byte-for-byte unchanged.
    pub fn ingest(
        self: *ObservationSetV1,
        observation: ObservationV1,
    ) Error!void {
        try observation.validate();
        if (self.count >= self.observations.len)
            return error.TooManyObservations;
        var insertion_index: usize = self.count;
        for (self.active(), 0..) |existing, index| {
            if (sameObservationKey(existing, observation))
                return error.DuplicateObservation;
            if (observationLessThan(observation, existing)) {
                insertion_index = index;
                break;
            }
        }

        var cursor: usize = self.count;
        while (cursor > insertion_index) : (cursor -= 1)
            self.observations[cursor] = self.observations[cursor - 1];
        self.observations[insertion_index] = observation;
        self.count += 1;
    }

    pub fn validate(self: *const ObservationSetV1) Error!void {
        if (self.count == 0 or self.count > self.observations.len)
            return error.InvalidObservation;
        for (self.active(), 0..) |observation, index| {
            try observation.validate();
            if (index != 0 and
                !observationLessThan(self.active()[index - 1], observation))
            {
                return error.InvalidObservation;
            }
        }
    }

    pub fn identityDigest(self: *const ObservationSetV1) Error![32]u8 {
        try self.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(OBSERVATION_SET_DIGEST_DOMAIN);
        hashInt(&hash, u16, MEASUREMENT_FORMAT_VERSION);
        hashInt(&hash, u8, self.count);
        for (self.active()) |observation| hash.update(&observation.observation_id);
        return hash.finalResult();
    }

    pub fn comparisons(self: *const ObservationSetV1) Error!ComparisonSetV1 {
        try self.validate();
        var result = ComparisonSetV1.init();
        for (self.active()) |candidate| {
            if (candidate.profile.isFrozenV1()) continue;
            const baseline = self.findBaseline(candidate) orelse
                return error.MissingFrozenV1Baseline;
            result.comparisons[result.count] = try ComparisonV1.init(
                baseline,
                &candidate,
            );
            result.count += 1;
        }
        if (result.count == 0) return error.NoCandidateMeasurements;
        try result.validateAgainst(self);
        return result;
    }

    fn findBaseline(
        self: *const ObservationSetV1,
        candidate: ObservationV1,
    ) ?*const ObservationV1 {
        for (self.active()) |*observation| {
            if (observation.source == candidate.source and
                observation.profile.isFrozenV1() and
                observation.profile.sameFamily(candidate.profile))
            {
                return observation;
            }
        }
        return null;
    }
};

pub const DeltaDirectionV1 = enum(u8) {
    equal = 0,
    decrease = 1,
    increase = 2,
};

/// Exact integer comparison. It deliberately does not compute percentages or
/// a scalar score; consumers can display the pair without rounding or implied
/// weighting.
pub const ExactDeltaV1 = struct {
    baseline: u64,
    candidate: u64,
    direction: DeltaDirectionV1,
    magnitude: u64,

    pub fn init(baseline: u64, candidate: u64) ExactDeltaV1 {
        if (candidate < baseline) return .{
            .baseline = baseline,
            .candidate = candidate,
            .direction = .decrease,
            .magnitude = baseline - candidate,
        };
        if (candidate > baseline) return .{
            .baseline = baseline,
            .candidate = candidate,
            .direction = .increase,
            .magnitude = candidate - baseline,
        };
        return .{
            .baseline = baseline,
            .candidate = candidate,
            .direction = .equal,
            .magnitude = 0,
        };
    }

    pub fn validate(self: ExactDeltaV1) Error!void {
        if (!std.meta.eql(self, init(self.baseline, self.candidate)))
            return error.InvalidComparison;
    }
};

pub const ParetoRelationV1 = enum(u8) {
    equal = 0,
    candidate_dominates = 1,
    frozen_v1_dominates = 2,
    tradeoff = 3,
};

pub const ComparisonV1 = struct {
    format_version: u16 = COMPARISON_FORMAT_VERSION,
    protocol_activation: bool = PROTOCOL_ACTIVATION,
    source: ObservationSourceV1,
    work_unit: VerifierWorkUnitV1,
    baseline_profile: MeasuredProfileV1,
    candidate_profile: MeasuredProfileV1,
    baseline_observation_id: [32]u8,
    candidate_observation_id: [32]u8,

    query_count: ExactDeltaV1,
    canonical_proof_bytes: ExactDeltaV1,
    fixed_wire_bytes: ?ExactDeltaV1,
    tree_path_count: ExactDeltaV1,
    trace_authentication_digests: ExactDeltaV1,
    fri_authentication_digests: ExactDeltaV1,
    fri_fold_values: ExactDeltaV1,
    terminal_values: ExactDeltaV1,
    verifier_work_units: ExactDeltaV1,
    native_verify_ns: ExactDeltaV1,
    poseidon2_provider_calls: ExactDeltaV1,

    pareto_relation: ParetoRelationV1,
    comparison_id: [32]u8,

    pub fn init(
        baseline: *const ObservationV1,
        candidate: *const ObservationV1,
    ) Error!ComparisonV1 {
        try baseline.validate();
        try candidate.validate();
        if (baseline.source != candidate.source or
            !baseline.profile.isFrozenV1() or
            !baseline.profile.sameFamily(candidate.profile) or
            candidate.profile.isFrozenV1() or
            candidate.profile.candidate.log_blowup_factor <=
                baseline.profile.candidate.log_blowup_factor or
            baseline.verifier_work.unit != candidate.verifier_work.unit)
        {
            return error.InvalidComparison;
        }
        const fixed_wire_bytes: ?ExactDeltaV1 = if (baseline.fixed_wire_bytes != null and
            candidate.fixed_wire_bytes != null) ExactDeltaV1.init(
            baseline.fixed_wire_bytes.?,
            candidate.fixed_wire_bytes.?,
        ) else if (baseline.fixed_wire_bytes == null and
            candidate.fixed_wire_bytes == null)
            null
        else
            return error.CoverageMismatch;

        var result = ComparisonV1{
            .source = baseline.source,
            .work_unit = baseline.verifier_work.unit,
            .baseline_profile = baseline.profile,
            .candidate_profile = candidate.profile,
            .baseline_observation_id = baseline.observation_id,
            .candidate_observation_id = candidate.observation_id,
            .query_count = ExactDeltaV1.init(
                baseline.profile.candidate.n_queries,
                candidate.profile.candidate.n_queries,
            ),
            .canonical_proof_bytes = ExactDeltaV1.init(
                baseline.canonical_proof_bytes,
                candidate.canonical_proof_bytes,
            ),
            .fixed_wire_bytes = fixed_wire_bytes,
            .tree_path_count = ExactDeltaV1.init(
                baseline.tree_paths.path_count,
                candidate.tree_paths.path_count,
            ),
            .trace_authentication_digests = ExactDeltaV1.init(
                baseline.tree_paths.authentication_digest_count,
                candidate.tree_paths.authentication_digest_count,
            ),
            .fri_authentication_digests = ExactDeltaV1.init(
                baseline.fri_paths.authentication_digest_count,
                candidate.fri_paths.authentication_digest_count,
            ),
            .fri_fold_values = ExactDeltaV1.init(
                baseline.fri_paths.fold_value_count,
                candidate.fri_paths.fold_value_count,
            ),
            .terminal_values = ExactDeltaV1.init(
                baseline.fri_paths.terminal_value_count,
                candidate.fri_paths.terminal_value_count,
            ),
            .verifier_work_units = ExactDeltaV1.init(
                baseline.verifier_work.exact_units,
                candidate.verifier_work.exact_units,
            ),
            .native_verify_ns = ExactDeltaV1.init(
                baseline.verifier_work.native_verify_ns,
                candidate.verifier_work.native_verify_ns,
            ),
            .poseidon2_provider_calls = ExactDeltaV1.init(
                baseline.poseidon2_provider_calls,
                candidate.poseidon2_provider_calls,
            ),
            .pareto_relation = undefined,
            .comparison_id = undefined,
        };
        result.pareto_relation = measuredParetoRelation(&result);
        result.comparison_id = comparisonIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const ComparisonV1) Error!void {
        if (self.format_version != COMPARISON_FORMAT_VERSION or
            self.protocol_activation != PROTOCOL_ACTIVATION or
            !self.baseline_profile.isFrozenV1() or
            self.candidate_profile.isFrozenV1() or
            !self.baseline_profile.sameFamily(self.candidate_profile) or
            self.candidate_profile.candidate.log_blowup_factor <=
                self.baseline_profile.candidate.log_blowup_factor or
            allZero(&self.baseline_observation_id) or
            allZero(&self.candidate_observation_id))
        {
            return error.InvalidComparison;
        }
        try self.baseline_profile.validate();
        try self.candidate_profile.validate();
        inline for (comparisonDeltas(self)) |delta| try delta.validate();
        if (self.fixed_wire_bytes) |delta| try delta.validate();
        const expected_work_unit: VerifierWorkUnitV1 = switch (self.source) {
            .native_leaf => .compiled_graph_nodes,
            .binary_outer => .air_constraints,
        };
        if (self.work_unit != expected_work_unit or
            self.query_count.baseline !=
                self.baseline_profile.candidate.n_queries or
            self.query_count.candidate !=
                self.candidate_profile.candidate.n_queries or
            self.pareto_relation != measuredParetoRelation(self) or
            !std.mem.eql(
                u8,
                &self.comparison_id,
                &comparisonIdentity(self),
            ))
        {
            return error.InvalidComparison;
        }
    }
};

pub const ComparisonSetV1 = struct {
    comparisons: [MAX_COMPARISONS]ComparisonV1,
    count: u8 = 0,

    pub fn init() ComparisonSetV1 {
        var result: ComparisonSetV1 = undefined;
        @memset(std.mem.asBytes(&result.comparisons), 0);
        result.count = 0;
        return result;
    }

    pub fn active(self: *const ComparisonSetV1) []const ComparisonV1 {
        return self.comparisons[0..self.count];
    }

    pub fn validate(self: *const ComparisonSetV1) Error!void {
        if (self.count == 0 or self.count > self.comparisons.len)
            return error.InvalidComparison;
        for (self.active(), 0..) |comparison, index| {
            try comparison.validate();
            if (index != 0 and !comparisonLessThan(
                self.active()[index - 1],
                comparison,
            )) return error.InvalidComparison;
        }
    }

    /// Replays every comparison from its two sealed observations and proves
    /// exact coverage of every non-V1 observation. This is the consumer-side
    /// authority check; `validate()` alone establishes only self-consistency.
    pub fn validateAgainst(
        self: *const ComparisonSetV1,
        observations: *const ObservationSetV1,
    ) Error!void {
        try self.validate();
        try observations.validate();
        var expected_comparison_count: usize = 0;
        for (observations.active()) |candidate| {
            if (candidate.profile.isFrozenV1()) continue;
            expected_comparison_count += 1;
            const baseline = observations.findBaseline(candidate) orelse
                return error.MissingFrozenV1Baseline;
            const expected = try ComparisonV1.init(baseline, &candidate);
            var found = false;
            for (self.active()) |comparison| {
                if (std.mem.eql(
                    u8,
                    &comparison.candidate_observation_id,
                    &candidate.observation_id,
                )) {
                    if (found or !std.meta.eql(comparison, expected))
                        return error.InvalidComparison;
                    found = true;
                }
            }
            if (!found) return error.InvalidComparison;
        }
        if (self.count != expected_comparison_count)
            return error.InvalidComparison;
    }

    pub fn identityDigest(self: *const ComparisonSetV1) Error![32]u8 {
        try self.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(COMPARISON_SET_DIGEST_DOMAIN);
        hashInt(&hash, u16, COMPARISON_FORMAT_VERSION);
        hashInt(&hash, u8, self.count);
        for (self.active()) |comparison| hash.update(&comparison.comparison_id);
        return hash.finalResult();
    }
};

pub const OBSERVATION_STATIC_BYTES: usize = @sizeOf(ObservationV1);
pub const OBSERVATION_SET_STATIC_BYTES: usize = @sizeOf(ObservationSetV1);
pub const COMPARISON_STATIC_BYTES: usize = @sizeOf(ComparisonV1);
pub const COMPARISON_SET_STATIC_BYTES: usize = @sizeOf(ComparisonSetV1);

pub fn sameObservationKey(left: ObservationV1, right: ObservationV1) bool {
    return left.source == right.source and
        std.meta.eql(left.profile, right.profile);
}

pub fn observationLessThan(left: ObservationV1, right: ObservationV1) bool {
    const left_source = @intFromEnum(left.source);
    const right_source = @intFromEnum(right.source);
    if (left_source != right_source) return left_source < right_source;
    return profileLessThan(left.profile, right.profile);
}

pub fn comparisonLessThan(left: ComparisonV1, right: ComparisonV1) bool {
    const left_source = @intFromEnum(left.source);
    const right_source = @intFromEnum(right.source);
    if (left_source != right_source) return left_source < right_source;
    return profileLessThan(left.candidate_profile, right.candidate_profile);
}

pub fn profileLessThan(left: MeasuredProfileV1, right: MeasuredProfileV1) bool {
    if (left.column_log_degree != right.column_log_degree)
        return left.column_log_degree < right.column_log_degree;
    if (left.candidate.log_blowup_factor !=
        right.candidate.log_blowup_factor)
    {
        return left.candidate.log_blowup_factor <
            right.candidate.log_blowup_factor;
    }
    if (left.candidate.pow_bits != right.candidate.pow_bits)
        return left.candidate.pow_bits < right.candidate.pow_bits;
    return left.configured_security_floor < right.configured_security_floor;
}

pub fn comparisonDeltas(comparison: *const ComparisonV1) [10]ExactDeltaV1 {
    return .{
        comparison.query_count,
        comparison.canonical_proof_bytes,
        comparison.tree_path_count,
        comparison.trace_authentication_digests,
        comparison.fri_authentication_digests,
        comparison.fri_fold_values,
        comparison.terminal_values,
        comparison.verifier_work_units,
        comparison.native_verify_ns,
        comparison.poseidon2_provider_calls,
    };
}

pub fn measuredParetoRelation(comparison: *const ComparisonV1) ParetoRelationV1 {
    var saw_decrease = false;
    var saw_increase = false;
    for (comparisonDeltas(comparison)) |delta| switch (delta.direction) {
        .equal => {},
        .decrease => saw_decrease = true,
        .increase => saw_increase = true,
    };
    if (comparison.fixed_wire_bytes) |delta| switch (delta.direction) {
        .equal => {},
        .decrease => saw_decrease = true,
        .increase => saw_increase = true,
    };
    if (saw_decrease and saw_increase) return .tradeoff;
    if (saw_decrease) return .candidate_dominates;
    if (saw_increase) return .frozen_v1_dominates;
    return .equal;
}

pub fn observationIdentity(observation: *const ObservationV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(OBSERVATION_DIGEST_DOMAIN);
    hashInt(&hash, u16, observation.format_version);
    hashInt(&hash, u8, @intFromBool(observation.protocol_activation));
    hashInt(&hash, u8, @intFromEnum(observation.source));
    hashMeasuredProfile(&hash, observation.profile);
    hashInt(&hash, u64, observation.canonical_proof_bytes);
    hashOptionalU64(&hash, observation.fixed_wire_bytes);
    hashTreePaths(&hash, observation.tree_paths);
    hashFriPaths(&hash, observation.fri_paths);
    hashInt(&hash, u8, @intFromEnum(observation.verifier_work.unit));
    hashInt(&hash, u64, observation.verifier_work.exact_units);
    hashInt(&hash, u64, observation.verifier_work.native_verify_ns);
    hashInt(&hash, u64, observation.poseidon2_provider_calls);
    hash.update(&observation.receipt_sha256);
    return hash.finalResult();
}

pub fn comparisonIdentity(comparison: *const ComparisonV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(COMPARISON_DIGEST_DOMAIN);
    hashInt(&hash, u16, comparison.format_version);
    hashInt(&hash, u8, @intFromBool(comparison.protocol_activation));
    hashInt(&hash, u8, @intFromEnum(comparison.source));
    hashInt(&hash, u8, @intFromEnum(comparison.work_unit));
    hashMeasuredProfile(&hash, comparison.baseline_profile);
    hashMeasuredProfile(&hash, comparison.candidate_profile);
    hash.update(&comparison.baseline_observation_id);
    hash.update(&comparison.candidate_observation_id);
    for (comparisonDeltas(comparison)) |delta| hashDelta(&hash, delta);
    if (comparison.fixed_wire_bytes) |delta| {
        hashInt(&hash, u8, 1);
        hashDelta(&hash, delta);
    } else {
        hashInt(&hash, u8, 0);
    }
    hashInt(&hash, u8, @intFromEnum(comparison.pareto_relation));
    return hash.finalResult();
}

pub fn hashDelta(hash: anytype, delta: ExactDeltaV1) void {
    hashInt(hash, u64, delta.baseline);
    hashInt(hash, u64, delta.candidate);
    hashInt(hash, u8, @intFromEnum(delta.direction));
    hashInt(hash, u64, delta.magnitude);
}

pub fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer, .error_union => @compileError(
            "FRI measurement ABI contains dynamic state",
        ),
        .optional => |optional| assertPointerFree(optional.child),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}

comptime {
    if (PROTOCOL_ACTIVATION or FROZEN_V1_MUTATED or
        HEAP_ALLOCATIONS_PER_OBSERVATION != 0 or
        HEAP_ALLOCATIONS_PER_INGEST != 0 or
        HEAP_ALLOCATIONS_PER_COMPARISON != 0 or
        MAX_OBSERVATIONS > std.math.maxInt(u8) or
        MAX_COMPARISONS > std.math.maxInt(u8))
    {
        @compileError("FRI measurement non-activation contract drifted");
    }
    assertPointerFree(ObservationInputV1);
    assertPointerFree(ObservationV1);
    assertPointerFree(ComparisonV1);
}
