//! Internal fri profile frontier authority shard; use fri_profile_frontier.zig publicly.

pub const std = @import("std");
pub const fixed_profile = @import("fixed_profile.zig");
pub const protocol = @import("protocol.zig");

pub const MAX_CANDIDATES: usize = 16;
pub const MAX_OBSERVATIONS: usize = 32;
pub const MAX_COMPARISONS: usize = MAX_OBSERVATIONS;
pub const MAX_OBSERVED_TREES: usize = 8;
pub const MAX_OBSERVED_FRI_LAYERS: usize = fixed_profile.MAX_FRI_ROUNDS;
pub const FORMAT_VERSION: u16 = 1;
pub const MEASUREMENT_FORMAT_VERSION: u16 = 1;
pub const COMPARISON_FORMAT_VERSION: u16 = 1;
pub const DIGEST_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-profile-frontier/v1\x00";
pub const OBSERVATION_DIGEST_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-observation/v1\x00";
pub const OBSERVATION_SET_DIGEST_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-observation-set/v1\x00";
pub const COMPARISON_DIGEST_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-comparison/v1\x00";
pub const COMPARISON_SET_DIGEST_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-comparison-set/v1\x00";

pub const PROTOCOL_ACTIVATION = false;
pub const FROZEN_V1_MUTATED = false;
pub const HEAP_ALLOCATIONS_PER_OBSERVATION = 0;
pub const HEAP_ALLOCATIONS_PER_INGEST = 0;
pub const HEAP_ALLOCATIONS_PER_COMPARISON = 0;

pub const Error = fixed_profile.Error || error{
    ArithmeticOverflow,
    CoverageMismatch,
    DuplicateObservation,
    EmptyReceiptIdentity,
    InvalidConfiguredSecurity,
    InvalidComparison,
    InvalidFrontier,
    InvalidObservation,
    InvalidPathDimensions,
    InvalidVerifierWork,
    MissingFrozenV1Baseline,
    NoCandidateMeasurements,
    TooManyObservations,
};

pub const Candidate = struct {
    log_blowup_factor: u32,
    n_queries: u32,
    pow_bits: u32,
    configured_security_bits: u32,
    domain_expansion: u32,
    fri_rounds: u32,
    raw_trace_query_paths: u64,
    fri_authentication_digests_upper_bound: u64,
    fri_fold_values_upper_bound: u64,
    terminal_domain_values: u64,

    pub fn validate(
        self: Candidate,
        column_log_degree: u32,
        configured_security_floor: u32,
    ) Error!void {
        const expected = try derive(
            column_log_degree,
            self.log_blowup_factor,
            self.pow_bits,
            configured_security_floor,
        );
        if (!std.meta.eql(self, expected)) return error.InvalidFrontier;
    }

    /// Strict Pareto dominance over the modeled prover-domain and recursive-
    /// verifier work dimensions. Proof size and measured time intentionally do
    /// not appear: those require an actual proof capture.
    pub fn dominates(self: Candidate, other: Candidate) bool {
        const no_worse = self.domain_expansion <= other.domain_expansion and
            self.raw_trace_query_paths <= other.raw_trace_query_paths and
            self.fri_authentication_digests_upper_bound <=
                other.fri_authentication_digests_upper_bound and
            self.fri_fold_values_upper_bound <=
                other.fri_fold_values_upper_bound and
            self.terminal_domain_values <= other.terminal_domain_values;
        const better = self.domain_expansion < other.domain_expansion or
            self.raw_trace_query_paths < other.raw_trace_query_paths or
            self.fri_authentication_digests_upper_bound <
                other.fri_authentication_digests_upper_bound or
            self.fri_fold_values_upper_bound <
                other.fri_fold_values_upper_bound or
            self.terminal_domain_values < other.terminal_domain_values;
        return no_worse and better;
    }
};

pub const Frontier = struct {
    candidates: [MAX_CANDIDATES]Candidate,
    count: u8,
    column_log_degree: u32,
    configured_security_floor: u32,
    pow_bits: u32,

    pub fn active(self: *const Frontier) []const Candidate {
        return self.candidates[0..self.count];
    }

    pub fn validate(self: *const Frontier) Error!void {
        if (self.count == 0 or self.count > self.candidates.len)
            return error.InvalidFrontier;
        var prior_blowup: u32 = 0;
        for (self.active(), 0..) |candidate, index| {
            try candidate.validate(
                self.column_log_degree,
                self.configured_security_floor,
            );
            if (candidate.pow_bits != self.pow_bits or
                (index != 0 and candidate.log_blowup_factor <= prior_blowup))
            {
                return error.InvalidFrontier;
            }
            prior_blowup = candidate.log_blowup_factor;
            for (self.active(), 0..) |other, other_index| {
                if (index != other_index and other.dominates(candidate))
                    return error.InvalidFrontier;
            }
        }
    }

    pub fn identityDigest(self: *const Frontier) Error![32]u8 {
        try self.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DIGEST_DOMAIN);
        hashInt(&hash, u16, FORMAT_VERSION);
        hashInt(&hash, u32, self.column_log_degree);
        hashInt(&hash, u32, self.configured_security_floor);
        hashInt(&hash, u32, self.pow_bits);
        hashInt(&hash, u8, self.count);
        for (self.active()) |candidate| {
            hashInt(&hash, u32, candidate.log_blowup_factor);
            hashInt(&hash, u32, candidate.n_queries);
            hashInt(&hash, u32, candidate.pow_bits);
            hashInt(&hash, u32, candidate.configured_security_bits);
            hashInt(&hash, u32, candidate.domain_expansion);
            hashInt(&hash, u32, candidate.fri_rounds);
            hashInt(&hash, u64, candidate.raw_trace_query_paths);
            hashInt(
                &hash,
                u64,
                candidate.fri_authentication_digests_upper_bound,
            );
            hashInt(&hash, u64, candidate.fri_fold_values_upper_bound);
            hashInt(&hash, u64, candidate.terminal_domain_values);
        }
        return hash.finalResult();
    }
};

/// Builds the nondominated subset in increasing blowup order. Construction is
/// fixed-capacity and allocation-free; the tiny O(k²) filter is cold-path
/// design analysis over at most sixteen candidates, never proof work.
pub fn build(
    column_log_degree: u32,
    minimum_log_blowup: u32,
    maximum_log_blowup: u32,
    pow_bits: u32,
    configured_security_floor: u32,
) Error!Frontier {
    if (minimum_log_blowup == 0 or
        maximum_log_blowup < minimum_log_blowup or
        maximum_log_blowup - minimum_log_blowup + 1 > MAX_CANDIDATES)
    {
        return error.InvalidFrontier;
    }
    var all: [MAX_CANDIDATES]Candidate = undefined;
    const candidate_count: usize = maximum_log_blowup - minimum_log_blowup + 1;
    for (all[0..candidate_count], minimum_log_blowup..) |*candidate, blowup| {
        candidate.* = try derive(
            column_log_degree,
            @intCast(blowup),
            pow_bits,
            configured_security_floor,
        );
    }

    var result = Frontier{
        .candidates = undefined,
        .count = 0,
        .column_log_degree = column_log_degree,
        .configured_security_floor = configured_security_floor,
        .pow_bits = pow_bits,
    };
    for (all[0..candidate_count], 0..) |candidate, index| {
        var dominated = false;
        for (all[0..candidate_count], 0..) |other, other_index| {
            if (index != other_index and other.dominates(candidate)) {
                dominated = true;
                break;
            }
        }
        if (!dominated) {
            result.candidates[result.count] = candidate;
            result.count += 1;
        }
    }
    try result.validate();
    return result;
}

pub fn v1Comparison(column_log_degree: u32) Error!Frontier {
    return build(
        column_log_degree,
        1,
        6,
        protocol.PCS_POW_BITS,
        protocol.PCS_CONFIG.securityBits(),
    );
}

/// Receipt origin is part of every comparison key. Leaf graph-node work and
/// binary outer AIR-constraint work are intentionally never summed or ranked
/// against one another.
pub const ObservationSourceV1 = enum(u8) {
    native_leaf = 1,
    binary_outer = 2,
};

/// Explicit unit for the exact verifier-work counter supplied by the receipt
/// adapter. Keeping the unit in the identity prevents a graph-node count from
/// being silently compared with an AIR-constraint count.
pub const VerifierWorkUnitV1 = enum(u8) {
    compiled_graph_nodes = 1,
    air_constraints = 2,
};

pub const MeasuredProfileV1 = struct {
    column_log_degree: u32,
    configured_security_floor: u32,
    candidate: Candidate,

    pub fn initV1Candidate(
        column_log_degree: u32,
        log_blowup_factor: u32,
    ) Error!MeasuredProfileV1 {
        return init(
            column_log_degree,
            log_blowup_factor,
            protocol.PCS_POW_BITS,
            protocol.PCS_CONFIG.securityBits(),
        );
    }

    pub fn init(
        column_log_degree: u32,
        log_blowup_factor: u32,
        pow_bits: u32,
        configured_security_floor: u32,
    ) Error!MeasuredProfileV1 {
        return .{
            .column_log_degree = column_log_degree,
            .configured_security_floor = configured_security_floor,
            .candidate = try derive(
                column_log_degree,
                log_blowup_factor,
                pow_bits,
                configured_security_floor,
            ),
        };
    }

    pub fn validate(self: MeasuredProfileV1) Error!void {
        try self.candidate.validate(
            self.column_log_degree,
            self.configured_security_floor,
        );
    }

    pub fn isFrozenV1(self: MeasuredProfileV1) bool {
        return self.configured_security_floor ==
            protocol.PCS_CONFIG.securityBits() and
            self.candidate.log_blowup_factor ==
                protocol.PCS_CONFIG.fri_config.log_blowup_factor and
            self.candidate.n_queries ==
                protocol.PCS_CONFIG.fri_config.n_queries and
            self.candidate.pow_bits == protocol.PCS_POW_BITS;
    }

    pub fn sameFamily(
        self: MeasuredProfileV1,
        other: MeasuredProfileV1,
    ) bool {
        return self.column_log_degree == other.column_log_degree and
            self.configured_security_floor ==
                other.configured_security_floor and
            self.candidate.pow_bits == other.candidate.pow_bits;
    }
};

/// Fixed-capacity exact dimensions for all commitment-tree query paths in one
/// accepted proof capture. `path_count` and `authentication_digest_count` are
/// redundant on purpose and are checked against the per-tree depths.
pub const TreePathDimensionsV1 = struct {
    tree_count: u8,
    path_count: u64,
    authentication_digest_count: u64,
    path_depths: [MAX_OBSERVED_TREES]u32,

    pub fn init(
        query_count: u32,
        path_depths: []const u32,
    ) Error!TreePathDimensionsV1 {
        if (query_count == 0 or path_depths.len == 0 or
            path_depths.len > MAX_OBSERVED_TREES)
        {
            return error.InvalidPathDimensions;
        }
        var stored = [_]u32{0} ** MAX_OBSERVED_TREES;
        var depth_sum: u64 = 0;
        for (path_depths, stored[0..path_depths.len]) |depth, *destination| {
            if (depth == 0) return error.InvalidPathDimensions;
            destination.* = depth;
            depth_sum = try add(depth_sum, depth);
        }
        return .{
            .tree_count = @intCast(path_depths.len),
            .path_count = try mul(path_depths.len, query_count),
            .authentication_digest_count = try mul(depth_sum, query_count),
            .path_depths = stored,
        };
    }

    pub fn validate(
        self: TreePathDimensionsV1,
        query_count: u32,
    ) Error!void {
        if (self.tree_count == 0 or self.tree_count > self.path_depths.len or
            query_count == 0)
        {
            return error.InvalidPathDimensions;
        }
        var depth_sum: u64 = 0;
        for (self.path_depths, 0..) |depth, index| {
            if (index < self.tree_count) {
                if (depth == 0) return error.InvalidPathDimensions;
                depth_sum = try add(depth_sum, depth);
            } else if (depth != 0) return error.InvalidPathDimensions;
        }
        if (self.path_count != try mul(self.tree_count, query_count) or
            self.authentication_digest_count !=
                try mul(depth_sum, query_count))
        {
            return error.InvalidPathDimensions;
        }
    }
};

pub const FriLayerDimensionsV1 = struct {
    fold_width: u32 = 0,
    authentication_path_depth: u32 = 0,

    pub fn validate(self: FriLayerDimensionsV1) Error!void {
        if (self.fold_width < 2 or !std.math.isPowerOfTwo(self.fold_width))
            return error.InvalidPathDimensions;
    }
};

/// Exact active FRI layer dimensions from the accepted capture. The terminal
/// value count is measured rather than inferred, while the authentication and
/// fold totals are re-derived from the layer table and query count.
pub const FriPathDimensionsV1 = struct {
    layer_count: u8,
    authentication_digest_count: u64,
    fold_value_count: u64,
    terminal_value_count: u64,
    layers: [MAX_OBSERVED_FRI_LAYERS]FriLayerDimensionsV1,

    pub fn init(
        query_count: u32,
        layers: []const FriLayerDimensionsV1,
        terminal_value_count: u64,
    ) Error!FriPathDimensionsV1 {
        if (query_count == 0 or layers.len == 0 or
            layers.len > MAX_OBSERVED_FRI_LAYERS or terminal_value_count == 0)
        {
            return error.InvalidPathDimensions;
        }
        var stored =
            [_]FriLayerDimensionsV1{.{}} ** MAX_OBSERVED_FRI_LAYERS;
        var path_depth_sum: u64 = 0;
        var fold_width_sum: u64 = 0;
        for (layers, stored[0..layers.len]) |layer, *destination| {
            try layer.validate();
            destination.* = layer;
            path_depth_sum = try add(
                path_depth_sum,
                layer.authentication_path_depth,
            );
            fold_width_sum = try add(fold_width_sum, layer.fold_width);
        }
        return .{
            .layer_count = @intCast(layers.len),
            .authentication_digest_count = try mul(
                path_depth_sum,
                query_count,
            ),
            .fold_value_count = try mul(fold_width_sum, query_count),
            .terminal_value_count = terminal_value_count,
            .layers = stored,
        };
    }

    pub fn validate(
        self: FriPathDimensionsV1,
        query_count: u32,
    ) Error!void {
        if (self.layer_count == 0 or self.layer_count > self.layers.len or
            query_count == 0 or self.terminal_value_count == 0)
        {
            return error.InvalidPathDimensions;
        }
        var path_depth_sum: u64 = 0;
        var fold_width_sum: u64 = 0;
        for (self.layers, 0..) |layer, index| {
            if (index < self.layer_count) {
                try layer.validate();
                path_depth_sum = try add(
                    path_depth_sum,
                    layer.authentication_path_depth,
                );
                fold_width_sum = try add(fold_width_sum, layer.fold_width);
            } else if (!std.meta.eql(layer, FriLayerDimensionsV1{})) {
                return error.InvalidPathDimensions;
            }
        }
        if (self.authentication_digest_count !=
            try mul(path_depth_sum, query_count) or
            self.fold_value_count != try mul(fold_width_sum, query_count))
        {
            return error.InvalidPathDimensions;
        }
    }
};

pub const VerifierWorkV1 = struct {
    unit: VerifierWorkUnitV1,
    exact_units: u64,
    native_verify_ns: u64,

    pub fn validate(self: VerifierWorkV1) Error!void {
        if (self.exact_units == 0 or self.native_verify_ns == 0)
            return error.InvalidVerifierWork;
    }
};

/// Dependency-safe adapter schema populated at the leaf or binary proof root.
/// It contains values only: no proof, capture, allocator, timer, or receipt
/// pointer crosses into this frontend cost model.
pub const ObservationInputV1 = struct {
    source: ObservationSourceV1,
    profile: MeasuredProfileV1,
    canonical_proof_bytes: u64,
    fixed_wire_bytes: ?u64,
    tree_paths: TreePathDimensionsV1,
    fri_paths: FriPathDimensionsV1,
    verifier_work: VerifierWorkV1,
    poseidon2_provider_calls: u64,
    receipt_sha256: [32]u8,
};

pub fn hashMeasuredProfile(hash: anytype, profile: MeasuredProfileV1) void {
    hashInt(hash, u32, profile.column_log_degree);
    hashInt(hash, u32, profile.configured_security_floor);
    hashCandidate(hash, profile.candidate);
}

pub fn hashCandidate(hash: anytype, candidate: Candidate) void {
    hashInt(hash, u32, candidate.log_blowup_factor);
    hashInt(hash, u32, candidate.n_queries);
    hashInt(hash, u32, candidate.pow_bits);
    hashInt(hash, u32, candidate.configured_security_bits);
    hashInt(hash, u32, candidate.domain_expansion);
    hashInt(hash, u32, candidate.fri_rounds);
    hashInt(hash, u64, candidate.raw_trace_query_paths);
    hashInt(hash, u64, candidate.fri_authentication_digests_upper_bound);
    hashInt(hash, u64, candidate.fri_fold_values_upper_bound);
    hashInt(hash, u64, candidate.terminal_domain_values);
}

pub fn hashTreePaths(hash: anytype, paths: TreePathDimensionsV1) void {
    hashInt(hash, u8, paths.tree_count);
    hashInt(hash, u64, paths.path_count);
    hashInt(hash, u64, paths.authentication_digest_count);
    for (paths.path_depths) |depth| hashInt(hash, u32, depth);
}

pub fn hashFriPaths(hash: anytype, paths: FriPathDimensionsV1) void {
    hashInt(hash, u8, paths.layer_count);
    hashInt(hash, u64, paths.authentication_digest_count);
    hashInt(hash, u64, paths.fold_value_count);
    hashInt(hash, u64, paths.terminal_value_count);
    for (paths.layers) |layer| {
        hashInt(hash, u32, layer.fold_width);
        hashInt(hash, u32, layer.authentication_path_depth);
    }
}

pub fn hashOptionalU64(hash: anytype, value: ?u64) void {
    if (value) |present| {
        hashInt(hash, u8, 1);
        hashInt(hash, u64, present);
    } else {
        hashInt(hash, u8, 0);
    }
}

pub fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

pub fn derive(
    column_log_degree: u32,
    log_blowup_factor: u32,
    pow_bits: u32,
    configured_security_floor: u32,
) Error!Candidate {
    if (configured_security_floor <= pow_bits)
        return error.InvalidConfiguredSecurity;
    const query_bits = configured_security_floor - pow_bits;
    const n_queries = try ceilDiv(query_bits, log_blowup_factor);
    var config = protocol.PCS_CONFIG.fri_config;
    config.log_blowup_factor = log_blowup_factor;
    config.n_queries = n_queries;
    const schedule = try fixed_profile.FriSchedule.init(column_log_degree, config);

    var path_depth_sum: u64 = 0;
    var fold_value_sum: u64 = 0;
    for (schedule.active()) |round| {
        path_depth_sum = try add(path_depth_sum, round.authentication_path_depth);
        fold_value_sum = try add(fold_value_sum, round.fold_width);
    }
    const query_count: u64 = n_queries;
    const configured_bits = try add32(
        pow_bits,
        try mul32(log_blowup_factor, n_queries),
    );
    return .{
        .log_blowup_factor = log_blowup_factor,
        .n_queries = n_queries,
        .pow_bits = pow_bits,
        .configured_security_bits = configured_bits,
        .domain_expansion = try powerOfTwo(log_blowup_factor),
        .fri_rounds = schedule.count,
        .raw_trace_query_paths = try mul(
            protocol.COMMITMENT_TREE_COUNT,
            query_count,
        ),
        .fri_authentication_digests_upper_bound = try mul(
            path_depth_sum,
            query_count,
        ),
        .fri_fold_values_upper_bound = try mul(
            fold_value_sum,
            query_count,
        ),
        .terminal_domain_values = try powerOfTwo64(
            schedule.terminal_evaluation_log,
        ),
    };
}

pub fn ceilDiv(numerator: u32, denominator: u32) Error!u32 {
    if (denominator == 0) return error.InvalidConfiguredSecurity;
    return @intCast((@as(u64, numerator) + denominator - 1) / denominator);
}

pub fn add(lhs: u64, rhs: anytype) Error!u64 {
    return std.math.add(u64, lhs, @intCast(rhs)) catch
        error.ArithmeticOverflow;
}

pub fn mul(lhs: anytype, rhs: u64) Error!u64 {
    return std.math.mul(u64, @intCast(lhs), rhs) catch
        error.ArithmeticOverflow;
}

pub fn add32(lhs: u32, rhs: u32) Error!u32 {
    return std.math.add(u32, lhs, rhs) catch error.ArithmeticOverflow;
}

pub fn mul32(lhs: u32, rhs: u32) Error!u32 {
    return std.math.mul(u32, lhs, rhs) catch error.ArithmeticOverflow;
}

pub fn powerOfTwo(exponent: u32) Error!u32 {
    if (exponent >= @bitSizeOf(u32)) return error.ArithmeticOverflow;
    return @as(u32, 1) << @intCast(exponent);
}

pub fn powerOfTwo64(exponent: u32) Error!u64 {
    if (exponent >= @bitSizeOf(u64)) return error.ArithmeticOverflow;
    return @as(u64, 1) << @intCast(exponent);
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
