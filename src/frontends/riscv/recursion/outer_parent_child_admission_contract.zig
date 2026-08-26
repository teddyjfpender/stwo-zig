//! Internal outer parent child admission authority shard; use outer_parent_child_admission.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const CirclePointQM31 = stwo_core.circle.CirclePointQM31;

pub const channel = @import("poseidon2_channel.zig");
pub const engine = @import("engine.zig");
pub const fixed_profile = @import("fixed_profile.zig");
pub const fixed_wire = @import("fixed_wire.zig");
pub const pair_node = @import("pair_node.zig");
pub const protocol = @import("protocol.zig");
pub const sample_point_layout = @import("sample_point_layout.zig");
pub const roster = @import("air/universal_roster.zig");

pub const ProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(engine.Hasher);

pub const FORMAT_VERSION: u32 = 1;
pub const WIRE_MAGIC: u32 = 0x4f50_4331; // "OPC1"
pub const OUTER_FORMAT_VERSION: u32 = 1;
pub const OUTER_TRANSCRIPT_DOMAIN: u32 = 0x5246_4131; // "RFA1"
pub const QUERY_COUNT: usize = 3;
pub const INTERACTION_POW_BITS: u32 = 0;
pub const PCS_POW_BITS: u32 = 0;
pub const LOG_BLOWUP_FACTOR: u32 = 1;
pub const LOG_LAST_LAYER_DEGREE_BOUND: u32 = 0;
pub const FOLD_STEP: u32 = 1;
pub const TREE_COUNT: usize = fixed_profile.TREE_COUNT;
pub const CLAIMED_SUM_COUNT: usize = roster.COMPONENT_COUNT;
pub const MAX_FRI_ROUNDS: usize = fixed_profile.MAX_DOMAIN_LOG;
pub const MAX_DOMAIN_LOG: u32 = fixed_profile.MAX_DOMAIN_LOG;

pub const PROFILE_ID_DOMAIN: u32 = 0x4f50_5246; // "OPRF"
pub const COLUMN_LAYOUT_ID_DOMAIN: u32 = 0x4f43_4f4c; // "OCOL"
pub const SAMPLE_LAYOUT_ID_DOMAIN: u32 = 0x4f53_4d50; // "OSMP"
pub const CAPTURE_ID_DOMAIN: u32 = 0x4f43_4150; // "OCAP"
pub const CLAIMS_ID_DOMAIN: u32 = 0x4f43_4c4d; // "OCLM"
pub const RECEIPT_ID_DOMAIN: u32 = 0x4f52_4350; // "ORCP"

pub const OUTER_FRI_CONFIG: stwo_core.fri.FriConfig = .{
    .log_blowup_factor = LOG_BLOWUP_FACTOR,
    .log_last_layer_degree_bound = LOG_LAST_LAYER_DEGREE_BOUND,
    .n_queries = QUERY_COUNT,
    .fold_step = FOLD_STEP,
};

pub const OUTER_PCS_CONFIG: stwo_core.pcs.PcsConfig = .{
    .pow_bits = PCS_POW_BITS,
    .fri_config = OUTER_FRI_CONFIG,
};

/// The present integration proves a verifier subsystem, not yet the complete
/// universal recursive statement.  The scope is explicit and seal-bound so
/// upgrading it cannot be a caller-side boolean reinterpretation.
pub const ProofScope = enum(u8) {
    verifier_subsystem = 1,
    complete_parent = 2,
};

pub const RECURSIVE_PARENT_PRODUCTION = false;

pub const Error = fixed_wire.Error || fixed_profile.Error ||
    sample_point_layout.Error || error{
    ArithmeticOverflow,
    CaptureShapeMismatch,
    DimensionMismatch,
    EmptyAuthority,
    InvalidColumnLayout,
    InvalidComponentLogSize,
    InvalidFriSchedule,
    InvalidProofScope,
    InvalidQuerySchedule,
    InvalidReceipt,
    NonCanonicalCapture,
    PairIdentityMismatch,
    ParentProofIncomplete,
    ProfileSealMismatch,
    TranscriptMismatch,
    WireHeaderMismatch,
};

pub const FriRoundV1 = struct {
    evaluation_log: u32,
    fold_step: u32,
    fold_width: u32,
    authentication_path_depth: u32,
};

/// Fold-one schedule with enough capacity for every admitted M31 domain.  It
/// is intentionally separate from leaf V1's 16-slot fold-four schedule.
pub const FriScheduleV1 = struct {
    count: u32,
    rounds: [MAX_FRI_ROUNDS]FriRoundV1,
    terminal_evaluation_log: u32,
    last_layer_coefficient_count: u32,

    pub fn init(column_log_degree: u32) Error!FriScheduleV1 {
        if (column_log_degree == 0 or column_log_degree > MAX_DOMAIN_LOG)
            return error.InvalidFriSchedule;
        const terminal = std.math.add(
            u32,
            LOG_LAST_LAYER_DEGREE_BOUND,
            LOG_BLOWUP_FACTOR,
        ) catch return error.ArithmeticOverflow;
        var result = FriScheduleV1{
            .count = 0,
            .rounds = [_]FriRoundV1{std.mem.zeroes(FriRoundV1)} **
                MAX_FRI_ROUNDS,
            .terminal_evaluation_log = terminal,
            .last_layer_coefficient_count = 1,
        };
        var degree = column_log_degree;
        while (degree > LOG_LAST_LAYER_DEGREE_BOUND) : (degree -= 1) {
            if (result.count == result.rounds.len)
                return error.InvalidFriSchedule;
            const evaluation_log = std.math.add(
                u32,
                degree,
                LOG_BLOWUP_FACTOR,
            ) catch return error.ArithmeticOverflow;
            result.rounds[result.count] = .{
                .evaluation_log = evaluation_log,
                .fold_step = FOLD_STEP,
                .fold_width = 2,
                .authentication_path_depth = evaluation_log - 1,
            };
            result.count += 1;
        }
        return result;
    }

    pub fn active(self: *const FriScheduleV1) []const FriRoundV1 {
        return self.rounds[0..self.count];
    }

    pub fn eql(left: FriScheduleV1, right: FriScheduleV1) bool {
        if (left.count != right.count or
            left.terminal_evaluation_log != right.terminal_evaluation_log or
            left.last_layer_coefficient_count !=
                right.last_layer_coefficient_count)
        {
            return false;
        }
        for (left.active(), right.active()) |left_round, right_round| {
            if (!std.meta.eql(left_round, right_round)) return false;
        }
        return true;
    }
};

/// Exact Poseidon channel state immediately before the generic core verifier
/// draws composition randomness.  The native outer verifier must publish it
/// transactionally beside the successful proof capture.
pub const ChannelCheckpointV1 = struct {
    digest: channel.Digest,
    draw_count: u32 = 0,

    pub fn validate(self: ChannelCheckpointV1) Error!void {
        try requireDigest(self.digest);
        // Every preceding outer transcript mix resets the draw index.
        if (self.draw_count != 0) return error.InvalidReceipt;
    }

    pub fn intoChannel(self: ChannelCheckpointV1) channel.Channel {
        return .{ .digest = self.digest, .n_draws = self.draw_count };
    }
};

/// Values that only the outer verifier is authorized to publish.  The
/// profile seal binds this complete record; it is not a self-authenticating
/// substitute for the verifier-to-consumer custody channel.
pub const VerifierReceiptV1 = struct {
    format_version: u32 = FORMAT_VERSION,
    outer_format_version: u32 = OUTER_FORMAT_VERSION,
    outer_transcript_domain: u32 = OUTER_TRANSCRIPT_DOMAIN,
    scope: ProofScope = .verifier_subsystem,
    air_program_id: channel.Digest,
    manifest_id: channel.Digest,
    statement_id: channel.Digest,
    verification_key_id: channel.Digest,
    component_log_sizes: [CLAIMED_SUM_COUNT]u32,
    pre_core_channel: ChannelCheckpointV1,
    claimed_sums: [CLAIMED_SUM_COUNT]fixed_wire.Qm31Wire,
    /// Exact public boundary emitted by the verifier-input relation. This is
    /// independent of the two-term input/public wire closure below and must
    /// never be reconstructed by aggregating those terms.
    verifier_input_boundary: fixed_wire.Qm31Wire,
    wire_closure: [2]fixed_wire.Qm31Wire,
    interaction_pow_nonce: u64 = 0,

    pub fn validate(self: *const VerifierReceiptV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.outer_format_version != OUTER_FORMAT_VERSION or
            self.outer_transcript_domain != OUTER_TRANSCRIPT_DOMAIN or
            self.interaction_pow_nonce != 0)
        {
            return error.InvalidReceipt;
        }
        switch (self.scope) {
            .verifier_subsystem, .complete_parent => {},
        }
        try requireDigest(self.air_program_id);
        try requireDigest(self.manifest_id);
        try requireDigest(self.statement_id);
        try requireDigest(self.verification_key_id);
        try self.pre_core_channel.validate();
        for (self.component_log_sizes) |log_size| {
            if (log_size < 4 or log_size > MAX_DOMAIN_LOG)
                return error.InvalidComponentLogSize;
        }
        for (self.claimed_sums) |value| try validateQm31Wire(value);
        try validateQm31Wire(self.verifier_input_boundary);
        for (self.wire_closure) |value| try validateQm31Wire(value);
    }
};

/// Runtime-exact geometry authenticated before selecting a comptime wire.
pub const ShapeV1 = struct {
    format_version: u32,
    scope: ProofScope,
    air_program_id: channel.Digest,
    manifest_id: channel.Digest,
    statement_id: channel.Digest,
    verification_key_id: channel.Digest,
    preprocessing_id: channel.Digest,
    column_layout_id: channel.Digest,
    sample_layout_id: channel.Digest,
    component_log_sizes: [CLAIMED_SUM_COUNT]u32,
    table_count: u32,
    claimed_sum_count: u32,
    sampled_value_count: u32,
    tree_column_counts: [TREE_COUNT]u32,
    tree_heights: [TREE_COUNT]u32,
    column_log_degree: u32,
    proof_wire_bytes: u64,
    fri: FriScheduleV1,

    pub fn validate(self: ShapeV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.claimed_sum_count != CLAIMED_SUM_COUNT or
            self.table_count == 0 or self.sampled_value_count == 0 or
            self.proof_wire_bytes == 0)
        {
            return error.CaptureShapeMismatch;
        }
        try requireDigest(self.air_program_id);
        try requireDigest(self.manifest_id);
        try requireDigest(self.statement_id);
        try requireDigest(self.verification_key_id);
        try requireDigest(self.preprocessing_id);
        try requireDigest(self.column_layout_id);
        try requireDigest(self.sample_layout_id);
        var table_count: u32 = 0;
        for (self.tree_column_counts) |count| {
            if (count == 0) return error.InvalidColumnLayout;
            table_count = std.math.add(u32, table_count, count) catch
                return error.ArithmeticOverflow;
        }
        if (table_count != self.table_count)
            return error.InvalidColumnLayout;
        const composition_height = self.tree_heights[TREE_COUNT - 1];
        for (self.tree_heights) |height| {
            if (height <= LOG_BLOWUP_FACTOR or height > MAX_DOMAIN_LOG)
                return error.CaptureShapeMismatch;
            if (height > composition_height)
                return error.InvalidColumnLayout;
        }
        for (self.component_log_sizes) |log_size| {
            if (log_size < 4 or log_size > MAX_DOMAIN_LOG)
                return error.InvalidComponentLogSize;
        }
        const expected_fri = try FriScheduleV1.init(self.column_log_degree);
        if (!self.fri.eql(expected_fri) or
            self.tree_heights[TREE_COUNT - 1] !=
                self.column_log_degree + LOG_BLOWUP_FACTOR)
        {
            return error.InvalidFriSchedule;
        }
        const wire_dimensions = try self.dimensions();
        if (self.proof_wire_bytes != try serializedByteCountRuntime(wire_dimensions))
            return error.WireByteCountMismatch;
    }

    pub fn dimensions(self: ShapeV1) Error!fixed_wire.Dimensions {
        var maximum_depth: usize = 0;
        for (self.tree_heights) |height| maximum_depth = @max(maximum_depth, height);
        for (self.fri.active()) |round|
            maximum_depth = @max(maximum_depth, round.authentication_path_depth);
        const queried_value_count = std.math.mul(
            usize,
            self.table_count,
            QUERY_COUNT,
        ) catch return error.ArithmeticOverflow;
        return .{
            .commitment_count = TREE_COUNT,
            .claimed_sum_count = CLAIMED_SUM_COUNT,
            .sampled_value_count = self.sampled_value_count,
            .queried_value_count = queried_value_count,
            .trace_path_count = TREE_COUNT * QUERY_COUNT,
            .fri_layer_count = self.fri.count,
            .query_count = QUERY_COUNT,
            .maximum_fold_width = 2,
            .last_layer_coefficient_count = self.fri.last_layer_coefficient_count,
            .maximum_merkle_depth = maximum_depth,
        };
    }

    pub fn id(self: ShapeV1) Error!channel.Digest {
        try self.validate();
        var hash = AuthorityHasher.init(PROFILE_ID_DOMAIN);
        hash.addU32(FORMAT_VERSION);
        hash.addU32(OUTER_FORMAT_VERSION);
        hash.addU32(OUTER_TRANSCRIPT_DOMAIN);
        hash.addU32(@intFromEnum(self.scope));
        hash.addU32(INTERACTION_POW_BITS);
        hash.addU32(PCS_POW_BITS);
        hash.addU32(LOG_BLOWUP_FACTOR);
        hash.addU32(QUERY_COUNT);
        hash.addU32(LOG_LAST_LAYER_DEGREE_BOUND);
        hash.addU32(FOLD_STEP);
        hash.digest(protocol.PROTOCOL_ID_WORDS);
        hash.digest(channel.parameterId());
        hash.digest(self.air_program_id);
        hash.digest(self.manifest_id);
        hash.digest(self.statement_id);
        hash.digest(self.verification_key_id);
        hash.digest(self.preprocessing_id);
        hash.digest(self.column_layout_id);
        hash.digest(self.sample_layout_id);
        hash.addU32s(&self.component_log_sizes);
        hash.addU32(self.table_count);
        hash.addU32(self.claimed_sum_count);
        hash.addU32(self.sampled_value_count);
        hash.addU32s(&self.tree_column_counts);
        hash.addU32s(&self.tree_heights);
        hash.addU32(self.column_log_degree);
        hash.addU64(self.proof_wire_bytes);
        hash.addU32(self.fri.count);
        hash.addU32(self.fri.terminal_evaluation_log);
        hash.addU32(self.fri.last_layer_coefficient_count);
        for (self.fri.active()) |round| {
            hash.addU32(round.evaluation_log);
            hash.addU32(round.fold_step);
            hash.addU32(round.fold_width);
            hash.addU32(round.authentication_path_depth);
        }
        return hash.finalize();
    }
};

pub const VerifierSealV1 = struct {
    profile_id: channel.Digest,
    capture_id: channel.Digest,
    receipt_id: channel.Digest,
    transcript_id: channel.Digest,
    claimed_sums_id: channel.Digest,
    verifier_input_boundary: fixed_wire.Qm31Wire,

    pub fn validate(self: VerifierSealV1) Error!void {
        try requireDigest(self.profile_id);
        try requireDigest(self.capture_id);
        try requireDigest(self.receipt_id);
        try requireDigest(self.transcript_id);
        try requireDigest(self.claimed_sums_id);
        try validateQm31Wire(self.verifier_input_boundary);
    }
};

pub const DerivedAdmissionV1 = struct {
    shape: ShapeV1,
    dimensions: fixed_wire.Dimensions,
    seal: VerifierSealV1,
    final_channel_digest: channel.Digest,
    final_draw_count: u32,
};

pub const PairChildInputsV1 = struct {
    position: pair_node.ChildPosition,
    role: pair_node.ChildRole,
    leaf_index: u32,
    pair_index: u32,
    leaf_count: u32,
    session_id: channel.Digest,
    challenge_context_id: channel.Digest,
    authority_context_id: channel.Digest,
    parent_vk_id: channel.Digest,
    statement_id: channel.Digest,
    summary_id: channel.Digest,
    event_count: u64,
    signed_relation_total: pair_node.SecureFelt,
};

pub fn serializedByteCount(comptime dimensions: fixed_wire.Dimensions) usize {
    dimensions.validate();
    return serializedByteCountRuntime(dimensions) catch
        @panic("outer-parent wire byte count overflow");
}

pub fn serializedByteCountRuntime(dimensions: fixed_wire.Dimensions) Error!usize {
    const header_bytes = (2 + 6 * channel.RATE + 4) * @sizeOf(u32);
    const result = std.math.add(
        usize,
        header_bytes,
        try fixed_wire.serializedByteCountRuntime(dimensions),
    ) catch return error.ArithmeticOverflow;
    if (result > std.math.maxInt(u32)) return error.ArithmeticOverflow;
    return result;
}

pub fn validatePayload(
    comptime dimensions: fixed_wire.Dimensions,
    payload: *const fixed_wire.FixedStarkProofWire(dimensions),
    shape: ShapeV1,
) Error!void {
    try shape.validate();
    if (!dimensionsEql(dimensions, try shape.dimensions()) or
        payload.interaction_pow != 0)
    {
        return error.DimensionMismatch;
    }
    for (payload.commitments) |value| try validateDigest(value);
    for (payload.claimed_sums) |value| try validateQm31Wire(value);
    for (payload.sampled_values) |value| try validateQm31Wire(value);
    for (payload.queried_values) |value| try validateCanonicalWord(value);
    for (payload.last_layer_coefficients) |value| try validateQm31Wire(value);
    for (shape.tree_heights, 0..) |height, tree| {
        const start = tree * QUERY_COUNT;
        for (payload.trace_paths[start..][0..QUERY_COUNT]) |path|
            try path.validate(height);
    }
    for (payload.fri_layers, shape.fri.active()) |layer, round| {
        if (layer.active_width != round.fold_width)
            return error.FriLayerWidthMismatch;
        try validateDigest(layer.commitment);
        for (layer.queries) |query| {
            for (query.values, 0..) |value, index| {
                try validateQm31Wire(value);
                if (index >= round.fold_width and !isZeroQm31(value))
                    return error.NonZeroFriValuePadding;
            }
            query.path.validate(round.authentication_path_depth) catch |err| switch (err) {
                error.MerklePathDepthMismatch => return error.FriPathDepthMismatch,
                else => return err,
            };
        }
    }
}

pub const ByteWriter = struct {
    bytes: []u8,
    at: usize,

    pub fn writeU32(self: *ByteWriter, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }

    pub fn writeU64(self: *ByteWriter, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.at..][0..8], value, .little);
        self.at += 8;
    }

    pub fn digest(self: *ByteWriter, value: channel.Digest) void {
        for (value) |word| self.writeU32(word);
    }

    pub fn qm31(self: *ByteWriter, value: fixed_wire.Qm31Wire) void {
        for (value) |word| self.writeU32(word);
    }
};

/// Streaming equivalent of `protocol.proofId(canonical_bytes)`. Canonical
/// little-endian u32/u64 encodings become exactly the two-byte limbs consumed
/// by `hashBytes`, avoiding an output-buffer write during validation.
pub const ProofIdHasher = struct {
    inner: channel.CanonicalWordHasher,

    pub fn init(byte_count: usize) ProofIdHasher {
        std.debug.assert(byte_count <= std.math.maxInt(u32));
        var inner = channel.CanonicalWordHasher.init(protocol.PROOF_ID_DOMAIN);
        const length = [_]M31{M31.fromCanonical(@intCast(byte_count))};
        inner.update(&length);
        return .{ .inner = inner };
    }

    pub fn writeU32(self: *ProofIdHasher, value: u32) void {
        const limbs = [_]M31{
            M31.fromCanonical(value & 0xffff),
            M31.fromCanonical(value >> 16),
        };
        self.inner.update(&limbs);
    }

    pub fn writeU64(self: *ProofIdHasher, value: u64) void {
        self.writeU32(@truncate(value));
        self.writeU32(@truncate(value >> 32));
    }

    pub fn digest(self: *ProofIdHasher, value: channel.Digest) void {
        for (value) |word| self.writeU32(word);
    }

    pub fn qm31(self: *ProofIdHasher, value: fixed_wire.Qm31Wire) void {
        for (value) |word| self.writeU32(word);
    }

    pub fn finalize(self: *ProofIdHasher) channel.Digest {
        return self.inner.finalize();
    }
};

pub fn claimedSumsId(values: []const fixed_wire.Qm31Wire) channel.Digest {
    var hash = AuthorityHasher.init(CLAIMS_ID_DOMAIN);
    hash.addUsize(values.len);
    for (values) |value| hash.qm31Wire(value);
    return hash.finalize();
}

pub const AuthorityHasher = struct {
    inner: channel.CanonicalWordHasher,

    pub fn init(domain: u32) AuthorityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    pub fn addU32(self: *AuthorityHasher, value: u32) void {
        std.debug.assert(value < stwo_core.fields.m31.Modulus);
        const word = [_]M31{M31.fromCanonical(value)};
        self.inner.update(&word);
    }

    pub fn addUsize(self: *AuthorityHasher, value: usize) void {
        std.debug.assert(value <= std.math.maxInt(u32));
        self.addU32(@intCast(value));
    }

    pub fn addU64(self: *AuthorityHasher, value: u64) void {
        self.addU32(@truncate(value & 0xffff));
        self.addU32(@truncate((value >> 16) & 0xffff));
        self.addU32(@truncate((value >> 32) & 0xffff));
        self.addU32(@truncate(value >> 48));
    }

    pub fn addU32s(self: *AuthorityHasher, values: []const u32) void {
        for (values) |value| self.addU32(value);
    }

    pub fn digest(self: *AuthorityHasher, value: channel.Digest) void {
        self.addU32s(&value);
    }

    pub fn qm31(self: *AuthorityHasher, value: QM31) void {
        self.inner.update(&value.toM31Array());
    }

    pub fn qm31Wire(self: *AuthorityHasher, value: fixed_wire.Qm31Wire) void {
        self.addU32s(&value);
    }

    pub fn finalize(self: *AuthorityHasher) channel.Digest {
        return self.inner.finalize();
    }
};

pub fn qm31Wire(value: QM31) fixed_wire.Qm31Wire {
    const words = value.toM31Array();
    return .{ words[0].toU32(), words[1].toU32(), words[2].toU32(), words[3].toU32() };
}

pub fn validateCanonicalWord(value: u32) Error!void {
    if (value >= stwo_core.fields.m31.Modulus)
        return error.NonCanonicalCapture;
}

pub fn validateQm31Wire(value: fixed_wire.Qm31Wire) Error!void {
    for (value) |word| try validateCanonicalWord(word);
}

pub fn validateDigest(value: channel.Digest) Error!void {
    for (value) |word| try validateCanonicalWord(word);
}

pub fn requireDigest(value: channel.Digest) Error!void {
    try validateDigest(value);
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    if (aggregate == 0) return error.EmptyAuthority;
}

pub fn dimensionsEql(left: fixed_wire.Dimensions, right: fixed_wire.Dimensions) bool {
    return std.meta.eql(left, right);
}

pub fn isZeroQm31(value: fixed_wire.Qm31Wire) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}
