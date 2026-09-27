//! Internal outer parent child admission authority shard; use outer_parent_child_admission.zig publicly.

const dependency_0 = @import("outer_parent_child_admission_contract.zig");

const AuthorityHasher = dependency_0.AuthorityHasher;
const ByteWriter = dependency_0.ByteWriter;
const CAPTURE_ID_DOMAIN = dependency_0.CAPTURE_ID_DOMAIN;
const CLAIMED_SUM_COUNT = dependency_0.CLAIMED_SUM_COUNT;
const COLUMN_LAYOUT_ID_DOMAIN = dependency_0.COLUMN_LAYOUT_ID_DOMAIN;
const ChannelCheckpointV1 = dependency_0.ChannelCheckpointV1;
const CirclePointQM31 = dependency_0.CirclePointQM31;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const FriScheduleV1 = dependency_0.FriScheduleV1;
const LOG_BLOWUP_FACTOR = dependency_0.LOG_BLOWUP_FACTOR;
const M31 = dependency_0.M31;
const MAX_DOMAIN_LOG = dependency_0.MAX_DOMAIN_LOG;
const PCS_POW_BITS = dependency_0.PCS_POW_BITS;
const PairChildInputsV1 = dependency_0.PairChildInputsV1;
const ProofCapture = dependency_0.ProofCapture;
const ProofIdHasher = dependency_0.ProofIdHasher;
const ProofScope = dependency_0.ProofScope;
const QM31 = dependency_0.QM31;
const QUERY_COUNT = dependency_0.QUERY_COUNT;
const RECEIPT_ID_DOMAIN = dependency_0.RECEIPT_ID_DOMAIN;
const RECURSIVE_PARENT_PRODUCTION = dependency_0.RECURSIVE_PARENT_PRODUCTION;
const SAMPLE_LAYOUT_ID_DOMAIN = dependency_0.SAMPLE_LAYOUT_ID_DOMAIN;
const ShapeV1 = dependency_0.ShapeV1;
const TREE_COUNT = dependency_0.TREE_COUNT;
const VerifierReceiptV1 = dependency_0.VerifierReceiptV1;
const VerifierSealV1 = dependency_0.VerifierSealV1;
const WIRE_MAGIC = dependency_0.WIRE_MAGIC;
const channel = dependency_0.channel;
const claimedSumsId = dependency_0.claimedSumsId;
const dimensionsEql = dependency_0.dimensionsEql;
const engine = dependency_0.engine;
const fixed_wire = dependency_0.fixed_wire;
const pair_node = dependency_0.pair_node;
const protocol = dependency_0.protocol;
const qm31Wire = dependency_0.qm31Wire;
const requireDigest = dependency_0.requireDigest;
const sample_point_layout = dependency_0.sample_point_layout;
const serializedByteCount = dependency_0.serializedByteCount;
const std = dependency_0.std;
const stwo_core = dependency_0.stwo_core;
const validatePayload = dependency_0.validatePayload;

/// Canonical outer wire header. The payload deliberately reuses only the
/// pointer-free field layout of `FixedStarkProofWire`; leaf-V1 validation and
/// codecs are never invoked for this profile.
pub fn FixedOuterProofWireV1(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    return struct {
        magic: u32,
        format_version: u32,
        protocol_id: channel.Digest,
        profile_id: channel.Digest,
        capture_id: channel.Digest,
        receipt_id: channel.Digest,
        transcript_id: channel.Digest,
        claimed_sums_id: channel.Digest,
        verifier_input_boundary: fixed_wire.Qm31Wire,
        payload: fixed_wire.FixedStarkProofWire(dimensions),

        const Self = @This();

        pub fn transcriptWire(self: *const Self) *const fixed_wire.FixedStarkProofWire(
            dimensions,
        ) {
            return &self.payload;
        }

        pub fn validateAgainst(
            self: *const Self,
            candidate: *const BinaryPairCandidateV1,
            encoding_scratch: []u8,
        ) Error!void {
            try candidate.validate();
            if (!dimensionsEql(dimensions, candidate.dimensions))
                return error.DimensionMismatch;
            if (self.magic != WIRE_MAGIC or
                self.format_version != FORMAT_VERSION or
                !std.meta.eql(self.protocol_id, protocol.PROTOCOL_ID_WORDS) or
                !std.meta.eql(self.profile_id, candidate.profile_id) or
                !std.meta.eql(self.capture_id, candidate.capture_id) or
                !std.meta.eql(self.receipt_id, candidate.receipt_id) or
                !std.meta.eql(self.transcript_id, candidate.transcript_id) or
                !std.meta.eql(self.claimed_sums_id, candidate.claimed_sums_id) or
                !std.meta.eql(
                    self.verifier_input_boundary,
                    candidate.verifier_input_boundary,
                ))
            {
                return error.WireHeaderMismatch;
            }
            try validatePayload(dimensions, &self.payload, candidate.shape);
            if (!std.meta.eql(
                claimedSumsId(&self.payload.claimed_sums),
                self.claimed_sums_id,
            )) return error.WireHeaderMismatch;
            if (!std.meta.eql(proofIdAssumeValid(dimensions, self), candidate.proof_id))
                return error.WireHeaderMismatch;
            if (encoding_scratch.len != serializedByteCount(dimensions))
                return error.ByteLengthMismatch;
            if (slicesOverlap(std.mem.asBytes(self), encoding_scratch) or
                slicesOverlap(std.mem.asBytes(candidate), encoding_scratch))
            {
                return error.AliasedBuffer;
            }
            encodeAssumeValid(dimensions, self, encoding_scratch);
        }

        pub fn encodeInto(
            self: *const Self,
            candidate: *const BinaryPairCandidateV1,
            destination: []u8,
        ) Error!void {
            try self.validateAgainst(candidate, destination);
        }
    };
}

/// The exact identity surface consumed by the binary-pair custody layer.
/// Existing `pair_node.VerifiedChildV1` remains valid because this is a
/// versioned child profile within the same overarching recursion protocol.
pub const BinaryPairCandidateV1 = struct {
    scope: ProofScope,
    shape: ShapeV1,
    dimensions: fixed_wire.Dimensions,
    profile_id: channel.Digest,
    capture_id: channel.Digest,
    receipt_id: channel.Digest,
    transcript_id: channel.Digest,
    claimed_sums_id: channel.Digest,
    verifier_input_boundary: fixed_wire.Qm31Wire,
    proof_id: channel.Digest,
    canonical_wire_bytes: u64,

    pub fn validate(self: *const BinaryPairCandidateV1) Error!void {
        try self.shape.validate();
        if (!dimensionsEql(self.dimensions, try self.shape.dimensions()) or
            self.canonical_wire_bytes != self.shape.proof_wire_bytes or
            !std.meta.eql(self.profile_id, try self.shape.id()))
        {
            return error.DimensionMismatch;
        }
        try (VerifierSealV1{
            .profile_id = self.profile_id,
            .capture_id = self.capture_id,
            .receipt_id = self.receipt_id,
            .transcript_id = self.transcript_id,
            .claimed_sums_id = self.claimed_sums_id,
            .verifier_input_boundary = self.verifier_input_boundary,
        }).validate();
        try requireDigest(self.proof_id);
    }

    pub fn productionReady(self: *const BinaryPairCandidateV1) bool {
        return RECURSIVE_PARENT_PRODUCTION and self.scope == .complete_parent;
    }

    /// Produces the verifier-owned child receipt expected by pair-node
    /// authentication.  This does not override `productionReady`: callers
    /// must retain the explicit scope gate until the complete parent prover
    /// and its independent verifier exist.
    pub fn verifiedChild(
        self: *const BinaryPairCandidateV1,
        inputs: PairChildInputsV1,
    ) Error!pair_node.VerifiedChildV1 {
        try self.validate();
        if (!self.productionReady())
            return error.ParentProofIncomplete;
        if (!std.meta.eql(inputs.statement_id, self.shape.statement_id) or
            !std.meta.eql(inputs.parent_vk_id, self.shape.verification_key_id))
        {
            return error.PairIdentityMismatch;
        }
        return .{
            .position = inputs.position,
            .role = inputs.role,
            .leaf_index = inputs.leaf_index,
            .pair_index = inputs.pair_index,
            .leaf_count = inputs.leaf_count,
            .protocol_id = protocol.PROTOCOL_ID_WORDS,
            .session_id = inputs.session_id,
            .challenge_context_id = inputs.challenge_context_id,
            .authority_context_id = inputs.authority_context_id,
            .parent_vk_id = inputs.parent_vk_id,
            .statement_id = inputs.statement_id,
            .proof_id = self.proof_id,
            .transcript_id = self.transcript_id,
            .summary_id = inputs.summary_id,
            .event_count = inputs.event_count,
            .signed_relation_total = inputs.signed_relation_total,
        };
    }
};

/// Runtime-shaped result for artifact producers that learn the exact outer
/// proof geometry only after the independent verifier publishes its capture.
/// The byte count is repeated beside the candidate as a native-sized value so
/// callers can publish the exact encoded payload without narrowing casts.
pub const RuntimeAdmissionV1 = struct {
    candidate: BinaryPairCandidateV1,
    canonical_byte_count: usize,

    pub fn validate(self: *const RuntimeAdmissionV1) Error!void {
        try self.candidate.validate();
        if (self.candidate.canonical_wire_bytes != self.canonical_byte_count)
            return error.WireByteCountMismatch;
    }
};

pub fn deriveShape(
    receipt: *const VerifierReceiptV1,
    capture: *const ProofCapture,
) Error!ShapeV1 {
    if (capture.commitments.len != TREE_COUNT or
        capture.column_log_sizes.len != TREE_COUNT or
        capture.trace_paths.len != TREE_COUNT or
        capture.sampled_points.len != TREE_COUNT or
        capture.queries.raw.len != QUERY_COUNT or
        capture.deep_answers.len != QUERY_COUNT)
    {
        return error.CaptureShapeMismatch;
    }
    var tree_column_counts: [TREE_COUNT]u32 = undefined;
    var tree_heights: [TREE_COUNT]u32 = undefined;
    var table_count: u32 = 0;
    for (capture.column_log_sizes, capture.trace_paths, 0..) |
        logs,
        paths,
        index,
    | {
        if (logs.len == 0 or logs.len > std.math.maxInt(u32))
            return error.InvalidColumnLayout;
        tree_column_counts[index] = @intCast(logs.len);
        table_count = std.math.add(u32, table_count, tree_column_counts[index]) catch
            return error.ArithmeticOverflow;
        var maximum_log: u32 = 0;
        for (logs) |log_size| {
            if (log_size <= LOG_BLOWUP_FACTOR or log_size > MAX_DOMAIN_LOG)
                return error.InvalidColumnLayout;
            maximum_log = @max(maximum_log, log_size);
        }
        if (maximum_log != paths.path_depth)
            return error.InvalidColumnLayout;
        tree_heights[index] = maximum_log;
    }
    const column_log_degree = std.math.sub(
        u32,
        tree_heights[TREE_COUNT - 1],
        LOG_BLOWUP_FACTOR,
    ) catch return error.InvalidFriSchedule;
    for (capture.column_log_sizes[TREE_COUNT - 1]) |log_size| {
        if (log_size != tree_heights[TREE_COUNT - 1])
            return error.InvalidColumnLayout;
    }
    const fri = try FriScheduleV1.init(column_log_degree);
    var sampled_value_count: usize = 0;
    for (capture.sampled_points, capture.column_log_sizes) |columns, logs| {
        if (columns.len != logs.len) return error.CaptureShapeMismatch;
        for (columns) |points| {
            sampled_value_count = std.math.add(
                usize,
                sampled_value_count,
                points.len,
            ) catch return error.ArithmeticOverflow;
        }
    }
    if (sampled_value_count == 0 or sampled_value_count > std.math.maxInt(u32) or
        sampled_value_count != capture.sampled_values.len)
    {
        return error.CaptureShapeMismatch;
    }
    return .{
        .format_version = FORMAT_VERSION,
        .scope = receipt.scope,
        .air_program_id = receipt.air_program_id,
        .manifest_id = receipt.manifest_id,
        .statement_id = receipt.statement_id,
        .verification_key_id = receipt.verification_key_id,
        .preprocessing_id = capture.commitments[0],
        .column_layout_id = columnLayoutId(capture.column_log_sizes),
        .sample_layout_id = sampleLayoutId(capture.sampled_points),
        .component_log_sizes = receipt.component_log_sizes,
        .table_count = table_count,
        .claimed_sum_count = CLAIMED_SUM_COUNT,
        .sampled_value_count = @intCast(sampled_value_count),
        .tree_column_counts = tree_column_counts,
        .tree_heights = tree_heights,
        .column_log_degree = column_log_degree,
        .proof_wire_bytes = 1, // Replaced after exact dimensions are derived.
        .fri = fri,
    };
}

pub const TranscriptReplay = struct {
    final_digest: channel.Digest,
    final_draw_count: u32,
};

pub fn replayTranscript(
    capture: *const ProofCapture,
    shape: ShapeV1,
    checkpoint: ChannelCheckpointV1,
) Error!TranscriptReplay {
    try checkpoint.validate();
    var transcript = checkpoint.intoChannel();
    if (!transcript.drawSecureFelt().eql(capture.composition_randomness))
        return error.TranscriptMismatch;
    engine.MerkleChannel.mixRoot(
        &transcript,
        capture.commitments[TREE_COUNT - 1],
    );
    if (!transcript.drawSecureFelt().eql(capture.oods_seed))
        return error.TranscriptMismatch;
    transcript.mixFelts(capture.sampled_values);
    if (!transcript.drawSecureFelt().eql(capture.deep_randomness))
        return error.TranscriptMismatch;
    for (capture.fri.layers) |layer| {
        engine.MerkleChannel.mixRoot(&transcript, layer.commitment);
        if (!transcript.drawSecureFelt().eql(layer.folding_alpha))
            return error.TranscriptMismatch;
    }
    transcript.mixFelts(capture.last_layer_coefficients);
    if (!transcript.verifyPowNonce(PCS_POW_BITS, capture.proof_of_work))
        return error.TranscriptMismatch;
    transcript.mixU64(capture.proof_of_work);
    const query_words = transcript.drawU32s();
    const query_log = shape.column_log_degree + LOG_BLOWUP_FACTOR;
    if (query_log >= 32) return error.InvalidQuerySchedule;
    const mask = (@as(u32, 1) << @intCast(query_log)) - 1;
    for (capture.queries.raw, query_words[0..QUERY_COUNT]) |actual, word| {
        if (actual != @as(usize, word & mask))
            return error.TranscriptMismatch;
    }
    return .{
        .final_digest = transcript.digestWords(),
        .final_draw_count = transcript.n_draws,
    };
}

pub fn validateSampledPoints(shape: ShapeV1, capture: *const ProofCapture) Error!void {
    const current = stwo_core.circle.secureFieldPointFromRandomSeedChecked(
        capture.oods_seed,
    ) catch return error.CaptureShapeMismatch;
    const step = stwo_core.poly.circle.canonic.CanonicCoset.new(
        shape.column_log_degree,
    ).step();
    const previous = current.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
    var sampled_count: usize = 0;
    for (capture.sampled_points, capture.column_log_sizes) |columns, logs| {
        if (columns.len != logs.len) return error.CaptureShapeMismatch;
        for (columns) |points| {
            try validateSamplePointColumnLayout(points, current, previous);
            for (points) |point| {
                try validateQm31(point.x);
                try validateQm31(point.y);
            }
            sampled_count = std.math.add(usize, sampled_count, points.len) catch
                return error.ArithmeticOverflow;
        }
    }
    if (sampled_count != capture.sampled_values.len)
        return error.CaptureShapeMismatch;
}

/// Validates the only mask-point layouts emitted by the admitted outer AIRs.
///
/// Current-only columns are common to every component. Two-point LogUp masks
/// have two independently authoritative conventions: shared/legacy providers
/// request `[current, previous]`, while universal typed rows request
/// `[previous, current]` and index them in that order. The native verifier
/// authenticates the sampled values, and the capture/seal hashes retain the
/// exact order; accepting both conventions here therefore does not normalize
/// or bless consumer-controlled input.
pub fn validateSamplePointColumnLayout(
    points: []const CirclePointQM31,
    current: CirclePointQM31,
    previous: CirclePointQM31,
) Error!void {
    return sample_point_layout.validateColumn(points, current, previous);
}

pub fn encodeAssumeValid(
    comptime dimensions: fixed_wire.Dimensions,
    wire: *const FixedOuterProofWireV1(dimensions),
    destination: []u8,
) void {
    var writer = ByteWriter{ .bytes = destination, .at = 0 };
    writer.writeU32(wire.magic);
    writer.writeU32(wire.format_version);
    writer.digest(wire.protocol_id);
    writer.digest(wire.profile_id);
    writer.digest(wire.capture_id);
    writer.digest(wire.receipt_id);
    writer.digest(wire.transcript_id);
    writer.digest(wire.claimed_sums_id);
    writer.qm31(wire.verifier_input_boundary);
    for (wire.payload.commitments) |value| writer.digest(value);
    for (wire.payload.claimed_sums) |value| writer.qm31(value);
    for (wire.payload.sampled_values) |value| writer.qm31(value);
    for (wire.payload.queried_values) |value| writer.writeU32(value);
    for (wire.payload.trace_paths) |path| {
        writer.writeU32(path.active_depth);
        for (path.siblings) |value| writer.digest(value);
    }
    for (wire.payload.fri_layers) |layer| {
        writer.writeU32(layer.active_width);
        writer.digest(layer.commitment);
        for (layer.queries) |query| {
            for (query.values) |value| writer.qm31(value);
            writer.writeU32(query.path.active_depth);
            for (query.path.siblings) |value| writer.digest(value);
        }
    }
    for (wire.payload.last_layer_coefficients) |value| writer.qm31(value);
    writer.writeU64(wire.payload.interaction_pow);
    writer.writeU64(wire.payload.pcs_pow);
    std.debug.assert(writer.at == destination.len);
}

pub fn proofIdAssumeValid(
    comptime dimensions: fixed_wire.Dimensions,
    wire: *const FixedOuterProofWireV1(dimensions),
) channel.Digest {
    var hash = ProofIdHasher.init(serializedByteCount(dimensions));
    hash.writeU32(wire.magic);
    hash.writeU32(wire.format_version);
    hash.digest(wire.protocol_id);
    hash.digest(wire.profile_id);
    hash.digest(wire.capture_id);
    hash.digest(wire.receipt_id);
    hash.digest(wire.transcript_id);
    hash.digest(wire.claimed_sums_id);
    hash.qm31(wire.verifier_input_boundary);
    for (wire.payload.commitments) |value| hash.digest(value);
    for (wire.payload.claimed_sums) |value| hash.qm31(value);
    for (wire.payload.sampled_values) |value| hash.qm31(value);
    for (wire.payload.queried_values) |value| hash.writeU32(value);
    for (wire.payload.trace_paths) |path| {
        hash.writeU32(path.active_depth);
        for (path.siblings) |value| hash.digest(value);
    }
    for (wire.payload.fri_layers) |layer| {
        hash.writeU32(layer.active_width);
        hash.digest(layer.commitment);
        for (layer.queries) |query| {
            for (query.values) |value| hash.qm31(value);
            hash.writeU32(query.path.active_depth);
            for (query.path.siblings) |value| hash.digest(value);
        }
    }
    for (wire.payload.last_layer_coefficients) |value| hash.qm31(value);
    hash.writeU64(wire.payload.interaction_pow);
    hash.writeU64(wire.payload.pcs_pow);
    return hash.finalize();
}

pub fn captureId(capture: *const ProofCapture) channel.Digest {
    var hash = AuthorityHasher.init(CAPTURE_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addUsize(capture.commitments.len);
    for (capture.commitments) |value| hash.digest(value);
    hash.addUsize(capture.column_log_sizes.len);
    for (capture.column_log_sizes) |logs| {
        hash.addUsize(logs.len);
        hash.addU32s(logs);
    }
    hash.addUsize(capture.sampled_points.len);
    for (capture.sampled_points) |columns| {
        hash.addUsize(columns.len);
        for (columns) |points| {
            hash.addUsize(points.len);
            for (points) |point| {
                hash.qm31(point.x);
                hash.qm31(point.y);
            }
        }
    }
    hash.addUsize(capture.sampled_values.len);
    for (capture.sampled_values) |value| hash.qm31(value);
    hash.addUsize(capture.queried_values.len);
    for (capture.queried_values) |value| hash.addU32(value.toU32());
    hash.addUsize(capture.deep_answers.len);
    for (capture.deep_answers) |value| hash.qm31(value);
    hash.addUsize(capture.trace_paths.len);
    for (capture.trace_paths) |paths| {
        hash.addU32(paths.path_depth);
        hash.addUsize(paths.positions.len);
        for (paths.positions) |position| hash.addUsize(position);
        hash.addUsize(paths.siblings.len);
        for (paths.siblings) |value| hash.digest(value);
    }
    hash.addUsize(capture.fri.layers.len);
    for (capture.fri.layers) |layer| {
        hash.digest(layer.commitment);
        hash.qm31(layer.folding_alpha);
        hash.addU32(layer.fold_step);
        hash.addU32(layer.fold_width);
        hash.addU32(layer.path_depth);
        hash.addUsize(layer.query_count);
        hash.addUsize(layer.positions.len);
        for (layer.positions) |position| hash.addUsize(position);
        hash.addUsize(layer.values.len);
        for (layer.values) |value| hash.qm31(value);
        hash.addUsize(layer.siblings.len);
        for (layer.siblings) |value| hash.digest(value);
    }
    hash.addUsize(capture.last_layer_coefficients.len);
    for (capture.last_layer_coefficients) |value| hash.qm31(value);
    hash.addU64(capture.proof_of_work);
    hash.qm31(capture.composition_randomness);
    hash.qm31(capture.oods_seed);
    hash.qm31(capture.deep_randomness);
    hash.addUsize(capture.queries.raw.len);
    for (capture.queries.raw) |position| hash.addUsize(position);
    hash.addUsize(capture.queries.unique.len);
    for (capture.queries.unique) |position| hash.addUsize(position);
    return hash.finalize();
}

pub fn receiptId(
    receipt: *const VerifierReceiptV1,
    profile_id: channel.Digest,
    capture_id: channel.Digest,
    transcript_id: channel.Digest,
    claimed_sums_id: channel.Digest,
) channel.Digest {
    var hash = AuthorityHasher.init(RECEIPT_ID_DOMAIN);
    hash.addU32(receipt.format_version);
    hash.addU32(receipt.outer_format_version);
    hash.addU32(receipt.outer_transcript_domain);
    hash.addU32(@intFromEnum(receipt.scope));
    hash.digest(profile_id);
    hash.digest(capture_id);
    hash.digest(transcript_id);
    hash.digest(claimed_sums_id);
    hash.digest(receipt.air_program_id);
    hash.digest(receipt.manifest_id);
    hash.digest(receipt.statement_id);
    hash.digest(receipt.verification_key_id);
    hash.addU32s(&receipt.component_log_sizes);
    hash.digest(receipt.pre_core_channel.digest);
    hash.addU32(receipt.pre_core_channel.draw_count);
    hash.qm31Wire(receipt.verifier_input_boundary);
    for (receipt.wire_closure) |value| hash.qm31Wire(value);
    hash.addU64(receipt.interaction_pow_nonce);
    return hash.finalize();
}

pub fn columnLayoutId(logs_by_tree: []const []u32) channel.Digest {
    var hash = AuthorityHasher.init(COLUMN_LAYOUT_ID_DOMAIN);
    hash.addUsize(logs_by_tree.len);
    for (logs_by_tree) |logs| {
        hash.addUsize(logs.len);
        hash.addU32s(logs);
    }
    return hash.finalize();
}

pub fn sampleLayoutId(points_by_tree: []const [][]CirclePointQM31) channel.Digest {
    var hash = AuthorityHasher.init(SAMPLE_LAYOUT_ID_DOMAIN);
    hash.addUsize(points_by_tree.len);
    for (points_by_tree) |columns| {
        hash.addUsize(columns.len);
        for (columns) |points| hash.addUsize(points.len);
    }
    return hash.finalize();
}

pub fn validateQuerySet(raw: []const usize, unique: []const usize, log_size: u32) Error!void {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidQuerySchedule;
    const domain_size = @as(usize, 1) << @intCast(log_size);
    for (unique, 0..) |position, index| {
        if (position >= domain_size or
            (index != 0 and unique[index - 1] >= position))
        {
            return error.InvalidQuerySchedule;
        }
        var seen = false;
        for (raw) |candidate| if (candidate == position) {
            seen = true;
            break;
        };
        if (!seen) return error.InvalidQuerySchedule;
    }
    for (raw) |position| {
        if (position >= domain_size or findSortedPosition(unique, position) == null)
            return error.InvalidQuerySchedule;
    }
}

pub fn findSortedPosition(positions: []const usize, target: usize) ?usize {
    var left: usize = 0;
    var right: usize = positions.len;
    while (left < right) {
        const middle = left + (right - left) / 2;
        if (positions[middle] < target) left = middle + 1 else right = middle;
    }
    if (left < positions.len and positions[left] == target) return left;
    return null;
}

pub fn mapTreeQueryPosition(position: usize, max_log_size: u32, tree_log_size: u32) usize {
    if (tree_log_size == 0) return 0;
    if (max_log_size < tree_log_size) {
        return (position >> 1 << @intCast(tree_log_size - max_log_size + 1)) +
            (position & 1);
    }
    return (position >> @intCast(max_log_size - tree_log_size + 1) << 1) +
        (position & 1);
}

pub fn validateM31(value: M31) Error!void {
    if (value.toU32() >= stwo_core.fields.m31.Modulus)
        return error.NonCanonicalCapture;
}

pub fn validateQm31(value: QM31) Error!void {
    for (value.toM31Array()) |word| try validateM31(word);
}

pub fn slicesOverlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}
