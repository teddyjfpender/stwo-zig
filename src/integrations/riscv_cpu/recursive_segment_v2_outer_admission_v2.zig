//! Opaque admission of one independently verified 39-claim SegmentV2 outer
//! proof into the next recursion layer.
//!
//! Frozen V1 outer admission fixes a 36-claim universal roster and therefore
//! cannot represent SegmentV2 without truncation. This module keeps the
//! verifier-minted V2 receipt and capture in integration custody, replays the
//! exact post-interaction transcript from its pre-core checkpoint, and offers
//! one compile-time fixed-wire copy seam to manifest-generic row owners.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact = @import("recursive_segment_v2_verified_artifact.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const captured_fri = recursion.captured_fri;
const fixed_wire = recursion.fixed_wire;
const protocol = recursion.protocol;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const TREE_COUNT: usize = admission.TREE_COUNT;
pub const QUERY_COUNT: usize = admission.QUERY_COUNT;
pub const CLAIM_COUNT: usize = artifact.CLAIM_COUNT;
pub const StatementWords = @TypeOf(@as(artifact.Publication, undefined).statement_words);
/// Canonical fixed-wire geometry for the current SegmentV2 outer verifier.
///
/// This value is protocol authority, not an allocation shape inferred by a
/// recursive caller.  `deriveDimensions` independently recomputes every
/// capture-dependent axis at admission and must match this profile exactly.
/// The ReleaseFast real-ingress gate pins the same receipt end to end.
pub const SEGMENT_V2_OUTER_DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = TREE_COUNT,
    .claimed_sum_count = CLAIM_COUNT,
    .sampled_value_count = 2_245,
    .queried_value_count = 6_255,
    .trace_path_count = TREE_COUNT * QUERY_COUNT,
    .fri_layer_count = 16,
    .query_count = QUERY_COUNT,
    .maximum_fold_width = 2,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 17,
};
comptime {
    SEGMENT_V2_OUTER_DIMENSIONS.validate();
}
pub const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-segment-v2-outer-admission/v2\x00";

pub const HEAP_ALLOCATIONS_PER_ADMISSION: usize = 1;
pub const LOSSY_V1_PROJECTION_AVAILABLE = false;
pub const PRODUCTION_CAPABILITY = false;

pub const Error = artifact.Error || admission.Error || captured_fri.Error || error{
    ArithmeticOverflow,
    CaptureShapeMismatch,
    DimensionMismatch,
    TranscriptMismatch,
    AuthorityIdentityMismatch,
};

pub const AdmittedSegmentV2ChildV2 = opaque {
    pub fn deinit(self: *AdmittedSegmentV2ChildV2) void {
        const value = storage(self);
        const allocator = value.allocator;
        value.* = undefined;
        allocator.destroy(value);
    }

    pub fn validate(self: *const AdmittedSegmentV2ChildV2) Error!void {
        const value = storageConst(self);
        try artifact.preflight(
            value.capture,
            value.publication,
            value.witness,
            value.manifest,
        );
        const derived_dimensions = try deriveDimensions(value.capture);
        if (!std.meta.eql(derived_dimensions, value.dimensions) or
            !std.meta.eql(derived_dimensions, SEGMENT_V2_OUTER_DIMENSIONS) or
            !std.mem.eql(u8, &value.identity, &authorityIdentity(value)))
        {
            return error.AuthorityIdentityMismatch;
        }
        try validateCaptureAgainstDimensions(value.capture, derived_dimensions);
        try replayTranscript(value.capture, value.witness, value.publication);
    }

    pub fn dimensions(
        self: *const AdmittedSegmentV2ChildV2,
    ) fixed_wire.Dimensions {
        return storageConst(self).dimensions;
    }

    pub fn identity(self: *const AdmittedSegmentV2ChildV2) [32]u8 {
        return storageConst(self).identity;
    }

    pub fn publication(
        self: *const AdmittedSegmentV2ChildV2,
    ) *const artifact.Publication {
        return storageConst(self).publication;
    }

    pub fn capture(
        self: *const AdmittedSegmentV2ChildV2,
    ) *const artifact.OuterProofCapture {
        return storageConst(self).capture;
    }

    pub fn recursiveWitness(
        self: *const AdmittedSegmentV2ChildV2,
    ) *const artifact.RecursiveWitnessV1 {
        return storageConst(self).witness;
    }

    pub fn statementWords(
        self: *const AdmittedSegmentV2ChildV2,
    ) *const StatementWords {
        return &storageConst(self).publication.statement_words;
    }

    pub fn proofId(self: *const AdmittedSegmentV2ChildV2) artifact.Digest {
        return storageConst(self).publication.proof_id;
    }

    pub fn transcriptId(
        self: *const AdmittedSegmentV2ChildV2,
    ) artifact.Digest {
        return storageConst(self).publication.transcript_id;
    }

    pub fn claimedSums(
        self: *const AdmittedSegmentV2ChildV2,
    ) *const [CLAIM_COUNT]QM31 {
        return &storageConst(self).witness.claimed_sums;
    }

    pub fn relationDraws(
        self: *const AdmittedSegmentV2ChildV2,
    ) *const [artifact.RELATION_DRAW_COUNT]QM31 {
        return &storageConst(self).witness.relation_draws;
    }

    pub fn poseidon2Partials(
        self: *const AdmittedSegmentV2ChildV2,
    ) *const [artifact.POSEIDON2_PARTIAL_COUNT]QM31 {
        return &storageConst(self).witness.poseidon2_partials;
    }

    pub fn verifierInputBoundary(
        self: *const AdmittedSegmentV2ChildV2,
    ) QM31 {
        return storageConst(self).witness.outer_admission
            .verifier_input_boundary;
    }

    pub fn wireClosure(
        self: *const AdmittedSegmentV2ChildV2,
    ) [2]QM31 {
        return storageConst(self).witness.outer_admission.wire_closure;
    }

    /// Materializes the independently replayed FRI/PCS arithmetic authority
    /// consumed by recursive rows 20--32. The caller owns the returned value
    /// and must keep exactly one instance per admitted child in pair custody.
    /// Construction copies only verifier-captured values; it never reparses
    /// proof bytes or accepts prover-owned material.
    pub fn initCapturedFriOwned(
        self: *const AdmittedSegmentV2ChildV2,
        allocator: std.mem.Allocator,
    ) Error!captured_fri.Owned {
        try self.validate();
        return captured_fri.Owned.init(
            allocator,
            capturedFriProfileConfig(),
            storageConst(self).capture,
        );
    }

    /// Copies the already admitted capture into the exact fixed payload used
    /// by rows 20--35. All fallible validation occurs before the destination's
    /// first byte changes.
    pub fn fillFixedWireInto(
        self: *const AdmittedSegmentV2ChildV2,
        comptime wire_dimensions: fixed_wire.Dimensions,
        destination: *fixed_wire.FixedStarkProofWire(wire_dimensions),
    ) Error!void {
        wire_dimensions.validate();
        try self.validate();
        const value = storageConst(self);
        if (!std.meta.eql(wire_dimensions, value.dimensions))
            return error.DimensionMismatch;
        populateFixedWireAssumeValid(
            wire_dimensions,
            destination,
            value.capture,
            &value.witness.outer_admission,
        );
    }
};

/// Exact 39-claim profile for the SegmentV2 outer proof. Using
/// `ProfileConfig.fromPcs` here would silently select the frozen 36-claim V1
/// universal roster, so the claim count is deliberately explicit.
pub fn capturedFriProfileConfig() captured_fri.ProfileConfig {
    return .{
        .log_blowup_factor = admission.LOG_BLOWUP_FACTOR,
        .log_last_layer_degree_bound = admission.LOG_LAST_LAYER_DEGREE_BOUND,
        .interaction_pow_bits = admission.INTERACTION_POW_BITS,
        .pcs_pow_bits = admission.PCS_POW_BITS,
        .claimed_sum_count = CLAIM_COUNT,
    };
}

const Storage = struct {
    allocator: std.mem.Allocator,
    publication: *const artifact.Publication,
    capture: *const artifact.OuterProofCapture,
    witness: *const artifact.RecursiveWitnessV1,
    manifest: *const recursion.air.segment_outer_adapter_manifest_v2.Manifest,
    dimensions: fixed_wire.Dimensions,
    identity: [32]u8,
};

/// Sole admission constructor. The returned capability borrows the four
/// verifier artifacts; they must outlive it and remain immutable.
pub fn admitVerifiedSegmentV2ChildV2(
    allocator: std.mem.Allocator,
    publication: *const artifact.Publication,
    capture: *const artifact.OuterProofCapture,
    witness: *const artifact.RecursiveWitnessV1,
    manifest: *const recursion.air.segment_outer_adapter_manifest_v2.Manifest,
) Error!*AdmittedSegmentV2ChildV2 {
    try artifact.preflight(capture, publication, witness, manifest);
    const dimensions = try deriveDimensions(capture);
    if (!std.meta.eql(dimensions, SEGMENT_V2_OUTER_DIMENSIONS))
        return error.DimensionMismatch;
    try validateCaptureAgainstDimensions(capture, dimensions);
    try replayTranscript(capture, witness, publication);
    const result = try allocator.create(Storage);
    errdefer allocator.destroy(result);
    result.* = .{
        .allocator = allocator,
        .publication = publication,
        .capture = capture,
        .witness = witness,
        .manifest = manifest,
        .dimensions = dimensions,
        .identity = undefined,
    };
    result.identity = authorityIdentity(result);
    try @as(*const AdmittedSegmentV2ChildV2, @ptrCast(result)).validate();
    return @ptrCast(result);
}

fn deriveDimensions(
    capture: *const artifact.OuterProofCapture,
) Error!fixed_wire.Dimensions {
    if (capture.commitments.len != TREE_COUNT or
        capture.trace_paths.len != TREE_COUNT or
        capture.column_log_sizes.len != TREE_COUNT or
        capture.queries.raw.len != QUERY_COUNT or
        capture.deep_answers.len != QUERY_COUNT or
        capture.fri.layers.len == 0 or
        capture.last_layer_coefficients.len == 0)
    {
        return error.CaptureShapeMismatch;
    }
    var maximum_depth: usize = 0;
    for (capture.trace_paths) |paths|
        maximum_depth = @max(maximum_depth, paths.path_depth);
    var maximum_fold_width: usize = 0;
    for (capture.fri.layers) |layer| {
        maximum_depth = @max(maximum_depth, layer.path_depth);
        maximum_fold_width = @max(maximum_fold_width, layer.fold_width);
    }
    return .{
        .commitment_count = TREE_COUNT,
        .claimed_sum_count = CLAIM_COUNT,
        .sampled_value_count = capture.sampled_values.len,
        .queried_value_count = capture.queried_values.len,
        .trace_path_count = TREE_COUNT * QUERY_COUNT,
        .fri_layer_count = capture.fri.layers.len,
        .query_count = QUERY_COUNT,
        .maximum_fold_width = maximum_fold_width,
        .last_layer_coefficient_count = capture.last_layer_coefficients.len,
        .maximum_merkle_depth = maximum_depth,
    };
}

fn validateCaptureAgainstDimensions(
    capture: *const artifact.OuterProofCapture,
    dimensions: fixed_wire.Dimensions,
) Error!void {
    if (dimensions.claimed_sum_count != CLAIM_COUNT or
        capture.commitments.len != dimensions.commitment_count or
        capture.sampled_values.len != dimensions.sampled_value_count or
        capture.queried_values.len != dimensions.queried_value_count or
        capture.trace_paths.len * QUERY_COUNT != dimensions.trace_path_count or
        capture.fri.layers.len != dimensions.fri_layer_count or
        capture.last_layer_coefficients.len !=
            dimensions.last_layer_coefficient_count)
    {
        return error.CaptureShapeMismatch;
    }
    for (capture.trace_paths) |paths| {
        if (paths.positions.len != QUERY_COUNT or
            paths.siblings.len != QUERY_COUNT * paths.path_depth or
            paths.path_depth > dimensions.maximum_merkle_depth)
        {
            return error.CaptureShapeMismatch;
        }
    }
    for (capture.fri.layers) |layer| {
        if (layer.query_count != QUERY_COUNT or
            layer.fold_width == 0 or
            layer.fold_width > dimensions.maximum_fold_width or
            layer.positions.len != QUERY_COUNT or
            layer.values.len != QUERY_COUNT * layer.fold_width or
            layer.siblings.len != QUERY_COUNT * layer.path_depth or
            layer.path_depth > dimensions.maximum_merkle_depth)
        {
            return error.CaptureShapeMismatch;
        }
    }
}

fn replayTranscript(
    capture: *const artifact.OuterProofCapture,
    witness: *const artifact.RecursiveWitnessV1,
    publication: *const artifact.Publication,
) Error!void {
    var transcript = recursion.engine.Channel{
        .digest = witness.outer_admission.pre_core_channel.digest,
        .n_draws = witness.outer_admission.pre_core_channel.draw_count,
    };
    if (!transcript.drawSecureFelt().eql(capture.composition_randomness))
        return error.TranscriptMismatch;
    recursion.engine.MerkleChannel.mixRoot(
        &transcript,
        capture.commitments[TREE_COUNT - 1],
    );
    if (!transcript.drawSecureFelt().eql(capture.oods_seed))
        return error.TranscriptMismatch;
    transcript.mixFelts(capture.sampled_values);
    if (!transcript.drawSecureFelt().eql(capture.deep_randomness))
        return error.TranscriptMismatch;
    for (capture.fri.layers) |layer| {
        recursion.engine.MerkleChannel.mixRoot(&transcript, layer.commitment);
        if (!transcript.drawSecureFelt().eql(layer.folding_alpha))
            return error.TranscriptMismatch;
    }
    transcript.mixFelts(capture.last_layer_coefficients);
    if (!transcript.verifyPowNonce(admission.PCS_POW_BITS, capture.proof_of_work))
        return error.TranscriptMismatch;
    transcript.mixU64(capture.proof_of_work);
    const query_words = transcript.drawU32s();
    var query_log: u32 = 0;
    for (capture.trace_paths) |paths| query_log = @max(query_log, paths.path_depth);
    if (query_log >= 32) return error.TranscriptMismatch;
    const mask = (@as(u32, 1) << @intCast(query_log)) - 1;
    for (capture.queries.raw, query_words[0..QUERY_COUNT]) |actual, word|
        if (actual != @as(usize, word & mask))
            return error.TranscriptMismatch;
    const expected = protocol.transcriptId(
        transcript.digestWords(),
        transcript.n_draws,
    );
    if (!std.meta.eql(expected, publication.transcript_id))
        return error.TranscriptMismatch;
}

fn populateFixedWireAssumeValid(
    comptime dimensions: fixed_wire.Dimensions,
    destination: *fixed_wire.FixedStarkProofWire(dimensions),
    capture: *const artifact.OuterProofCapture,
    receipt: *const artifact.OuterAdmissionReceiptV2,
) void {
    @memset(std.mem.asBytes(destination), 0);
    for (capture.commitments, 0..) |value, index|
        destination.commitments[index] = value;
    for (receipt.claimed_sums, 0..) |value, index|
        destination.claimed_sums[index] = qm31Wire(value);
    for (capture.sampled_values, 0..) |value, index|
        destination.sampled_values[index] = qm31Wire(value);
    for (capture.queried_values, 0..) |value, index|
        destination.queried_values[index] = value.toU32();
    for (capture.trace_paths, 0..) |source, tree| {
        for (0..QUERY_COUNT) |query| {
            const target = &destination.trace_paths[tree * QUERY_COUNT + query];
            target.active_depth = source.path_depth;
            for (source.path(query), 0..) |sibling, depth|
                target.siblings[depth] = sibling;
        }
    }
    for (capture.fri.layers, 0..) |source, layer_index| {
        const target = &destination.fri_layers[layer_index];
        target.active_width = source.fold_width;
        target.commitment = source.commitment;
        for (0..QUERY_COUNT) |query| {
            for (source.queryValues(query), 0..) |value, value_index|
                target.queries[query].values[value_index] = qm31Wire(value);
            target.queries[query].path.active_depth = source.path_depth;
            for (source.queryPath(query), 0..) |sibling, depth|
                target.queries[query].path.siblings[depth] = sibling;
        }
    }
    for (capture.last_layer_coefficients, 0..) |value, index|
        destination.last_layer_coefficients[index] = qm31Wire(value);
    destination.interaction_pow = receipt.interaction_pow_nonce;
    destination.pcs_pow = capture.proof_of_work;
}

fn authorityIdentity(value: *const Storage) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(std.mem.asBytes(&value.publication.proof_id));
    hash.update(std.mem.asBytes(&value.publication.capture_id));
    hash.update(std.mem.asBytes(&value.publication.publication_id));
    hash.update(std.mem.asBytes(&value.witness.outer_admission.receipt_id));
    hashInt(&hash, usize, value.dimensions.commitment_count);
    hashInt(&hash, usize, value.dimensions.claimed_sum_count);
    hashInt(&hash, usize, value.dimensions.sampled_value_count);
    hashInt(&hash, usize, value.dimensions.queried_value_count);
    hashInt(&hash, usize, value.dimensions.trace_path_count);
    hashInt(&hash, usize, value.dimensions.fri_layer_count);
    hashInt(&hash, usize, value.dimensions.query_count);
    hashInt(&hash, usize, value.dimensions.maximum_fold_width);
    hashInt(&hash, usize, value.dimensions.last_layer_coefficient_count);
    hashInt(&hash, usize, value.dimensions.maximum_merkle_depth);
    return hash.finalResult();
}

fn qm31Wire(value: QM31) fixed_wire.Qm31Wire {
    const words = value.toM31Array();
    return .{ words[0].toU32(), words[1].toU32(), words[2].toU32(), words[3].toU32() };
}

fn storage(value: *AdmittedSegmentV2ChildV2) *Storage {
    return @ptrCast(@alignCast(value));
}

fn storageConst(value: *const AdmittedSegmentV2ChildV2) *const Storage {
    return @ptrCast(@alignCast(value));
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or TREE_COUNT != 4 or
        QUERY_COUNT != 3 or CLAIM_COUNT != 39 or
        capturedFriProfileConfig().claimed_sum_count != CLAIM_COUNT or
        HEAP_ALLOCATIONS_PER_ADMISSION != 1 or
        LOSSY_V1_PROJECTION_AVAILABLE or PRODUCTION_CAPABILITY)
    {
        @compileError("SegmentV2 outer-admission capability drifted");
    }
    switch (@typeInfo(AdmittedSegmentV2ChildV2)) {
        .@"opaque" => {},
        else => @compileError("SegmentV2 outer admission must remain opaque"),
    }
}
