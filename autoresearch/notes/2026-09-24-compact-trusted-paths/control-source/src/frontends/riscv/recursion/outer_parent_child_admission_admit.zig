//! Internal outer parent child admission authority shard; use outer_parent_child_admission.zig publicly.

const dependency_0 = @import("outer_parent_child_admission_contract.zig");
const dependency_1 = @import("outer_parent_child_admission_binary_pair_candidate_v1.zig");

const BinaryPairCandidateV1 = dependency_1.BinaryPairCandidateV1;
const ByteWriter = dependency_0.ByteWriter;
const CLAIMED_SUM_COUNT = dependency_0.CLAIMED_SUM_COUNT;
const DerivedAdmissionV1 = dependency_0.DerivedAdmissionV1;
const Error = dependency_0.Error;
const FOLD_STEP = dependency_0.FOLD_STEP;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const FixedOuterProofWireV1 = dependency_1.FixedOuterProofWireV1;
const INTERACTION_POW_BITS = dependency_0.INTERACTION_POW_BITS;
const LOG_BLOWUP_FACTOR = dependency_0.LOG_BLOWUP_FACTOR;
const M31 = dependency_0.M31;
const PCS_POW_BITS = dependency_0.PCS_POW_BITS;
const ProofCapture = dependency_0.ProofCapture;
const ProofIdHasher = dependency_0.ProofIdHasher;
const QUERY_COUNT = dependency_0.QUERY_COUNT;
const RECURSIVE_PARENT_PRODUCTION = dependency_0.RECURSIVE_PARENT_PRODUCTION;
const RuntimeAdmissionV1 = dependency_1.RuntimeAdmissionV1;
const ShapeV1 = dependency_0.ShapeV1;
const TREE_COUNT = dependency_0.TREE_COUNT;
const VerifierReceiptV1 = dependency_0.VerifierReceiptV1;
const VerifierSealV1 = dependency_0.VerifierSealV1;
const WIRE_MAGIC = dependency_0.WIRE_MAGIC;
const captureId = dependency_1.captureId;
const channel = dependency_0.channel;
const claimedSumsId = dependency_0.claimedSumsId;
const deriveShape = dependency_1.deriveShape;
const dimensionsEql = dependency_0.dimensionsEql;
const encodeAssumeValid = dependency_1.encodeAssumeValid;
const engine = dependency_0.engine;
const fixed_wire = dependency_0.fixed_wire;
const mapTreeQueryPosition = dependency_1.mapTreeQueryPosition;
const proofIdAssumeValid = dependency_1.proofIdAssumeValid;
const protocol = dependency_0.protocol;
const qm31Wire = dependency_0.qm31Wire;
const receiptId = dependency_1.receiptId;
const replayTranscript = dependency_1.replayTranscript;
const serializedByteCount = dependency_0.serializedByteCount;
const serializedByteCountRuntime = dependency_0.serializedByteCountRuntime;
const slicesOverlap = dependency_1.slicesOverlap;
const std = dependency_0.std;
const validateDigest = dependency_0.validateDigest;
const validateM31 = dependency_1.validateM31;
const validateQm31 = dependency_1.validateQm31;
const validateQuerySet = dependency_1.validateQuerySet;
const validateSampledPoints = dependency_1.validateSampledPoints;

/// Producer-side helper. The trusted outer verifier calls this only after its
/// independent verifier has succeeded and publishes the result together with
/// `capture`. Consumers compare against that published value; they must not
/// call this function to bless untrusted input themselves.
pub fn deriveVerifierSeal(
    receipt: *const VerifierReceiptV1,
    capture: *const ProofCapture,
) Error!VerifierSealV1 {
    return (try deriveAdmission(receipt, capture)).seal;
}

/// Validates first, publishes the caller-owned wire once, and derives the
/// exact pair-child proof identity from its canonical encoding. `destination`
/// remains byte-for-byte unchanged on every error.
///
/// Integration seam for the future complete `recursive_pair_outer`:
///
/// 1. snapshot `pre_core_channel`, the sealed 36-claim vector, the distinct
///    verifier-input boundary, the two-term wire closure,
///    program/manifest/statement/VK identities, and proof scope inside the
///    successful native verifier transaction;
/// 2. publish `VerifierReceiptV1`, `ProofCapture`, and `VerifierSealV1`
///    together, never re-deriving the expected seal at ingress;
/// 3. call `admit` into a generated `FixedOuterProofWireV1` whose comptime
///    dimensions equal the returned profile dimensions;
/// 4. feed `transcriptWire()` plus this candidate's native-outer transcript
///    identity to the binary row source, not leaf V1's frozen transcript plan;
/// 5. permit `verifiedChild` only after the complete parent proof and its
///    independent verifier justify flipping `RECURSIVE_PARENT_PRODUCTION`.
pub fn admit(
    comptime dimensions: fixed_wire.Dimensions,
    destination: *FixedOuterProofWireV1(dimensions),
    encoding_scratch: []u8,
    expected_seal: VerifierSealV1,
    receipt: *const VerifierReceiptV1,
    capture: *const ProofCapture,
) Error!BinaryPairCandidateV1 {
    dimensions.validate();
    try expected_seal.validate();
    const derived = try deriveAdmission(receipt, capture);
    if (!std.meta.eql(derived.seal, expected_seal))
        return error.ProfileSealMismatch;
    if (!dimensionsEql(dimensions, derived.dimensions))
        return error.DimensionMismatch;
    if (encoding_scratch.len != serializedByteCount(dimensions))
        return error.ByteLengthMismatch;
    const destination_bytes = std.mem.asBytes(destination);
    if (slicesOverlap(destination_bytes, encoding_scratch) or
        slicesOverlap(destination_bytes, std.mem.asBytes(receipt)) or
        slicesOverlap(encoding_scratch, std.mem.asBytes(receipt)) or
        captureStorageOverlaps(destination_bytes, capture) or
        captureStorageOverlaps(encoding_scratch, capture))
    {
        return error.AliasedBuffer;
    }

    // All fallible work is complete. Publication and encoding below are
    // infallible over already checked fixed capacities.
    @memset(std.mem.asBytes(destination), 0);
    destination.magic = WIRE_MAGIC;
    destination.format_version = FORMAT_VERSION;
    destination.protocol_id = protocol.PROTOCOL_ID_WORDS;
    destination.profile_id = derived.seal.profile_id;
    destination.capture_id = derived.seal.capture_id;
    destination.receipt_id = derived.seal.receipt_id;
    destination.transcript_id = derived.seal.transcript_id;
    destination.claimed_sums_id = derived.seal.claimed_sums_id;
    destination.verifier_input_boundary = derived.seal.verifier_input_boundary;
    populatePayload(dimensions, &destination.payload, receipt, capture);
    encodeAssumeValid(dimensions, destination, encoding_scratch);

    const candidate = BinaryPairCandidateV1{
        .scope = receipt.scope,
        .shape = derived.shape,
        .dimensions = derived.dimensions,
        .profile_id = derived.seal.profile_id,
        .capture_id = derived.seal.capture_id,
        .receipt_id = derived.seal.receipt_id,
        .transcript_id = derived.seal.transcript_id,
        .claimed_sums_id = derived.seal.claimed_sums_id,
        .verifier_input_boundary = derived.seal.verifier_input_boundary,
        .proof_id = proofIdAssumeValid(dimensions, destination),
        .canonical_wire_bytes = derived.shape.proof_wire_bytes,
    };
    candidate.validate() catch unreachable;
    return candidate;
}

/// Runtime counterpart of `admit` for canonical artifact producers.
///
/// The outer verifier determines column and opening geometry at runtime, so a
/// producer cannot select `FixedOuterProofWireV1` until after successful
/// verification. This entry point validates the verifier receipt, capture,
/// and expected seal first, requires the exact derived byte count, rejects
/// every alias with trusted source storage, and only then writes the canonical
/// fixed-wire encoding. `destination` remains byte-for-byte unchanged on
/// every returned error.
pub fn admitRuntime(
    destination: []u8,
    expected_seal: VerifierSealV1,
    receipt: *const VerifierReceiptV1,
    capture: *const ProofCapture,
) Error!RuntimeAdmissionV1 {
    try expected_seal.validate();
    const derived = try deriveAdmission(receipt, capture);
    if (!std.meta.eql(derived.seal, expected_seal))
        return error.ProfileSealMismatch;

    const canonical_byte_count = try serializedByteCountRuntime(
        derived.dimensions,
    );
    if (destination.len != canonical_byte_count)
        return error.ByteLengthMismatch;
    if (slicesOverlap(destination, std.mem.asBytes(receipt)) or
        captureStorageOverlaps(destination, capture))
    {
        return error.AliasedBuffer;
    }

    // All fallible validation is complete. Encoding the already validated
    // capture into its exact derived capacities is infallible.
    encodeRuntimeAssumeValid(
        destination,
        derived.dimensions,
        derived.seal,
        receipt,
        capture,
    );
    const candidate = BinaryPairCandidateV1{
        .scope = receipt.scope,
        .shape = derived.shape,
        .dimensions = derived.dimensions,
        .profile_id = derived.seal.profile_id,
        .capture_id = derived.seal.capture_id,
        .receipt_id = derived.seal.receipt_id,
        .transcript_id = derived.seal.transcript_id,
        .claimed_sums_id = derived.seal.claimed_sums_id,
        .verifier_input_boundary = derived.seal.verifier_input_boundary,
        .proof_id = protocol.proofId(destination),
        .canonical_wire_bytes = @intCast(canonical_byte_count),
    };
    candidate.validate() catch unreachable;
    const result = RuntimeAdmissionV1{
        .candidate = candidate,
        .canonical_byte_count = canonical_byte_count,
    };
    result.validate() catch unreachable;
    return result;
}

/// Validates the same verifier publication consumed by `admitRuntime` and
/// returns the one admissible destination length. Artifact producers use this
/// before allocation; the subsequent admission repeats validation so no
/// allocation result can become a detached authority token.
pub fn runtimeCanonicalByteCount(
    expected_seal: VerifierSealV1,
    receipt: *const VerifierReceiptV1,
    capture: *const ProofCapture,
) Error!usize {
    try expected_seal.validate();
    const derived = try deriveAdmission(receipt, capture);
    if (!std.meta.eql(derived.seal, expected_seal))
        return error.ProfileSealMismatch;
    return serializedByteCountRuntime(derived.dimensions);
}

/// Allocation-free identity of the exact canonical runtime wire that
/// `admitRuntime` would publish.  This is the verifier-custody comparison seam
/// for consumers that need the proof ID without first allocating or retaining
/// a second byte encoding.  Validation and seal comparison are repeated here;
/// caller-authored capture fields never become proof authority merely because
/// they can be streamed through the hash.
pub fn proofIdRuntime(
    expected_seal: VerifierSealV1,
    receipt: *const VerifierReceiptV1,
    capture: *const ProofCapture,
) Error!channel.Digest {
    try expected_seal.validate();
    const derived = try deriveAdmission(receipt, capture);
    if (!std.meta.eql(derived.seal, expected_seal))
        return error.ProfileSealMismatch;
    return proofIdRuntimeAssumeValid(
        derived.dimensions,
        derived.seal,
        receipt,
        capture,
    );
}

pub fn deriveAdmission(
    receipt: *const VerifierReceiptV1,
    capture: *const ProofCapture,
) Error!DerivedAdmissionV1 {
    try receipt.validate();
    var shape = try deriveShape(receipt, capture);
    const dimensions = try shape.dimensions();
    shape.proof_wire_bytes = try serializedByteCountRuntime(dimensions);
    try shape.validate();
    try validateCaptureAgainstShape(receipt, capture, shape, dimensions);

    const profile_id = try shape.id();
    const capture_id = captureId(capture);
    const claimed_sums_id = claimedSumsId(&receipt.claimed_sums);
    const replay = try replayTranscript(capture, shape, receipt.pre_core_channel);
    const transcript_id = protocol.transcriptId(
        replay.final_digest,
        replay.final_draw_count,
    );
    const receipt_id = receiptId(
        receipt,
        profile_id,
        capture_id,
        transcript_id,
        claimed_sums_id,
    );
    const seal = VerifierSealV1{
        .profile_id = profile_id,
        .capture_id = capture_id,
        .receipt_id = receipt_id,
        .transcript_id = transcript_id,
        .claimed_sums_id = claimed_sums_id,
        .verifier_input_boundary = receipt.verifier_input_boundary,
    };
    try seal.validate();
    return .{
        .shape = shape,
        .dimensions = dimensions,
        .seal = seal,
        .final_channel_digest = replay.final_digest,
        .final_draw_count = replay.final_draw_count,
    };
}

pub fn validateCaptureAgainstShape(
    receipt: *const VerifierReceiptV1,
    capture: *const ProofCapture,
    shape: ShapeV1,
    dimensions: fixed_wire.Dimensions,
) Error!void {
    _ = receipt;
    if (capture.commitments.len != dimensions.commitment_count or
        capture.column_log_sizes.len != TREE_COUNT or
        capture.sampled_points.len != TREE_COUNT or
        capture.sampled_values.len != dimensions.sampled_value_count or
        capture.queried_values.len != dimensions.queried_value_count or
        capture.deep_answers.len != dimensions.query_count or
        capture.trace_paths.len != TREE_COUNT or
        capture.fri.layers.len != dimensions.fri_layer_count or
        capture.last_layer_coefficients.len !=
            dimensions.last_layer_coefficient_count or
        capture.queries.raw.len != dimensions.query_count or
        capture.queries.unique.len == 0 or
        capture.queries.unique.len > capture.queries.raw.len)
    {
        return error.CaptureShapeMismatch;
    }
    try validateQuerySet(
        capture.queries.raw,
        capture.queries.unique,
        shape.column_log_degree + LOG_BLOWUP_FACTOR,
    );
    for (
        capture.trace_paths,
        capture.column_log_sizes,
        shape.tree_heights,
        shape.tree_column_counts,
    ) |paths, logs, tree_height, column_count| {
        if (logs.len != column_count or paths.path_depth != tree_height or
            paths.positions.len != QUERY_COUNT or
            paths.siblings.len != QUERY_COUNT * tree_height)
        {
            return error.CaptureShapeMismatch;
        }
        for (capture.queries.raw, paths.positions) |raw, actual| {
            if (actual != mapTreeQueryPosition(
                raw,
                shape.column_log_degree + LOG_BLOWUP_FACTOR,
                tree_height,
            )) return error.InvalidQuerySchedule;
        }
    }
    var consumed_folds: u32 = 0;
    for (capture.fri.layers, shape.fri.active()) |layer, round| {
        if (layer.fold_step != round.fold_step or
            layer.fold_width != round.fold_width or
            layer.path_depth != round.authentication_path_depth or
            layer.query_count != QUERY_COUNT or
            layer.positions.len != QUERY_COUNT or
            layer.values.len != QUERY_COUNT * round.fold_width or
            layer.siblings.len != QUERY_COUNT * round.authentication_path_depth)
        {
            return error.CaptureShapeMismatch;
        }
        for (capture.queries.raw, layer.positions) |raw, actual| {
            if ((raw >> @intCast(consumed_folds)) != actual)
                return error.InvalidQuerySchedule;
        }
        consumed_folds += round.fold_step;
    }
    try validateSampledPoints(shape, capture);
    for (capture.commitments) |digest| try validateDigest(digest);
    for (capture.sampled_values) |value| try validateQm31(value);
    for (capture.queried_values) |value| try validateM31(value);
    for (capture.deep_answers) |value| try validateQm31(value);
    for (capture.trace_paths) |paths| {
        for (paths.siblings) |digest| try validateDigest(digest);
    }
    for (capture.fri.layers) |layer| {
        try validateDigest(layer.commitment);
        try validateQm31(layer.folding_alpha);
        for (layer.values) |value| try validateQm31(value);
        for (layer.siblings) |digest| try validateDigest(digest);
    }
    for (capture.last_layer_coefficients) |value| try validateQm31(value);
    try validateQm31(capture.composition_randomness);
    try validateQm31(capture.oods_seed);
    try validateQm31(capture.deep_randomness);
}

pub fn populatePayload(
    comptime dimensions: fixed_wire.Dimensions,
    destination: *fixed_wire.FixedStarkProofWire(dimensions),
    receipt: *const VerifierReceiptV1,
    capture: *const ProofCapture,
) void {
    for (capture.commitments, 0..) |value, index|
        destination.commitments[index] = value;
    for (receipt.claimed_sums, 0..) |value, index|
        destination.claimed_sums[index] = value;
    for (capture.sampled_values, 0..) |value, index|
        destination.sampled_values[index] = qm31Wire(value);
    for (capture.queried_values, 0..) |value, index|
        destination.queried_values[index] = value.toU32();
    for (capture.trace_paths, 0..) |paths, tree| {
        const start = tree * QUERY_COUNT;
        for (0..QUERY_COUNT) |query| {
            const target = &destination.trace_paths[start + query];
            target.active_depth = paths.path_depth;
            for (paths.path(query), 0..) |sibling, depth|
                target.siblings[depth] = sibling;
        }
    }
    for (capture.fri.layers, 0..) |source, layer| {
        const target = &destination.fri_layers[layer];
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

/// Encodes the same pointer-free wire layout as `encodeAssumeValid` directly
/// from a verifier-owned runtime capture. Every unused fixed-capacity lane is
/// explicitly zeroed, matching the zero-initialized compile-time wire.
pub fn encodeRuntimeAssumeValid(
    destination: []u8,
    dimensions: fixed_wire.Dimensions,
    seal: VerifierSealV1,
    receipt: *const VerifierReceiptV1,
    capture: *const ProofCapture,
) void {
    var writer = ByteWriter{ .bytes = destination, .at = 0 };
    writer.writeU32(WIRE_MAGIC);
    writer.writeU32(FORMAT_VERSION);
    writer.digest(protocol.PROTOCOL_ID_WORDS);
    writer.digest(seal.profile_id);
    writer.digest(seal.capture_id);
    writer.digest(seal.receipt_id);
    writer.digest(seal.transcript_id);
    writer.digest(seal.claimed_sums_id);
    writer.qm31(seal.verifier_input_boundary);

    for (capture.commitments) |value| writer.digest(value);
    for (receipt.claimed_sums) |value| writer.qm31(value);
    for (capture.sampled_values) |value| writer.qm31(qm31Wire(value));
    for (capture.queried_values) |value| writer.writeU32(value.toU32());

    const zero_digest = [_]u32{0} ** channel.RATE;
    for (capture.trace_paths) |paths| {
        for (0..QUERY_COUNT) |query| {
            writer.writeU32(paths.path_depth);
            const siblings = paths.path(query);
            for (siblings) |sibling| writer.digest(sibling);
            for (siblings.len..dimensions.maximum_merkle_depth) |_|
                writer.digest(zero_digest);
        }
    }

    const zero_qm31 = fixed_wire.Qm31Wire{ 0, 0, 0, 0 };
    for (capture.fri.layers) |layer| {
        writer.writeU32(layer.fold_width);
        writer.digest(layer.commitment);
        for (0..QUERY_COUNT) |query| {
            const values = layer.queryValues(query);
            for (values) |value| writer.qm31(qm31Wire(value));
            for (values.len..dimensions.maximum_fold_width) |_|
                writer.qm31(zero_qm31);
            writer.writeU32(layer.path_depth);
            const siblings = layer.queryPath(query);
            for (siblings) |sibling| writer.digest(sibling);
            for (siblings.len..dimensions.maximum_merkle_depth) |_|
                writer.digest(zero_digest);
        }
    }

    for (capture.last_layer_coefficients) |value|
        writer.qm31(qm31Wire(value));
    writer.writeU64(receipt.interaction_pow_nonce);
    writer.writeU64(capture.proof_of_work);
    std.debug.assert(writer.at == destination.len);
}

pub fn proofIdRuntimeAssumeValid(
    dimensions: fixed_wire.Dimensions,
    seal: VerifierSealV1,
    receipt: *const VerifierReceiptV1,
    capture: *const ProofCapture,
) channel.Digest {
    const byte_count = serializedByteCountRuntime(dimensions) catch unreachable;
    var hash = ProofIdHasher.init(byte_count);
    hash.writeU32(WIRE_MAGIC);
    hash.writeU32(FORMAT_VERSION);
    hash.digest(protocol.PROTOCOL_ID_WORDS);
    hash.digest(seal.profile_id);
    hash.digest(seal.capture_id);
    hash.digest(seal.receipt_id);
    hash.digest(seal.transcript_id);
    hash.digest(seal.claimed_sums_id);
    hash.qm31(seal.verifier_input_boundary);
    for (capture.commitments) |value| hash.digest(value);
    for (receipt.claimed_sums) |value| hash.qm31(value);
    for (capture.sampled_values) |value| hash.qm31(qm31Wire(value));
    for (capture.queried_values) |value| hash.writeU32(value.toU32());

    const zero_digest = [_]u32{0} ** channel.RATE;
    for (capture.trace_paths) |paths| {
        for (0..QUERY_COUNT) |query| {
            hash.writeU32(paths.path_depth);
            const siblings = paths.path(query);
            for (siblings) |sibling| hash.digest(sibling);
            for (siblings.len..dimensions.maximum_merkle_depth) |_|
                hash.digest(zero_digest);
        }
    }

    const zero_qm31 = fixed_wire.Qm31Wire{ 0, 0, 0, 0 };
    for (capture.fri.layers) |layer| {
        hash.writeU32(layer.fold_width);
        hash.digest(layer.commitment);
        for (0..QUERY_COUNT) |query| {
            const values = layer.queryValues(query);
            for (values) |value| hash.qm31(qm31Wire(value));
            for (values.len..dimensions.maximum_fold_width) |_|
                hash.qm31(zero_qm31);
            hash.writeU32(layer.path_depth);
            const siblings = layer.queryPath(query);
            for (siblings) |sibling| hash.digest(sibling);
            for (siblings.len..dimensions.maximum_merkle_depth) |_|
                hash.digest(zero_digest);
        }
    }

    for (capture.last_layer_coefficients) |value|
        hash.qm31(qm31Wire(value));
    hash.writeU64(receipt.interaction_pow_nonce);
    hash.writeU64(capture.proof_of_work);
    return hash.finalize();
}

pub fn captureStorageOverlaps(bytes: []const u8, capture: *const ProofCapture) bool {
    if (slicesOverlap(bytes, std.mem.asBytes(capture)) or
        slicesOverlap(bytes, std.mem.sliceAsBytes(capture.queries.raw)) or
        slicesOverlap(bytes, std.mem.sliceAsBytes(capture.queries.unique)) or
        slicesOverlap(bytes, std.mem.sliceAsBytes(capture.commitments)) or
        slicesOverlap(bytes, std.mem.sliceAsBytes(capture.column_log_sizes)) or
        slicesOverlap(bytes, std.mem.sliceAsBytes(capture.sampled_points)) or
        slicesOverlap(bytes, std.mem.sliceAsBytes(capture.sampled_values)) or
        slicesOverlap(bytes, std.mem.sliceAsBytes(capture.queried_values)) or
        slicesOverlap(bytes, std.mem.sliceAsBytes(capture.deep_answers)) or
        slicesOverlap(bytes, std.mem.sliceAsBytes(capture.trace_paths)) or
        slicesOverlap(bytes, std.mem.sliceAsBytes(capture.fri.layers)) or
        slicesOverlap(
            bytes,
            std.mem.sliceAsBytes(capture.last_layer_coefficients),
        ))
    {
        return true;
    }
    for (capture.column_log_sizes) |logs| {
        if (slicesOverlap(bytes, std.mem.sliceAsBytes(logs))) return true;
    }
    for (capture.sampled_points) |columns| {
        if (slicesOverlap(bytes, std.mem.sliceAsBytes(columns))) return true;
        for (columns) |points| {
            if (slicesOverlap(bytes, std.mem.sliceAsBytes(points))) return true;
        }
    }
    for (capture.trace_paths) |paths| {
        if (slicesOverlap(bytes, std.mem.sliceAsBytes(paths.positions)) or
            slicesOverlap(bytes, std.mem.sliceAsBytes(paths.siblings)))
        {
            return true;
        }
    }
    for (capture.fri.layers) |layer| {
        if (slicesOverlap(bytes, std.mem.sliceAsBytes(layer.positions)) or
            slicesOverlap(bytes, std.mem.sliceAsBytes(layer.values)) or
            slicesOverlap(bytes, std.mem.sliceAsBytes(layer.siblings)))
        {
            return true;
        }
    }
    return false;
}

comptime {
    if (QUERY_COUNT != 3 or PCS_POW_BITS != 0 or
        INTERACTION_POW_BITS != 0 or FOLD_STEP != 1 or
        CLAIMED_SUM_COUNT != 36 or TREE_COUNT != 4)
    {
        @compileError("outer recursive-parent profile drifted from OUTER_CONFIG");
    }
    if (engine.Hasher.Hash != channel.Digest)
        @compileError("outer child admission requires Poseidon2-M31 captures");
}
