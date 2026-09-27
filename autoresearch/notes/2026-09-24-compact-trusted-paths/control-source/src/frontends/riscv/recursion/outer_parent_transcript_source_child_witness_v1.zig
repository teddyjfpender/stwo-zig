//! Internal outer parent transcript source authority shard; use outer_parent_transcript_source.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const admission = @import("outer_parent_child_admission.zig");
pub const channel = @import("poseidon2_channel.zig");
pub const engine = @import("engine.zig");
pub const fixed_wire = @import("fixed_wire.zig");
pub const pair_node = @import("pair_node.zig");
pub const protocol = @import("protocol.zig");
pub const span_statement = @import("span_statement.zig");
pub const roster = @import("air/universal_roster.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SOURCE_ID_DOMAIN: u32 = 0x4f50_5453; // "OPTS"
pub const CHILD_COUNT: usize = 2;
pub const CLAIM_ROW_COUNT: usize = roster.COMPONENT_COUNT;
pub const QUERY_COUNT: usize = admission.QUERY_COUNT;
pub const MAX_FRI_ROUNDS: usize = admission.MAX_FRI_ROUNDS;

/// This source closes transcript custody only.  The value is intentionally a
/// distinct enum rather than a boolean that a caller could reinterpret.
pub const ProductionStatus = enum(u8) {
    verifier_subsystem_only = 1,
};

pub const CURRENT_STATUS: ProductionStatus = .verifier_subsystem_only;
pub const COMPLETE_PARENT_PROOF_VERIFIED = false;
pub const HEAP_ALLOCATIONS_PER_PREPARE: usize = 0;

pub const ProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(engine.Hasher);

pub const Error = admission.Error || pair_node.Error || span_statement.Error || error{
    AliasedWorkspace,
    BundleSealMismatch,
    ChildBindingMismatch,
    ChildOrderMismatch,
    ChildProfileMismatch,
    DuplicateChild,
    PreparedWitnessMismatch,
    ProductionStatusMismatch,
    TranscriptCaptureMismatch,
    UniversalClaimMismatch,
};

/// The exact universal claim schedule authenticated by one outer verifier.
/// Array index is the `universal_roster.Component` discriminant.
pub const UniversalClaimsV1 = struct {
    component_log_sizes: [CLAIM_ROW_COUNT]u32,
    claimed_sums: [CLAIM_ROW_COUNT]QM31,
    wire_closure: [2]QM31,

    pub fn logSize(self: *const UniversalClaimsV1, component: roster.Component) u32 {
        return self.component_log_sizes[@intFromEnum(component)];
    }

    pub fn claimedSum(self: *const UniversalClaimsV1, component: roster.Component) QM31 {
        return self.claimed_sums[@intFromEnum(component)];
    }

    pub fn validate(self: *const UniversalClaimsV1) Error!void {
        for (self.component_log_sizes) |log_size| {
            if (log_size < 4 or log_size > admission.MAX_DOMAIN_LOG)
                return error.ChildProfileMismatch;
        }
        for (self.claimed_sums) |value| try validateQm31(value);
        for (self.wire_closure) |value| try validateQm31(value);
    }
};

/// Every verifier-derived core continuation value required by later typed AIR
/// witnesses.  FRI alpha padding is canonical zero beyond `fri_round_count`.
pub const CoreReplayV1 = struct {
    composition_randomness: QM31,
    oods_seed: QM31,
    deep_randomness: QM31,
    fri_round_count: u32,
    fri_alphas: [MAX_FRI_ROUNDS]QM31,
    raw_queries: [QUERY_COUNT]u32,
    final_digest: channel.Digest,
    final_draw_count: u32,

    pub fn activeFriAlphas(self: *const CoreReplayV1) []const QM31 {
        return self.fri_alphas[0..self.fri_round_count];
    }

    pub fn validate(self: *const CoreReplayV1) Error!void {
        if (self.fri_round_count == 0 or
            self.fri_round_count > self.fri_alphas.len)
        {
            return error.TranscriptCaptureMismatch;
        }
        try validateQm31(self.composition_randomness);
        try validateQm31(self.oods_seed);
        try validateQm31(self.deep_randomness);
        for (self.activeFriAlphas()) |value| try validateQm31(value);
        for (self.fri_alphas[self.fri_round_count..]) |value| {
            if (!value.isZero()) return error.TranscriptCaptureMismatch;
        }
        try requireDigest(self.final_digest);
        if (self.final_draw_count != 1)
            return error.TranscriptCaptureMismatch;
    }
};

/// Checked cost ledger for the allocation-free hot path.  Pair-node format
/// validation is a cold trust-boundary cost and is intentionally reported
/// separately from the exact core transcript continuation.
pub const PerformanceCountsV1 = struct {
    roster_rows: usize,
    claimed_sum_values: usize,
    sampled_value_words: usize,
    fri_rounds: usize,
    transcript_operations: usize,
    transcript_state_permutations: usize,
    pow_candidate_permutations: usize,
    source_identity_permutations: usize,
    retained_witness_bytes: usize,
    heap_allocations: usize = HEAP_ALLOCATIONS_PER_PREPARE,

    pub fn totalExecutedPermutations(self: PerformanceCountsV1) usize {
        return self.transcript_state_permutations +
            self.pow_candidate_permutations +
            self.source_identity_permutations;
    }
};

pub const BoundContextV1 = struct {
    session_id: channel.Digest,
    job_id: channel.Digest,
    challenge_context_id: channel.Digest,
    authority_context_id: channel.Digest,
    parent_vk_id: channel.Digest,
    execution_statement_id: channel.Digest,
    public_call_commitment: channel.Digest,
    pair_index: u32,
    session_leaf_count: u32,
    event_count: u64,

    pub fn validate(self: *const BoundContextV1) Error!void {
        try requireDigest(self.session_id);
        try requireDigest(self.job_id);
        try requireDigest(self.challenge_context_id);
        try requireDigest(self.authority_context_id);
        try requireDigest(self.parent_vk_id);
        try requireDigest(self.execution_statement_id);
        try requireDigest(self.public_call_commitment);
        protocol.validateEventCount(self.event_count) catch
            return error.ChildBindingMismatch;
        if (self.session_leaf_count < CHILD_COUNT or
            self.session_leaf_count > pair_node.MAX_KAPPA or
            !std.math.isPowerOfTwo(self.session_leaf_count) or
            self.pair_index >= self.session_leaf_count / CHILD_COUNT)
        {
            return error.ChildBindingMismatch;
        }
        if (self.event_count == 0) {
            if (!std.meta.eql(
                self.public_call_commitment,
                protocol.emptyCallCommitment(),
            )) return error.ChildBindingMismatch;
        } else if (std.meta.eql(
            self.public_call_commitment,
            protocol.emptyCallCommitment(),
        )) {
            return error.ChildBindingMismatch;
        }
        const verifier_context = self.verifierContext();
        if (!std.meta.eql(
            self.challenge_context_id,
            challengeContextId(self.session_id),
        ) or !std.meta.eql(
            self.authority_context_id,
            authorityContextId(&verifier_context),
        )) return error.ChildBindingMismatch;
    }

    fn verifierContext(self: *const BoundContextV1) pair_node.VerifierContextV1 {
        return .{
            .session_id = self.session_id,
            .job_id = self.job_id,
            .execution_statement_id = self.execution_statement_id,
            .public_call_commitment = self.public_call_commitment,
            .event_count = self.event_count,
            .session_leaf_count = self.session_leaf_count,
            .pair_index = self.pair_index,
            .aggregator_vk_id = self.parent_vk_id,
        };
    }
};

pub const ChildWitnessV1 = struct {
    position: pair_node.ChildPosition,
    role: pair_node.ChildRole,
    leaf_index: u32,
    pair_index: u32,
    session_id: channel.Digest,
    parent_vk_id: channel.Digest,
    statement_id: channel.Digest,
    /// Exact canonical preimage published transactionally by the successful
    /// native verifier. This is copied into the retained witness so no caller
    /// can substitute words after custody admission.
    statement_words: span_statement.StatementWords,
    summary_id: channel.Digest,
    event_count: u64,
    signed_relation_total: pair_node.SecureFelt,

    shape: admission.ShapeV1,
    profile_id: channel.Digest,
    capture_id: channel.Digest,
    receipt_id: channel.Digest,
    proof_id: channel.Digest,
    transcript_id: channel.Digest,
    claimed_sums_id: channel.Digest,
    /// Exact verifier-input public boundary published by the successful
    /// native verifier. It is not derived from or folded into `wire_closure`.
    verifier_input_boundary: QM31,
    preprocessed_root: channel.Digest,
    universal: UniversalClaimsV1,
    replay: CoreReplayV1,

    pub fn validate(self: *const ChildWitnessV1) Error!void {
        try self.shape.validate();
        try requireDigest(self.session_id);
        try requireDigest(self.parent_vk_id);
        try requireDigest(self.statement_id);
        const statement_id = try statementId(&self.statement_words);
        try requireDigest(self.summary_id);
        try requireDigest(self.profile_id);
        try requireDigest(self.capture_id);
        try requireDigest(self.receipt_id);
        try requireDigest(self.proof_id);
        try requireDigest(self.transcript_id);
        try requireDigest(self.claimed_sums_id);
        try validateQm31(self.verifier_input_boundary);
        try requireDigest(self.preprocessed_root);
        self.signed_relation_total.validate() catch
            return error.ChildBindingMismatch;
        try self.universal.validate();
        try self.replay.validate();
        if (!std.meta.eql(statement_id, self.statement_id) or
            !std.meta.eql(self.profile_id, try self.shape.id()) or
            !std.meta.eql(self.statement_id, self.shape.statement_id) or
            !std.meta.eql(self.parent_vk_id, self.shape.verification_key_id) or
            (self.event_count == 0 and !self.signed_relation_total.isZero()) or
            !std.meta.eql(
                self.transcript_id,
                protocol.transcriptId(
                    self.replay.final_digest,
                    self.replay.final_draw_count,
                ),
            ))
        {
            return error.ChildBindingMismatch;
        }
    }
};

pub fn ChildBundle(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    return struct {
        capture: *const ProofCapture,
        receipt: *const admission.VerifierReceiptV1,
        seal: admission.VerifierSealV1,
        statement_words: *const span_statement.StatementWords,
        wire: *const admission.FixedOuterProofWireV1(dimensions),
        candidate: *const admission.BinaryPairCandidateV1,
        binding: admission.PairChildInputsV1,
    };
}

pub const PairInputsV1 = struct {
    context: pair_node.VerifierContextV1,
    root_pin: pair_node.RootVkPinV1,
};

pub fn preflightBundle(
    comptime dimensions: fixed_wire.Dimensions,
    bundle: ChildBundle(dimensions),
) Error!void {
    try bundle.receipt.validate();
    try bundle.seal.validate();
    try bundle.candidate.validate();
    const statement_id = try statementId(bundle.statement_words);
    if (bundle.receipt.scope != .verifier_subsystem or
        bundle.candidate.scope != .verifier_subsystem or
        bundle.candidate.dimensions.query_count != QUERY_COUNT or
        bundle.candidate.dimensions.claimed_sum_count != CLAIM_ROW_COUNT)
    {
        return error.ProductionStatusMismatch;
    }
    if (!std.meta.eql(statement_id, bundle.receipt.statement_id) or
        !std.meta.eql(statement_id, bundle.candidate.shape.statement_id) or
        !std.meta.eql(statement_id, bundle.binding.statement_id))
    {
        return error.ChildBindingMismatch;
    }
    const derived = try admission.deriveVerifierSeal(
        bundle.receipt,
        bundle.capture,
    );
    if (!std.meta.eql(derived, bundle.seal) or
        !sealMatchesCandidate(bundle.seal, bundle.candidate.*))
    {
        return error.BundleSealMismatch;
    }
}

pub fn bindContext(pair_inputs: PairInputsV1) Error!BoundContextV1 {
    try pair_inputs.context.validate();
    // Context validation above already checks the immutable pair-node suite.
    // Rechecking the root-pin payload locally avoids paying that cold suite
    // seal a second time on every source construction.
    try validateRootPinAfterContext(pair_inputs.root_pin);
    if (!std.meta.eql(
        pair_inputs.context.aggregator_vk_id,
        pair_inputs.root_pin.expected_aggregator_vk_id,
    )) return error.ChildBindingMismatch;

    return .{
        .session_id = pair_inputs.context.session_id,
        .job_id = pair_inputs.context.job_id,
        .challenge_context_id = challengeContextId(pair_inputs.context.session_id),
        .authority_context_id = authorityContextId(&pair_inputs.context),
        .parent_vk_id = pair_inputs.context.aggregator_vk_id,
        .execution_statement_id = pair_inputs.context.execution_statement_id,
        .public_call_commitment = pair_inputs.context.public_call_commitment,
        .pair_index = pair_inputs.context.pair_index,
        .session_leaf_count = pair_inputs.context.session_leaf_count,
        .event_count = pair_inputs.context.event_count,
    };
}

pub fn replayCore(
    comptime dimensions: fixed_wire.Dimensions,
    receipt: *const admission.VerifierReceiptV1,
    candidate: *const admission.BinaryPairCandidateV1,
    capture: *const ProofCapture,
    proof: *const fixed_wire.FixedStarkProofWire(dimensions),
) Error!CoreReplayV1 {
    try receipt.pre_core_channel.validate();
    var transcript = channel.Channel{
        .digest = receipt.pre_core_channel.digest,
        .n_draws = receipt.pre_core_channel.draw_count,
    };
    const composition_randomness = transcript.drawSecureFelt();
    if (!composition_randomness.eql(capture.composition_randomness))
        return error.TranscriptCaptureMismatch;

    engine.MerkleChannel.mixRoot(
        &transcript,
        proof.commitments[admission.TREE_COUNT - 1],
    );
    const oods_seed = transcript.drawSecureFelt();
    if (!oods_seed.eql(capture.oods_seed))
        return error.TranscriptCaptureMismatch;

    try mixQm31Wires(&transcript, &proof.sampled_values);
    const deep_randomness = transcript.drawSecureFelt();
    if (!deep_randomness.eql(capture.deep_randomness))
        return error.TranscriptCaptureMismatch;

    var fri_alphas = [_]QM31{QM31.zero()} ** MAX_FRI_ROUNDS;
    for (proof.fri_layers, capture.fri.layers, 0..) |layer, captured, index| {
        engine.MerkleChannel.mixRoot(&transcript, layer.commitment);
        fri_alphas[index] = transcript.drawSecureFelt();
        if (!fri_alphas[index].eql(captured.folding_alpha))
            return error.TranscriptCaptureMismatch;
    }
    try mixQm31Wires(&transcript, &proof.last_layer_coefficients);
    if (!transcript.verifyPowNonce(admission.PCS_POW_BITS, proof.pcs_pow))
        return error.TranscriptCaptureMismatch;
    transcript.mixU64(proof.pcs_pow);

    const query_words = transcript.drawU32s();
    const query_log = std.math.add(
        u32,
        candidate.shape.column_log_degree,
        admission.LOG_BLOWUP_FACTOR,
    ) catch return error.TranscriptCaptureMismatch;
    if (query_log >= 32) return error.TranscriptCaptureMismatch;
    const mask = (@as(u32, 1) << @intCast(query_log)) - 1;
    var raw_queries: [QUERY_COUNT]u32 = undefined;
    for (&raw_queries, capture.queries.raw, query_words[0..QUERY_COUNT]) |
        *target,
        captured,
        word,
    | {
        target.* = word & mask;
        if (captured != target.*) return error.TranscriptCaptureMismatch;
    }
    const final_digest = transcript.digestWords();
    const transcript_id = protocol.transcriptId(final_digest, transcript.n_draws);
    if (!std.meta.eql(transcript_id, candidate.transcript_id))
        return error.TranscriptCaptureMismatch;

    return .{
        .composition_randomness = composition_randomness,
        .oods_seed = oods_seed,
        .deep_randomness = deep_randomness,
        .fri_round_count = @intCast(proof.fri_layers.len),
        .fri_alphas = fri_alphas,
        .raw_queries = raw_queries,
        .final_digest = final_digest,
        .final_draw_count = transcript.n_draws,
    };
}

pub fn validateTranscriptPayloadParity(
    comptime dimensions: fixed_wire.Dimensions,
    capture: *const ProofCapture,
    proof: *const fixed_wire.FixedStarkProofWire(dimensions),
) Error!void {
    if (capture.commitments.len != proof.commitments.len or
        capture.sampled_values.len != proof.sampled_values.len or
        capture.fri.layers.len != proof.fri_layers.len or
        capture.last_layer_coefficients.len != proof.last_layer_coefficients.len or
        capture.proof_of_work != proof.pcs_pow or proof.interaction_pow != 0)
    {
        return error.TranscriptCaptureMismatch;
    }
    for (capture.commitments, proof.commitments) |captured, wired| {
        if (!std.meta.eql(captured, wired))
            return error.TranscriptCaptureMismatch;
    }
    for (capture.sampled_values, proof.sampled_values) |captured, wired| {
        if (!captured.eql(try qm31FromWire(wired)))
            return error.TranscriptCaptureMismatch;
    }
    for (capture.fri.layers, proof.fri_layers) |captured, wired| {
        if (!std.meta.eql(captured.commitment, wired.commitment))
            return error.TranscriptCaptureMismatch;
    }
    for (capture.last_layer_coefficients, proof.last_layer_coefficients) |
        captured,
        wired,
    | {
        if (!captured.eql(try qm31FromWire(wired)))
            return error.TranscriptCaptureMismatch;
    }
}

pub fn mixQm31Wires(transcript: *channel.Channel, values: anytype) Error!void {
    // Same sponge frame as Channel.mixFelts, streamed from fixed wire words so
    // no payload-sized temporary allocation or stack array is required.
    var hasher = channel.CanonicalWordHasher.init(0);
    var digest_words: [channel.RATE]M31 = undefined;
    for (&digest_words, transcript.digestWords()) |*target, word|
        target.* = try canonical(word);
    hasher.update(&digest_words);
    for (values) |value| {
        var words: [4]M31 = undefined;
        for (&words, value) |*target, word| target.* = try canonical(word);
        hasher.update(&words);
    }
    transcript.digest = hasher.finalize();
    transcript.n_draws = 0;
}

pub fn challengeContextId(session_id: channel.Digest) channel.Digest {
    var words: [channel.RATE * 3]u32 = undefined;
    @memcpy(words[0..channel.RATE], &session_id);
    @memcpy(words[channel.RATE..][0..channel.RATE], &protocol.PROTOCOL_ID_WORDS);
    @memcpy(
        words[2 * channel.RATE ..][0..channel.RATE],
        &protocol.RELATION_DOMAIN_ID_WORDS,
    );
    return channel.hashCanonicalU32s(&words, protocol.CHALLENGE_CONTEXT_ID_DOMAIN);
}

pub fn authorityContextId(context: *const pair_node.VerifierContextV1) channel.Digest {
    const challenge = challengeContextId(context.session_id);
    var words: [96]u32 = undefined;
    var at: usize = 0;
    appendDigest(&words, &at, pair_node.FORMAT_ID_WORDS);
    appendDigest(&words, &at, protocol.PROTOCOL_ID_WORDS);
    appendDigest(&words, &at, protocol.RELATION_DOMAIN_ID_WORDS);
    appendDigest(&words, &at, context.session_id);
    appendDigest(&words, &at, challenge);
    appendDigest(&words, &at, context.job_id);
    appendDigest(&words, &at, context.execution_statement_id);
    appendDigest(&words, &at, context.public_call_commitment);
    appendDigest(&words, &at, context.aggregator_vk_id);
    appendWord(&words, &at, context.session_leaf_count);
    appendWord(&words, &at, context.pair_index);
    appendU64(&words, &at, context.event_count);
    return channel.hashCanonicalU32s(words[0..at], pair_node.AUTHORITY_CONTEXT_DOMAIN);
}

pub fn validateRootPinAfterContext(pin: pair_node.RootVkPinV1) Error!void {
    try requireDigest(pin.format_id);
    try requireDigest(pin.protocol_id);
    try requireDigest(pin.expected_aggregator_vk_id);
    if (!std.meta.eql(pin.format_id, pair_node.FORMAT_ID_WORDS) or
        !std.meta.eql(pin.protocol_id, protocol.PROTOCOL_ID_WORDS))
    {
        return error.ChildBindingMismatch;
    }
}

pub fn sealMatchesCandidate(
    seal: admission.VerifierSealV1,
    candidate: admission.BinaryPairCandidateV1,
) bool {
    return std.meta.eql(seal.profile_id, candidate.profile_id) and
        std.meta.eql(seal.capture_id, candidate.capture_id) and
        std.meta.eql(seal.receipt_id, candidate.receipt_id) and
        std.meta.eql(seal.transcript_id, candidate.transcript_id) and
        std.meta.eql(seal.claimed_sums_id, candidate.claimed_sums_id) and
        std.meta.eql(
            seal.verifier_input_boundary,
            candidate.verifier_input_boundary,
        );
}

pub fn qm31FromWire(value: fixed_wire.Qm31Wire) Error!QM31 {
    for (value) |word| _ = try canonical(word);
    return QM31.fromU32Unchecked(value[0], value[1], value[2], value[3]);
}

pub fn validateQm31(value: QM31) Error!void {
    for (value.toM31Array()) |word| _ = try canonical(word.toU32());
}

pub fn requireDigest(value: channel.Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        _ = try canonical(word);
        aggregate |= word;
    }
    if (aggregate == 0) return error.ChildBindingMismatch;
}

pub fn canonical(value: u32) Error!M31 {
    if (value >= stwo_core.fields.m31.Modulus)
        return error.TranscriptCaptureMismatch;
    return M31.fromCanonical(value);
}

pub fn statementId(
    words: *const span_statement.StatementWords,
) Error!channel.Digest {
    _ = try span_statement.SpanStatement.fromCanonicalWords(words);
    var canonical_words: [span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 =
        undefined;
    for (words, &canonical_words) |word, *target| {
        const value = word.toU32();
        if (value >= stwo_core.fields.m31.Modulus)
            return error.CanonicalWordNonCanonical;
        target.* = value;
    }
    return protocol.statementId(&canonical_words);
}

pub fn appendWord(words: []u32, at: *usize, value: u32) void {
    words[at.*] = value;
    at.* += 1;
}

pub fn appendDigest(words: []u32, at: *usize, value: channel.Digest) void {
    @memcpy(words[at.*..][0..channel.RATE], &value);
    at.* += channel.RATE;
}

pub fn appendU64(words: []u32, at: *usize, value: u64) void {
    appendWord(words, at, @truncate(value & 0xffff));
    appendWord(words, at, @truncate((value >> 16) & 0xffff));
    appendWord(words, at, @truncate((value >> 32) & 0xffff));
    appendWord(words, at, @truncate(value >> 48));
}
