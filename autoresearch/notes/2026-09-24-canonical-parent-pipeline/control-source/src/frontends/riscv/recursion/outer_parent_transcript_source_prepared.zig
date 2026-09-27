//! Internal outer parent transcript source authority shard; use outer_parent_transcript_source.zig publicly.

const dependency_0 = @import("outer_parent_transcript_source_child_witness_v1.zig");

const BoundContextV1 = dependency_0.BoundContextV1;
const CHILD_COUNT = dependency_0.CHILD_COUNT;
const CLAIM_ROW_COUNT = dependency_0.CLAIM_ROW_COUNT;
const COMPLETE_PARENT_PROOF_VERIFIED = dependency_0.COMPLETE_PARENT_PROOF_VERIFIED;
const CURRENT_STATUS = dependency_0.CURRENT_STATUS;
const ChildBundle = dependency_0.ChildBundle;
const ChildWitnessV1 = dependency_0.ChildWitnessV1;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const M31 = dependency_0.M31;
const PairInputsV1 = dependency_0.PairInputsV1;
const PerformanceCountsV1 = dependency_0.PerformanceCountsV1;
const ProductionStatus = dependency_0.ProductionStatus;
const ProofCapture = dependency_0.ProofCapture;
const QM31 = dependency_0.QM31;
const QUERY_COUNT = dependency_0.QUERY_COUNT;
const SOURCE_ID_DOMAIN = dependency_0.SOURCE_ID_DOMAIN;
const UniversalClaimsV1 = dependency_0.UniversalClaimsV1;
const admission = dependency_0.admission;
const bindContext = dependency_0.bindContext;
const channel = dependency_0.channel;
const fixed_wire = dependency_0.fixed_wire;
const pair_node = dependency_0.pair_node;
const preflightBundle = dependency_0.preflightBundle;
const protocol = dependency_0.protocol;
const qm31FromWire = dependency_0.qm31FromWire;
const replayCore = dependency_0.replayCore;
const requireDigest = dependency_0.requireDigest;
const std = dependency_0.std;
const stwo_core = dependency_0.stwo_core;
const validateTranscriptPayloadParity = dependency_0.validateTranscriptPayloadParity;

pub fn Prepared(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    const Bundle = ChildBundle(dimensions);

    return struct {
        format_version: u16 = FORMAT_VERSION,
        status: ProductionStatus = CURRENT_STATUS,
        context: BoundContextV1,
        children: [CHILD_COUNT]ChildWitnessV1,
        source_id: channel.Digest,
        performance: PerformanceCountsV1,

        const Self = @This();

        pub fn productionReady(_: *const Self) bool {
            return COMPLETE_PARENT_PROOF_VERIFIED;
        }

        /// Publishes `destination` once, after every bundle, transcript,
        /// ordering, session, profile, and VK check has succeeded.  The
        /// caller-provided encoding scratch may be overwritten; destination
        /// is byte-for-byte unchanged on every error.
        pub fn prepareInto(
            destination: *Self,
            encoding_scratch: []u8,
            pair_inputs: PairInputsV1,
            bundles: [CHILD_COUNT]Bundle,
        ) Error!void {
            try preflightAliases(Self, destination, encoding_scratch, pair_inputs, bundles);
            const context = try bindContext(pair_inputs);

            // Seal/capture custody is checked for both children before the
            // reusable encoding workspace can alter any caller-owned bytes.
            for (bundles) |bundle| try preflightBundle(dimensions, bundle);
            for (bundles) |bundle| {
                try bundle.wire.validateAgainst(
                    bundle.candidate,
                    encoding_scratch,
                );
            }

            var children: [CHILD_COUNT]ChildWitnessV1 = undefined;
            for (&children, bundles, 0..) |*child, bundle, index| {
                child.* = try deriveChild(dimensions, context, bundle, index);
            }
            try validatePair(context, &children);

            var staged = Self{
                .context = context,
                .children = children,
                .source_id = undefined,
                .performance = undefined,
            };
            const identity = sourceIdentity(&staged);
            staged.source_id = identity.digest;
            staged.performance = performanceCounts(
                dimensions,
                &staged,
                identity.permutations,
            );
            try staged.validate();
            destination.* = staged;
        }

        /// Allocation-free revalidation against the complete custody bundle.
        pub fn validateAgainst(
            self: *const Self,
            encoding_scratch: []u8,
            pair_inputs: PairInputsV1,
            bundles: [CHILD_COUNT]Bundle,
        ) Error!void {
            if (byteSlicesOverlap(std.mem.asBytes(self), encoding_scratch))
                return error.AliasedWorkspace;
            var expected: Self = undefined;
            try Self.prepareInto(
                &expected,
                encoding_scratch,
                pair_inputs,
                bundles,
            );
            if (!std.meta.eql(self.*, expected))
                return error.PreparedWitnessMismatch;
        }

        pub fn validate(self: *const Self) Error!void {
            if (self.format_version != FORMAT_VERSION or
                self.status != CURRENT_STATUS or self.productionReady())
            {
                return error.ProductionStatusMismatch;
            }
            try self.context.validate();
            for (&self.children) |*child| try child.validate();
            try validatePair(self.context, &self.children);
            const identity = sourceIdentity(self);
            const expected_performance = performanceCounts(
                dimensions,
                self,
                identity.permutations,
            );
            if (!std.meta.eql(identity.digest, self.source_id) or
                !std.meta.eql(expected_performance, self.performance))
            {
                return error.PreparedWitnessMismatch;
            }
        }
    };
}

pub fn deriveChild(
    comptime dimensions: fixed_wire.Dimensions,
    context: BoundContextV1,
    bundle: ChildBundle(dimensions),
    index: usize,
) Error!ChildWitnessV1 {
    const candidate = bundle.candidate;
    const receipt = bundle.receipt;
    const proof = bundle.wire.transcriptWire();
    const expected_position: pair_node.ChildPosition = if (index == 0) .left else .right;
    const expected_role: pair_node.ChildRole = if (index == 0)
        .core_request
    else
        .poseidon2_provider;
    const expected_leaf = std.math.add(
        u32,
        std.math.mul(u32, context.pair_index, 2) catch
            return error.ChildBindingMismatch,
        @intCast(index),
    ) catch return error.ChildBindingMismatch;
    const binding = bundle.binding;
    if (binding.position != expected_position or
        binding.role != expected_role or
        binding.leaf_index != expected_leaf or
        binding.pair_index != context.pair_index or
        binding.leaf_count != 1 or
        !std.meta.eql(binding.session_id, context.session_id) or
        !std.meta.eql(binding.challenge_context_id, context.challenge_context_id) or
        !std.meta.eql(binding.authority_context_id, context.authority_context_id) or
        !std.meta.eql(binding.parent_vk_id, context.parent_vk_id) or
        !std.meta.eql(binding.parent_vk_id, candidate.shape.verification_key_id) or
        !std.meta.eql(binding.statement_id, candidate.shape.statement_id) or
        binding.event_count != context.event_count)
    {
        return if (binding.position != expected_position)
            error.ChildOrderMismatch
        else
            error.ChildBindingMismatch;
    }
    try requireDigest(binding.summary_id);
    binding.signed_relation_total.validate() catch
        return error.ChildBindingMismatch;

    if (!std.meta.eql(receipt.air_program_id, candidate.shape.air_program_id) or
        !std.meta.eql(receipt.manifest_id, candidate.shape.manifest_id) or
        !std.meta.eql(receipt.statement_id, candidate.shape.statement_id) or
        !std.meta.eql(
            receipt.verification_key_id,
            candidate.shape.verification_key_id,
        ) or
        !std.meta.eql(receipt.component_log_sizes, candidate.shape.component_log_sizes))
    {
        return error.BundleSealMismatch;
    }

    var universal = UniversalClaimsV1{
        .component_log_sizes = receipt.component_log_sizes,
        .claimed_sums = undefined,
        .wire_closure = undefined,
    };
    for (&universal.claimed_sums, receipt.claimed_sums, proof.claimed_sums) |
        *target,
        trusted,
        wired,
    | {
        if (!std.meta.eql(trusted, wired))
            return error.UniversalClaimMismatch;
        target.* = try qm31FromWire(wired);
    }
    for (&universal.wire_closure, receipt.wire_closure) |*target, value|
        target.* = try qm31FromWire(value);
    try universal.validate();

    try validateTranscriptPayloadParity(dimensions, bundle.capture, proof);
    const replay = try replayCore(dimensions, receipt, candidate, bundle.capture, proof);

    return .{
        .position = binding.position,
        .role = binding.role,
        .leaf_index = binding.leaf_index,
        .pair_index = binding.pair_index,
        .session_id = binding.session_id,
        .parent_vk_id = binding.parent_vk_id,
        .statement_id = binding.statement_id,
        .statement_words = bundle.statement_words.*,
        .summary_id = binding.summary_id,
        .event_count = binding.event_count,
        .signed_relation_total = binding.signed_relation_total,
        .shape = candidate.shape,
        .profile_id = candidate.profile_id,
        .capture_id = candidate.capture_id,
        .receipt_id = candidate.receipt_id,
        .proof_id = candidate.proof_id,
        .transcript_id = candidate.transcript_id,
        .claimed_sums_id = candidate.claimed_sums_id,
        .verifier_input_boundary = try qm31FromWire(
            candidate.verifier_input_boundary,
        ),
        .preprocessed_root = proof.commitments[0],
        .universal = universal,
        .replay = replay,
    };
}

pub fn validatePair(
    context: BoundContextV1,
    children: *const [CHILD_COUNT]ChildWitnessV1,
) Error!void {
    for (children, 0..) |*child, index| {
        try child.validate();
        const expected_position: pair_node.ChildPosition = if (index == 0) .left else .right;
        const expected_role: pair_node.ChildRole = if (index == 0)
            .core_request
        else
            .poseidon2_provider;
        const expected_leaf = std.math.add(
            u32,
            std.math.mul(u32, context.pair_index, @intCast(CHILD_COUNT)) catch
                return error.ChildBindingMismatch,
            @intCast(index),
        ) catch return error.ChildBindingMismatch;
        if (child.position != expected_position or child.role != expected_role)
            return error.ChildOrderMismatch;
        if (!std.meta.eql(child.session_id, context.session_id) or
            !std.meta.eql(child.parent_vk_id, context.parent_vk_id) or
            child.leaf_index != expected_leaf or
            child.pair_index != context.pair_index or
            child.event_count != context.event_count)
        {
            return error.ChildBindingMismatch;
        }
    }
    if (!profilesCompatible(children[0].shape, children[1].shape))
        return error.ChildProfileMismatch;
    if (std.meta.eql(children[0].proof_id, children[1].proof_id) or
        (std.meta.eql(children[0].statement_id, children[1].statement_id) and
            std.meta.eql(children[0].transcript_id, children[1].transcript_id)))
    {
        return error.DuplicateChild;
    }
    if (!children[0].signed_relation_total
        .add(children[1].signed_relation_total)
        .isZero())
    {
        return error.ChildBindingMismatch;
    }
}

pub fn profilesCompatible(left: admission.ShapeV1, right: admission.ShapeV1) bool {
    return left.format_version == right.format_version and
        left.scope == right.scope and
        std.meta.eql(left.air_program_id, right.air_program_id) and
        std.meta.eql(left.manifest_id, right.manifest_id) and
        std.meta.eql(left.verification_key_id, right.verification_key_id) and
        std.meta.eql(left.preprocessing_id, right.preprocessing_id) and
        std.meta.eql(left.column_layout_id, right.column_layout_id) and
        std.meta.eql(left.sample_layout_id, right.sample_layout_id) and
        std.meta.eql(left.component_log_sizes, right.component_log_sizes) and
        left.table_count == right.table_count and
        left.claimed_sum_count == right.claimed_sum_count and
        left.sampled_value_count == right.sampled_value_count and
        std.meta.eql(left.tree_column_counts, right.tree_column_counts) and
        std.meta.eql(left.tree_heights, right.tree_heights) and
        left.column_log_degree == right.column_log_degree and
        left.proof_wire_bytes == right.proof_wire_bytes and
        left.fri.eql(right.fri);
}

pub fn performanceCounts(
    comptime dimensions: fixed_wire.Dimensions,
    prepared: *const Prepared(dimensions),
    source_identity_permutations: usize,
) PerformanceCountsV1 {
    var state_permutations: usize = 0;
    var pow_candidate_permutations: usize = 0;
    var operations: usize = 0;
    var fri_rounds: usize = 0;
    for (prepared.children) |child| {
        const rounds: usize = @intCast(child.replay.fri_round_count);
        fri_rounds += rounds;
        operations += 8 + 2 * rounds;
        state_permutations += drawPermutationCount(); // composition randomness
        state_permutations += mixPermutationCount(channel.RATE); // composition root
        state_permutations += drawPermutationCount(); // OODS seed
        state_permutations += mixPermutationCount(4 * dimensions.sampled_value_count);
        state_permutations += drawPermutationCount(); // DEEP randomness
        state_permutations += rounds *
            (mixPermutationCount(channel.RATE) + drawPermutationCount());
        state_permutations += mixPermutationCount(
            4 * dimensions.last_layer_coefficient_count,
        );
        // Persistent nonce absorption plus the final query draw.
        state_permutations += mixUnrestrictedU64PermutationCount();
        state_permutations += drawPermutationCount();
        // verifyPowNonce evaluates one cloned nonce mix and draw.
        pow_candidate_permutations +=
            mixUnrestrictedU64PermutationCount() + drawPermutationCount();
    }
    return .{
        .roster_rows = CHILD_COUNT * CLAIM_ROW_COUNT,
        .claimed_sum_values = CHILD_COUNT * CLAIM_ROW_COUNT,
        .sampled_value_words = CHILD_COUNT * 4 * dimensions.sampled_value_count,
        .fri_rounds = fri_rounds,
        .transcript_operations = operations,
        .transcript_state_permutations = state_permutations,
        .pow_candidate_permutations = pow_candidate_permutations,
        .source_identity_permutations = source_identity_permutations,
        .retained_witness_bytes = @sizeOf(Prepared(dimensions)),
    };
}

pub const IdentityResult = struct {
    digest: channel.Digest,
    permutations: usize,
};

pub fn sourceIdentity(prepared: anytype) IdentityResult {
    var hash = AuthorityHasher.init(SOURCE_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(@intFromEnum(CURRENT_STATUS));
    hash.digest(protocol.PROTOCOL_ID_WORDS);
    hash.digest(prepared.context.session_id);
    hash.digest(prepared.context.job_id);
    hash.digest(prepared.context.challenge_context_id);
    hash.digest(prepared.context.authority_context_id);
    hash.digest(prepared.context.parent_vk_id);
    hash.digest(prepared.context.execution_statement_id);
    hash.digest(prepared.context.public_call_commitment);
    hash.addU32(prepared.context.pair_index);
    hash.addU32(prepared.context.session_leaf_count);
    hash.addU64(prepared.context.event_count);
    for (prepared.children) |child| {
        hash.addU32(@intFromEnum(child.position));
        hash.addU32(@intFromEnum(child.role));
        hash.addU32(child.leaf_index);
        hash.addU32(child.pair_index);
        hash.digest(child.session_id);
        hash.digest(child.parent_vk_id);
        hash.digest(child.statement_id);
        hash.addM31s(&child.statement_words);
        hash.digest(child.summary_id);
        hash.addU64(child.event_count);
        hash.addU32s(&child.signed_relation_total.limbs);
        hash.digest(child.profile_id);
        hash.digest(child.capture_id);
        hash.digest(child.receipt_id);
        hash.digest(child.proof_id);
        hash.digest(child.transcript_id);
        hash.digest(child.claimed_sums_id);
        hash.qm31(child.verifier_input_boundary);
        hash.digest(child.preprocessed_root);
        hash.addU32s(&child.universal.component_log_sizes);
        for (child.universal.claimed_sums) |value| hash.qm31(value);
        for (child.universal.wire_closure) |value| hash.qm31(value);
        hash.qm31(child.replay.composition_randomness);
        hash.qm31(child.replay.oods_seed);
        hash.qm31(child.replay.deep_randomness);
        hash.addU32(child.replay.fri_round_count);
        for (child.replay.activeFriAlphas()) |value| hash.qm31(value);
        hash.addU32s(&child.replay.raw_queries);
        hash.digest(child.replay.final_digest);
        hash.addU32(child.replay.final_draw_count);
    }
    return hash.finalize();
}

pub const AuthorityHasher = struct {
    inner: channel.CanonicalWordHasher,
    word_count: usize = 0,

    fn init(domain: u32) AuthorityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn addU32(self: *AuthorityHasher, value: u32) void {
        std.debug.assert(value < stwo_core.fields.m31.Modulus);
        const words = [_]M31{M31.fromCanonical(value)};
        self.inner.update(&words);
        self.word_count += 1;
    }

    fn addU64(self: *AuthorityHasher, value: u64) void {
        self.addU32(@truncate(value & 0xffff));
        self.addU32(@truncate((value >> 16) & 0xffff));
        self.addU32(@truncate((value >> 32) & 0xffff));
        self.addU32(@truncate(value >> 48));
    }

    fn addU32s(self: *AuthorityHasher, values: []const u32) void {
        for (values) |value| self.addU32(value);
    }

    fn digest(self: *AuthorityHasher, value: channel.Digest) void {
        self.addU32s(&value);
    }

    fn addM31s(self: *AuthorityHasher, values: []const M31) void {
        self.inner.update(values);
        self.word_count += values.len;
    }

    fn qm31(self: *AuthorityHasher, value: QM31) void {
        const words = value.toM31Array();
        self.inner.update(&words);
        self.word_count += words.len;
    }

    fn finalize(self: *AuthorityHasher) IdentityResult {
        return .{
            .digest = self.inner.finalize(),
            .permutations = channel.canonicalWordPermutationCount(self.word_count),
        };
    }
};

pub fn preflightAliases(
    comptime PreparedType: type,
    destination: *PreparedType,
    encoding_scratch: []u8,
    pair_inputs: PairInputsV1,
    bundles: anytype,
) Error!void {
    const destination_bytes = std.mem.asBytes(destination);
    if (byteSlicesOverlap(destination_bytes, encoding_scratch) or
        byteSlicesOverlap(destination_bytes, std.mem.asBytes(&pair_inputs)))
    {
        return error.AliasedWorkspace;
    }
    for (bundles) |bundle| {
        if (byteSlicesOverlap(destination_bytes, std.mem.asBytes(bundle.wire)) or
            byteSlicesOverlap(destination_bytes, std.mem.asBytes(bundle.candidate)) or
            byteSlicesOverlap(destination_bytes, std.mem.asBytes(bundle.receipt)) or
            byteSlicesOverlap(destination_bytes, std.mem.asBytes(bundle.statement_words)) or
            byteSlicesOverlap(destination_bytes, std.mem.asBytes(&bundle.seal)) or
            byteSlicesOverlap(destination_bytes, std.mem.asBytes(&bundle.binding)) or
            captureStorageOverlaps(destination_bytes, bundle.capture) or
            byteSlicesOverlap(encoding_scratch, std.mem.asBytes(bundle.wire)) or
            byteSlicesOverlap(encoding_scratch, std.mem.asBytes(bundle.candidate)) or
            byteSlicesOverlap(encoding_scratch, std.mem.asBytes(bundle.receipt)) or
            byteSlicesOverlap(encoding_scratch, std.mem.asBytes(bundle.statement_words)) or
            captureStorageOverlaps(encoding_scratch, bundle.capture))
        {
            return error.AliasedWorkspace;
        }
    }
}

pub fn captureStorageOverlaps(bytes: []const u8, capture: *const ProofCapture) bool {
    if (byteSlicesOverlap(bytes, std.mem.asBytes(capture)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.queries.raw)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.queries.unique)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.commitments)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.column_log_sizes)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.sampled_points)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.sampled_values)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.queried_values)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.deep_answers)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.trace_paths)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.fri.layers)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.last_layer_coefficients)))
    {
        return true;
    }
    for (capture.column_log_sizes) |logs|
        if (byteSlicesOverlap(bytes, std.mem.sliceAsBytes(logs))) return true;
    for (capture.sampled_points) |columns| {
        if (byteSlicesOverlap(bytes, std.mem.sliceAsBytes(columns))) return true;
        for (columns) |points|
            if (byteSlicesOverlap(bytes, std.mem.sliceAsBytes(points))) return true;
    }
    for (capture.trace_paths) |paths| {
        if (byteSlicesOverlap(bytes, std.mem.sliceAsBytes(paths.positions)) or
            byteSlicesOverlap(bytes, std.mem.sliceAsBytes(paths.siblings)))
        {
            return true;
        }
    }
    for (capture.fri.layers) |layer| {
        if (byteSlicesOverlap(bytes, std.mem.sliceAsBytes(layer.positions)) or
            byteSlicesOverlap(bytes, std.mem.sliceAsBytes(layer.values)) or
            byteSlicesOverlap(bytes, std.mem.sliceAsBytes(layer.siblings)))
        {
            return true;
        }
    }
    return false;
}

pub fn byteSlicesOverlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

pub fn drawPermutationCount() usize {
    return channel.canonicalWordPermutationCount(channel.RATE + 2);
}

pub fn mixPermutationCount(payload_words: usize) usize {
    return channel.canonicalWordPermutationCount(channel.RATE + payload_words);
}

pub fn mixUnrestrictedU64PermutationCount() usize {
    // Channel.mixU64 injectively splits two u32 words into four M31 limbs.
    return mixPermutationCount(4);
}

comptime {
    if (CHILD_COUNT != pair_node.CHILD_COUNT or CLAIM_ROW_COUNT != 36 or
        QUERY_COUNT != 3 or admission.PCS_POW_BITS != 0 or
        admission.INTERACTION_POW_BITS != 0 or admission.FOLD_STEP != 1 or
        admission.LOG_BLOWUP_FACTOR != 1 or
        admission.LOG_LAST_LAYER_DEGREE_BOUND != 0)
    {
        @compileError("outer parent transcript source drifted from OUTER_CONFIG");
    }
}
