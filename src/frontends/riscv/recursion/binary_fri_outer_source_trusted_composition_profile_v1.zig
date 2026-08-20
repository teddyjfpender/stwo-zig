//! Internal shard of binary_fri_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_fri_outer_source_claims.zig");
const dependency_8 = @import("binary_fri_outer_source_composition_source_value.zig");
const dependency_9 = @import("binary_fri_outer_source_validate_captured_against_wire.zig");

const std = dependency_0.std;
const stwo_core = dependency_0.stwo_core;
const QM31 = dependency_0.QM31;
const air_digest = dependency_0.air_digest;
const captured_fri = dependency_0.captured_fri;
const fixed_profile = dependency_0.fixed_profile;
const fixed_wire = dependency_0.fixed_wire;
const pair_node = dependency_0.pair_node;
const protocol = dependency_0.protocol;
const composition = dependency_0.composition;
const composition_input_witness = dependency_0.composition_input_witness;
const lowering = dependency_0.lowering;
const schedule = dependency_0.schedule;
const framework = dependency_0.framework;
const CHILD_COUNT = dependency_0.CHILD_COUNT;
const LEFT_CHILD = dependency_0.LEFT_CHILD;
const RIGHT_CHILD = dependency_0.RIGHT_CHILD;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const LEFT_COMPOSITION_STATEMENT_SCOPE = dependency_0.LEFT_COMPOSITION_STATEMENT_SCOPE;
const RIGHT_COMPOSITION_STATEMENT_SCOPE = dependency_0.RIGHT_COMPOSITION_STATEMENT_SCOPE;
const POSEIDON2_PARTIAL_COUNT = dependency_0.POSEIDON2_PARTIAL_COUNT;
const COMPOSITION_CLAIMED_SUM_COUNT = dependency_0.COMPOSITION_CLAIMED_SUM_COUNT;
const NO_POSEIDON2_SAMPLE_LAYOUT = dependency_0.NO_POSEIDON2_SAMPLE_LAYOUT;
const COMPOSITION_PROFILE_FORMAT_VERSION = dependency_0.COMPOSITION_PROFILE_FORMAT_VERSION;
const COMPOSITION_PROFILE_DOMAIN = dependency_0.COMPOSITION_PROFILE_DOMAIN;
const COMPOSITION_AUTHORITY_FORMAT_VERSION = dependency_0.COMPOSITION_AUTHORITY_FORMAT_VERSION;
const COMPOSITION_AUTHORITY_DOMAIN = dependency_0.COMPOSITION_AUTHORITY_DOMAIN;
const Error = dependency_0.Error;
const validateGraphEvaluation = dependency_8.validateGraphEvaluation;
const validateProtocolDigest = dependency_9.validateProtocolDigest;
const hashRecursionInputSource = dependency_9.hashRecursionInputSource;
const hashQm31Slice = dependency_9.hashQm31Slice;
const hashInt = dependency_9.hashInt;

/// Root-owned mapping from one admitted AIR program to its reviewed recursive
/// composition circuit.  This value is protocol configuration, never proof
/// material.  Supplying only a self-sealed graph is intentionally insufficient.
pub const TrustedCompositionProfileV1 = struct {
    format_version: u16 = COMPOSITION_PROFILE_FORMAT_VERSION,
    air_program_id: protocol.Digest,
    circuit_id: u32,
    circuit_identity: air_digest.Digest,
    graph_identity: air_digest.Digest,
    /// False only for the compatibility rows-30--32 admission API.  A full
    /// rows-18--34 bundle requires the recorder-produced input profile and
    /// exact source-to-node bindings below.
    row18_input_authority: bool = false,
    child_proof_kind: composition.ProofKind = .segment_leaf,
    input_profile: composition.InputProfile = .{
        .sampled_value_count = 0,
        .claimed_sum_count = 0,
        .relation_challenge_count = 0,
    },
    input_bindings: []const composition.RecursionInputBinding = &.{},
    /// Flattened verifier-capture column at which the native row-34 provider's
    /// eight interaction columns begin.  Every one of those columns must use
    /// the native `[current, previous]` mask; the generic typed-framework
    /// final-batch-only previous convention is not accepted for this row.
    poseidon2_sample_layout_start: u32 = NO_POSEIDON2_SAMPLE_LAYOUT,
    profile_digest: air_digest.Digest,

    pub fn seal(
        air_program_id: protocol.Digest,
        circuit_id: u32,
        circuit_identity: air_digest.Digest,
        graph_identity: air_digest.Digest,
    ) Error!TrustedCompositionProfileV1 {
        if (circuit_id == 0 or circuit_id >= stwo_core.fields.m31.Modulus)
            return error.InvalidCompositionProfile;
        const candidate = TrustedCompositionProfileV1{
            .air_program_id = air_program_id,
            .circuit_id = circuit_id,
            .circuit_identity = circuit_identity,
            .graph_identity = graph_identity,
            .profile_digest = undefined,
        };
        var result = candidate;
        result.profile_digest = compositionProfileDigest(candidate);
        return result;
    }

    /// Root-registry admission for a graph emitted by the authenticated
    /// composition recorder.  The registry fixes both the graph identity and
    /// the complete row-18 input ABI; a proof or caller cannot add a binding.
    pub fn sealRecorded(
        air_program_id: protocol.Digest,
        circuit_id: u32,
        circuit_identity: air_digest.Digest,
        graph_identity: air_digest.Digest,
        child_proof_kind: composition.ProofKind,
        input_profile: composition.InputProfile,
        input_bindings: []const composition.RecursionInputBinding,
        poseidon2_sample_layout_start: u32,
    ) Error!TrustedCompositionProfileV1 {
        if (circuit_id == 0 or circuit_id >= stwo_core.fields.m31.Modulus or
            input_bindings.len == 0)
        {
            return error.InvalidCompositionProfile;
        }
        const candidate = TrustedCompositionProfileV1{
            .air_program_id = air_program_id,
            .circuit_id = circuit_id,
            .circuit_identity = circuit_identity,
            .graph_identity = graph_identity,
            .row18_input_authority = true,
            .child_proof_kind = child_proof_kind,
            .input_profile = input_profile,
            .input_bindings = input_bindings,
            .poseidon2_sample_layout_start = poseidon2_sample_layout_start,
            .profile_digest = undefined,
        };
        var result = candidate;
        result.profile_digest = compositionProfileDigest(candidate);
        try result.validate();
        return result;
    }

    pub fn validate(self: TrustedCompositionProfileV1) Error!void {
        if (self.format_version != COMPOSITION_PROFILE_FORMAT_VERSION or
            self.circuit_id == 0 or
            self.circuit_id >= stwo_core.fields.m31.Modulus or
            !std.mem.eql(
                u8,
                &self.profile_digest,
                &compositionProfileDigest(self),
            ))
        {
            return error.InvalidCompositionProfile;
        }
        try validateProtocolDigest(self.air_program_id);
        if (self.row18_input_authority) {
            if (self.input_bindings.len == 0 or
                self.input_profile.claimed_sum_count !=
                    COMPOSITION_CLAIMED_SUM_COUNT or
                self.input_profile.public_wire_boundary_count != 0 or
                self.poseidon2_sample_layout_start ==
                    NO_POSEIDON2_SAMPLE_LAYOUT)
                return error.InvalidCompositionProfile;
        } else if (self.input_bindings.len != 0 or
            self.input_profile.sampled_value_count != 0 or
            self.input_profile.claimed_sum_count != 0 or
            self.input_profile.relation_challenge_count != 0 or
            self.input_profile.public_wire_boundary_count != 0 or
            self.poseidon2_sample_layout_start != NO_POSEIDON2_SAMPLE_LAYOUT)
        {
            return error.InvalidCompositionProfile;
        }
    }
};

/// Typed capability for one child recursion-composition graph.  The graph and
/// its evaluated values stay verifier-owned; this record binds them to the
/// child proof id and to a separately trusted profile.
pub const VerifiedChildCompositionAuthority = struct {
    format_version: u16 = COMPOSITION_AUTHORITY_FORMAT_VERSION,
    child_index: u8,
    verifier_id: u32,
    child_proof_id: protocol.Digest,
    air_program_id: protocol.Digest,
    circuit_id: u32,
    circuit_identity: air_digest.Digest,
    graph: composition.CircuitGraph,
    evaluation: lowering.Evaluation,
    /// Native provider recurrence coordinates in canonical alpha order:
    /// `[poseidon2, poseidon2_io]`.  Their sum is the roster-row-34 total,
    /// while row-18 binds each coordinate independently at claimed-sum input
    /// indices 36 and 37.
    poseidon2_partials: [POSEIDON2_PARTIAL_COUNT]QM31,
    poseidon2_roster_total: QM31,
    trusted_profile_digest: air_digest.Digest,
    authority_digest: air_digest.Digest,

    pub fn authenticate(
        trusted: TrustedCompositionProfileV1,
        child_index: usize,
        verified_child: pair_node.VerifiedChildV1,
        shape: fixed_profile.ProofShapeV1,
        circuit_identity: air_digest.Digest,
        graph: composition.CircuitGraph,
        evaluation: lowering.Evaluation,
        poseidon2_partials: [POSEIDON2_PARTIAL_COUNT]QM31,
        poseidon2_roster_total: QM31,
    ) !VerifiedChildCompositionAuthority {
        try trusted.validate();
        try shape.validate();
        if (child_index >= CHILD_COUNT) return error.ChildOrderMismatch;
        const expected_position: pair_node.ChildPosition = if (child_index == LEFT_CHILD)
            .left
        else
            .right;
        if (verified_child.position != expected_position or
            !std.meta.eql(shape.air_program_id, trusted.air_program_id) or
            !std.mem.eql(u8, &circuit_identity, &trusted.circuit_identity) or
            !std.mem.eql(u8, &graph.identity_digest, &trusted.graph_identity) or
            !std.mem.eql(u8, &evaluation.circuit_identity, &circuit_identity) or
            evaluation.values.len != graph.nodes.len)
        {
            return error.CompositionProfileMismatch;
        }
        try graph.validate();
        const candidate = VerifiedChildCompositionAuthority{
            .child_index = @intCast(child_index),
            .verifier_id = if (child_index == LEFT_CHILD)
                LEFT_RECURSION_VERIFIER_ID
            else
                RIGHT_RECURSION_VERIFIER_ID,
            .child_proof_id = verified_child.proof_id,
            .air_program_id = shape.air_program_id,
            .circuit_id = trusted.circuit_id,
            .circuit_identity = circuit_identity,
            .graph = graph,
            .evaluation = evaluation,
            .poseidon2_partials = poseidon2_partials,
            .poseidon2_roster_total = poseidon2_roster_total,
            .trusted_profile_digest = trusted.profile_digest,
            .authority_digest = undefined,
        };
        var result = candidate;
        result.authority_digest = compositionAuthorityDigest(candidate);
        try result.validateAgainst(trusted, verified_child, shape);
        return result;
    }

    pub fn validateAgainst(
        self: VerifiedChildCompositionAuthority,
        trusted: TrustedCompositionProfileV1,
        verified_child: pair_node.VerifiedChildV1,
        shape: fixed_profile.ProofShapeV1,
    ) !void {
        try trusted.validate();
        try shape.validate();
        const expected_verifier_id: u32 = if (self.child_index == LEFT_CHILD)
            LEFT_RECURSION_VERIFIER_ID
        else
            RIGHT_RECURSION_VERIFIER_ID;
        const expected_position: pair_node.ChildPosition = if (self.child_index == LEFT_CHILD)
            .left
        else
            .right;
        if (self.format_version != COMPOSITION_AUTHORITY_FORMAT_VERSION or
            self.child_index >= CHILD_COUNT or
            self.verifier_id != expected_verifier_id or
            verified_child.position != expected_position or
            !std.meta.eql(self.child_proof_id, verified_child.proof_id) or
            !std.meta.eql(self.air_program_id, shape.air_program_id) or
            !std.meta.eql(self.air_program_id, trusted.air_program_id) or
            self.circuit_id != trusted.circuit_id or
            !std.mem.eql(u8, &self.circuit_identity, &trusted.circuit_identity) or
            !std.mem.eql(u8, &self.graph.identity_digest, &trusted.graph_identity) or
            !std.mem.eql(u8, &self.evaluation.circuit_identity, &self.circuit_identity) or
            self.evaluation.values.len != self.graph.nodes.len or
            !self.poseidon2_roster_total.eql(
                self.poseidon2_partials[0].add(self.poseidon2_partials[1]),
            ) or
            !std.mem.eql(u8, &self.trusted_profile_digest, &trusted.profile_digest) or
            !std.mem.eql(
                u8,
                &self.authority_digest,
                &compositionAuthorityDigest(self),
            ))
        {
            return error.CompositionAuthorityMismatch;
        }
        try self.graph.validate();
    }
};

pub fn ChildInput(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    return struct {
        shape: fixed_profile.ProofShapeV1,
        wire: *const fixed_wire.FixedStarkProofWire(dimensions),
        capture: *const captured_fri.Owned,
        composition: ?VerifiedChildCompositionAuthority,
        trusted_composition_profile: ?TrustedCompositionProfileV1,
    };
}

/// One graph lane owned outside rows 18--34 but sharing rows 30--32. The
/// canonical all-36 cohort uses this for row 11's statement-semantics circuit,
/// ensuring that every live `recursion_wire` edge is lowered by one plan.
/// Both borrowed slices remain owned by the admitted non-FRI authority.
pub const SharedArithmeticInput = struct {
    lane: lowering.Lane,
    evaluation: lowering.Evaluation,
    identity_digest: air_digest.Digest,

    pub fn seal(
        lane: lowering.Lane,
        evaluation: lowering.Evaluation,
    ) !SharedArithmeticInput {
        try lane.graph.validate();
        if (!std.mem.eql(
            u8,
            &lane.circuit_identity,
            &evaluation.circuit_identity,
        ) or evaluation.values.len != lane.graph.nodes.len) {
            return error.SourceAuthorityMismatch;
        }
        var result = SharedArithmeticInput{
            .lane = lane,
            .evaluation = evaluation,
            .identity_digest = undefined,
        };
        result.identity_digest = sharedArithmeticInputDigest(result);
        try result.validate();
        return result;
    }

    pub fn validate(self: SharedArithmeticInput) !void {
        try self.lane.graph.validate();
        if (!std.mem.eql(
            u8,
            &self.lane.circuit_identity,
            &self.evaluation.circuit_identity,
        ) or self.evaluation.values.len != self.lane.graph.nodes.len or
            !std.mem.eql(
                u8,
                &self.identity_digest,
                &sharedArithmeticInputDigest(self),
            ))
        {
            return error.SourceAuthorityMismatch;
        }
    }
};

/// Minimal recorder-authenticated composition view consumed by the shared
/// rows-30--32 lowering plan. Integrations mint this only from an opaque
/// finalized recorder; it carries no claims, proof bytes, or detached witness
/// values and therefore cannot masquerade as the frozen V1 child authority.
pub const AuthenticatedCompositionLane = struct {
    circuit_id: u32,
    circuit_identity: air_digest.Digest,
    graph: composition.CircuitGraph,
    evaluation: lowering.Evaluation,

    pub fn validate(self: AuthenticatedCompositionLane) !void {
        if (self.circuit_id == 0 or
            self.circuit_id >= stwo_core.fields.m31.Modulus)
            return error.CompositionAuthorityMismatch;
        try validateGraphEvaluation(self.graph, self.evaluation);
        if (!std.mem.eql(
            u8,
            &self.circuit_identity,
            &self.graph.identity_digest,
        )) return error.CompositionAuthorityMismatch;
    }
};

/// Challenge-evaluated publication of one exact, pre-challenge tuple source.
/// The global closure layer may authenticate and carry this value, but never
/// derives it by negating an observed residual.
pub const PublicBoundaryEvidence = struct {
    source_authority_id: air_digest.Digest,
    snapshot_id: air_digest.Digest,
    tuple_provenance_id: air_digest.Digest,
    tuple_count: u32,
    claimed_sum: QM31,
};

/// Challenge-independent identity of one exact public-boundary tuple source.
/// Preparing this descriptor never evaluates a LogUp denominator; the later
/// evidence pass must reproduce all four fields from the same authenticated
/// source before publishing its challenge-dependent claim.
pub const PublicBoundaryDescriptor = struct {
    source_authority_id: air_digest.Digest,
    snapshot_id: air_digest.Digest,
    tuple_provenance_id: air_digest.Digest,
    tuple_count: u32,
};

pub const PublicBoundaryIndexRange = struct {
    start: u32,
    end: u32,
};

/// Auditable geometry behind the authenticated-recorder boundary.  Retaining
/// these counts explicitly prevents a source digest from hiding an off-by-one
/// pad range or a widened partial-claim suffix.
pub const AuthenticatedRecorderVerifierInputBoundaryDescriptor = struct {
    boundary: PublicBoundaryDescriptor,
    capture_sample_counts: [CHILD_COUNT]u32,
    recorder_sample_counts: [CHILD_COUNT]u32,
    zero_padding_item_counts: [CHILD_COUNT]u32,
    poseidon_partial_claim_ranges: [CHILD_COUNT]PublicBoundaryIndexRange,

    pub fn validate(
        self: AuthenticatedRecorderVerifierInputBoundaryDescriptor,
    ) !void {
        const partial_claim_count: u32 = @intCast(POSEIDON2_PARTIAL_COUNT);
        var expected_tuple_count: u32 = 0;
        for (
            self.capture_sample_counts,
            self.recorder_sample_counts,
            self.zero_padding_item_counts,
            self.poseidon_partial_claim_ranges,
        ) |capture_count, recorder_count, padding_count, partial_range| {
            if (capture_count > recorder_count or
                recorder_count - capture_count != padding_count or
                partial_range.end < partial_range.start or
                partial_range.end - partial_range.start !=
                    partial_claim_count)
            {
                return error.CompositionAuthorityMismatch;
            }
            const item_count = std.math.add(
                u32,
                padding_count,
                partial_range.end - partial_range.start,
            ) catch return error.ArithmeticOverflow;
            expected_tuple_count = std.math.add(
                u32,
                expected_tuple_count,
                std.math.mul(
                    u32,
                    item_count,
                    composition_input_witness.SECURE_VALUE_WORD_COUNT,
                ) catch return error.ArithmeticOverflow,
            ) catch return error.ArithmeticOverflow;
        }
        if (expected_tuple_count == 0 or
            self.boundary.tuple_count != expected_tuple_count)
        {
            return error.CompositionAuthorityMismatch;
        }
    }
};

/// One-pass post-challenge publication of the authenticated-recorder source.
/// Keeping the geometry beside the claim lets the parent authority compare
/// the challenge-independent facts without rescanning the recorder schedule.
pub const AuthenticatedRecorderVerifierInputBoundaryEvidence = struct {
    descriptor: AuthenticatedRecorderVerifierInputBoundaryDescriptor,
    claimed_sum: QM31,

    pub fn publicBoundaryEvidence(
        self: AuthenticatedRecorderVerifierInputBoundaryEvidence,
    ) PublicBoundaryEvidence {
        return .{
            .source_authority_id = self.descriptor.boundary.source_authority_id,
            .snapshot_id = self.descriptor.boundary.snapshot_id,
            .tuple_provenance_id = self.descriptor.boundary.tuple_provenance_id,
            .tuple_count = self.descriptor.boundary.tuple_count,
            .claimed_sum = self.claimed_sum,
        };
    }
};

pub fn compositionStatementScope(child_index: usize) u32 {
    return switch (child_index) {
        LEFT_CHILD => LEFT_COMPOSITION_STATEMENT_SCOPE,
        RIGHT_CHILD => RIGHT_COMPOSITION_STATEMENT_SCOPE,
        else => unreachable,
    };
}

pub const VM_CAPACITY_NODES = [_]composition.Node{
    .{ .op = .input },
    .{ .op = .input },
    .{ .op = .input },
    .{ .op = .input },
    .{ .op = .input },
    .{ .op = .input },
    .{ .op = .input },
    .{ .op = .input },
    .{ .op = .input },
};

pub const VM_CAPACITY_OUTPUTS = [_]u32{0};

pub fn compositionProfileDigest(profile: TrustedCompositionProfileV1) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(COMPOSITION_PROFILE_DOMAIN);
    hashInt(&hash, u16, profile.format_version);
    for (profile.air_program_id) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, profile.circuit_id);
    hash.update(&profile.circuit_identity);
    hash.update(&profile.graph_identity);
    hashInt(&hash, u8, @intFromBool(profile.row18_input_authority));
    hashInt(&hash, u8, @intFromEnum(profile.child_proof_kind));
    hashInt(&hash, u32, profile.input_profile.sampled_value_count);
    hashInt(&hash, u32, profile.input_profile.claimed_sum_count);
    hashInt(&hash, u32, profile.input_profile.relation_challenge_count);
    if (profile.input_profile.public_wire_boundary_count != 0) {
        hashInt(&hash, u32, 0x5057_4244); // "PWBD"
        hashInt(
            &hash,
            u32,
            profile.input_profile.public_wire_boundary_count,
        );
    }
    hashInt(&hash, u32, profile.poseidon2_sample_layout_start);
    hashInt(&hash, u64, profile.input_bindings.len);
    for (profile.input_bindings) |binding| {
        hashInt(&hash, u32, binding.node_id);
        hashRecursionInputSource(&hash, binding.source);
    }
    return hash.finalResult();
}

pub fn compositionAuthorityDigest(
    authority: VerifiedChildCompositionAuthority,
) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(COMPOSITION_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, authority.format_version);
    hashInt(&hash, u8, authority.child_index);
    hashInt(&hash, u32, authority.verifier_id);
    for (authority.child_proof_id) |word| hashInt(&hash, u32, word);
    for (authority.air_program_id) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, authority.circuit_id);
    hash.update(&authority.circuit_identity);
    hash.update(&authority.graph.identity_digest);
    hash.update(&authority.evaluation.circuit_identity);
    hashQm31Slice(&hash, authority.evaluation.values);
    for (authority.poseidon2_partials) |partial| for (partial.toM31Array()) |word|
        hashInt(&hash, u32, word.toU32());
    for (authority.poseidon2_roster_total.toM31Array()) |word|
        hashInt(&hash, u32, word.toU32());
    hash.update(&authority.trusted_profile_digest);
    return hash.finalResult();
}

pub fn sharedArithmeticInputDigest(input: SharedArithmeticInput) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-shared-arithmetic-input/v1\x00");
    hashInt(&hash, u32, input.lane.circuit_id);
    hashInt(&hash, u8, @intFromEnum(input.lane.active_in));
    hash.update(&input.lane.circuit_identity);
    hash.update(&input.lane.graph.identity_digest);
    hash.update(&input.evaluation.circuit_identity);
    hashQm31Slice(&hash, input.evaluation.values);
    return hash.finalResult();
}
