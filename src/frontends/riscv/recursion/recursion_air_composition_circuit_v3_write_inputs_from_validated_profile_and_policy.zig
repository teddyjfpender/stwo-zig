//! Internal shard of recursion_air_composition_circuit_v3.zig; use the public facade.

const dependency_0 = @import("recursion_air_composition_circuit_v3_canonical_empty_program_v3.zig");
const dependency_1 = @import("recursion_air_composition_circuit_v3_program_roster_v3.zig");
const dependency_2 = @import("recursion_air_composition_circuit_v3_circuit_view_v3.zig");
const dependency_5 = @import("recursion_air_composition_circuit_v3_authority_validation.zig");

const std = dependency_0.std;
const circle = dependency_0.circle;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const qm31 = dependency_0.qm31;
const verifier_types = dependency_0.verifier_types;
const graph_mod = dependency_0.graph_mod;
const recorder = dependency_0.recorder;
const universal = dependency_0.universal;
const statement_input = dependency_0.statement_input;
const capture_layout_v3 = dependency_0.capture_layout_v3;
const ProofKind = dependency_0.ProofKind;
const UNIVERSAL_PHYSICAL_CLAIM_COUNT = dependency_0.UNIVERSAL_PHYSICAL_CLAIM_COUNT;
const SEGMENT_PHYSICAL_CLAIM_COUNT = dependency_0.SEGMENT_PHYSICAL_CLAIM_COUNT;
const EMPTY_PHYSICAL_CLAIM_COUNT = dependency_0.EMPTY_PHYSICAL_CLAIM_COUNT;
const POSEIDON_PARTIAL_COUNT = dependency_0.POSEIDON_PARTIAL_COUNT;
const POSEIDON_ROSTER_ROW = dependency_0.POSEIDON_ROSTER_ROW;
const POSEIDON_AUX_START = dependency_0.POSEIDON_AUX_START;
const COMPOSITION_CLAIM_INPUT_COUNT = dependency_0.COMPOSITION_CLAIM_INPUT_COUNT;
const STATEMENT_WORD_COUNT = dependency_0.STATEMENT_WORD_COUNT;
const PROGRAM_KIND_COUNT = dependency_0.PROGRAM_KIND_COUNT;
const CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT = dependency_0.CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT;
const CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX = dependency_0.CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX;
const CANONICAL_EMPTY_CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT = dependency_0.CANONICAL_EMPTY_CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT;
const Error = dependency_0.Error;
const ManifestFamilyV3 = dependency_0.ManifestFamilyV3;
const ClaimPolicyV3 = dependency_0.ClaimPolicyV3;
const TrustedManifestsV3 = dependency_0.TrustedManifestsV3;
const AirProgramIdsV3 = dependency_0.AirProgramIdsV3;
const CanonicalEmptyProgramV3 = dependency_0.CanonicalEmptyProgramV3;
const proofKindIndex = dependency_0.proofKindIndex;
const activeProofKindSelectors = dependency_0.activeProofKindSelectors;
const InputProfileV3 = dependency_1.InputProfileV3;
const ConfigurationV3 = dependency_1.ConfigurationV3;
const CircuitAuthorityStorageV3 = dependency_2.CircuitAuthorityStorageV3;
const WitnessV3 = dependency_2.WitnessV3;
const HeterogeneousProgramStatisticsV3 = dependency_2.HeterogeneousProgramStatisticsV3;
const validateGraphBindings = dependency_5.validateGraphBindings;
const requireCanonicalM31 = dependency_5.requireCanonicalM31;
const requireCanonicalQm31 = dependency_5.requireCanonicalQm31;
const overlap = dependency_5.overlap;

pub const RecordedHeterogeneousCircuitStorageV3 = struct {
    allocator: std.mem.Allocator,
    recorded: recorder.Circuit,
    bindings: []graph_mod.RecursionInputBinding,
    configuration: ConfigurationV3,
    sample_input_authority: capture_layout_v3.SampleInputAuthorityV3,
    statistics: HeterogeneousProgramStatisticsV3,
    authority: CircuitAuthorityStorageV3,

    pub fn deinitOwned(self: *RecordedHeterogeneousCircuitStorageV3) void {
        self.allocator.free(self.bindings);
        self.recorded.deinit();
        self.* = undefined;
    }

    pub fn graph(
        self: *const RecordedHeterogeneousCircuitStorageV3,
    ) graph_mod.CircuitGraph {
        return self.recorded.graph();
    }

    pub fn validate(
        self: *const RecordedHeterogeneousCircuitStorageV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
    ) !void {
        try self.validateFinalizedRecording(manifests, air_program_ids);
        try self.authority.validateAgainstValidatedConfiguration(
            self.configuration,
            self.graph(),
            self.bindings,
        );
    }

    pub fn validateFinalizedRecording(
        self: *const RecordedHeterogeneousCircuitStorageV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
    ) !void {
        try self.configuration.validateAgainst(manifests, air_program_ids);
        try self.sample_input_authority.validateSelfConsistency();
        try self.recorded.validate();
        try validateGraphBindings(
            self.configuration,
            self.graph(),
            self.bindings,
        );
        if (self.configuration.sampled_value_count !=
            self.sample_input_authority.max_sample_count or
            self.statistics.sampled_values !=
                self.sample_input_authority.max_sample_count or
            self.statistics.graph_inputs != self.recorded.input_count or
            self.statistics.graph_nodes != self.recorded.nodes.len or
            self.statistics.graph_outputs != self.recorded.outputs.len)
        {
            return error.InvalidHeterogeneousProgram;
        }
        const expected_rows = [_]u8{
            @intCast(SEGMENT_PHYSICAL_CLAIM_COUNT),
            @intCast(UNIVERSAL_PHYSICAL_CLAIM_COUNT),
            @intCast(UNIVERSAL_PHYSICAL_CLAIM_COUNT),
        };
        if (!std.meta.eql(self.statistics.roster_rows_per_kind, expected_rows) or
            self.statistics.constraints_per_kind[0] !=
                manifests.segment.total_constraints or
            self.statistics.constraints_per_kind[1] !=
                manifests.universal.total_constraints or
            self.statistics.constraints_per_kind[2] !=
                manifests.universal.total_constraints)
        {
            return error.InvalidHeterogeneousProgram;
        }
    }
};

pub fn takeSecureRecorderInput(
    inputs: []const recorder.Scalar,
    cursor: *usize,
) recorder.Scalar {
    var words: [qm31.SECURE_EXTENSION_DEGREE]recorder.Scalar = undefined;
    @memcpy(
        &words,
        inputs[cursor.*..][0..qm31.SECURE_EXTENSION_DEGREE],
    );
    cursor.* += qm31.SECURE_EXTENSION_DEGREE;
    return recorder.fromPartialEvals(words);
}

pub fn reconstructSplitCompositionForLayout(
    layout: *const capture_layout_v3.CaptureLayoutV3,
    sampled_values: []const recorder.Scalar,
    oods_point: circle.CirclePoint(recorder.Scalar),
) !recorder.Scalar {
    const chunk_count = verifier_types.compositionChunkCount(
        layout.composition_log_split,
    ) orelse return error.InvalidHeterogeneousProgram;
    var chunks: [
        @as(usize, 1) << verifier_types.MAX_COMPOSITION_LOG_SPLIT
    ]recorder.Scalar = undefined;
    for (chunks[0..chunk_count], 0..) |*chunk, chunk_index| {
        var partials: [qm31.SECURE_EXTENSION_DEGREE]recorder.Scalar = undefined;
        for (&partials, 0..) |*partial, coordinate| {
            partial.* = try layout.at(
                sampled_values,
                capture_layout_v3.COMPOSITION_TREE_INDEX,
                chunk_index * qm31.SECURE_EXTENSION_DEGREE + coordinate,
                0,
            );
        }
        chunk.* = recorder.fromPartialEvals(partials);
    }
    return recorder.reconstructSplitComposition(
        chunks[0..chunk_count],
        oods_point,
        layout.composition_log_size,
        layout.composition_log_split,
    );
}

/// Strict, allocation-free claim assembler.  Every rejection occurs before
/// the first destination write, including overlap and canonicity failures.
pub fn writeClaimInputs(
    proof_kind: ProofKind,
    physical_claims: []const QM31,
    poseidon_partials: []const QM31,
    destination: *[COMPOSITION_CLAIM_INPUT_COUNT]QM31,
) Error!void {
    const expected = descriptorShape(proof_kind);
    if (physical_claims.len != expected.source_claim_count or
        poseidon_partials.len != expected.poseidon_partial_count)
    {
        return error.InvalidClaimInputCount;
    }
    for (physical_claims) |value| try requireCanonicalQm31(value);
    for (poseidon_partials) |value| try requireCanonicalQm31(value);

    if (proof_kind != .empty_leaf and
        !poseidon_partials[0].add(poseidon_partials[1]).eql(
            physical_claims[POSEIDON_ROSTER_ROW],
        ))
    {
        return error.PoseidonPartialMismatch;
    }

    const target = std.mem.asBytes(destination);
    if (overlap(target, std.mem.sliceAsBytes(physical_claims)) or
        overlap(target, std.mem.sliceAsBytes(poseidon_partials)))
    {
        return error.AliasedInput;
    }

    destination.* = [_]QM31{QM31.zero()} ** COMPOSITION_CLAIM_INPUT_COUNT;
    if (physical_claims.len != 0)
        @memcpy(destination[0..physical_claims.len], physical_claims);
    if (poseidon_partials.len != 0)
        @memcpy(
            destination[POSEIDON_AUX_START..COMPOSITION_CLAIM_INPUT_COUNT],
            poseidon_partials,
        );
}

pub fn validateClaimInputs(
    proof_kind: ProofKind,
    inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]QM31,
) Error!void {
    for (inputs) |value| try requireCanonicalQm31(value);
    switch (proof_kind) {
        .segment_leaf => {},
        .binary_node => for (inputs[UNIVERSAL_PHYSICAL_CLAIM_COUNT..POSEIDON_AUX_START]) |
            value,
        | if (!value.eql(QM31.zero())) return error.InactiveClaimInputMustBeZero,
        .empty_leaf => for (inputs) |value| if (!value.eql(QM31.zero()))
            return error.EmptyClaimInputMustBeZero,
    }
    if (proof_kind != .empty_leaf and
        !inputs[POSEIDON_AUX_START].add(inputs[POSEIDON_AUX_START + 1]).eql(
            inputs[POSEIDON_ROSTER_ROW],
        ))
    {
        return error.PoseidonPartialMismatch;
    }
}

/// Versioned empty-provider policy.  The legacy empty encoding remains all
/// zero; only a descriptor authenticated with `canonical_empty_provider` may
/// place the deterministic public-statement contribution in slot 36.
pub fn validateClaimInputsForPolicy(
    proof_kind: ProofKind,
    policy: ClaimPolicyV3,
    inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]QM31,
) Error!void {
    if (proof_kind != .empty_leaf or policy != .canonical_empty_provider)
        return validateClaimInputs(proof_kind, inputs);
    for (inputs, 0..) |value, index| {
        try requireCanonicalQm31(value);
        if (index != CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX and
            !value.eql(QM31.zero()))
        {
            return error.EmptyClaimInputMustBeZero;
        }
    }
}

/// Records the V3 claim policy into the recursive arithmetic graph.  The
/// caller supplies selectors already bound to the parent activation rule; this
/// function adds no host-only assumption:
///
///   * binary selector gates three zero-tail equations;
///   * empty selector gates all 41 zero equations; and
///   * segment-or-binary gates the ordered Poseidon partial closure.
///
/// The fixed output count makes graph-size regressions visible.  Recording is
/// allocation-free after the caller reserves the cold builder capacity.
pub fn recordClaimPolicyConstraints(
    builder: *recorder.Builder,
    proof_kind_selectors: *const [PROGRAM_KIND_COUNT]recorder.Scalar,
    claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
) Error!usize {
    return recordClaimPolicyConstraintsForPolicy(
        builder,
        proof_kind_selectors,
        claim_inputs,
        .canonical_empty,
    );
}

pub fn recordClaimPolicyConstraintsForPolicy(
    builder: *recorder.Builder,
    proof_kind_selectors: *const [PROGRAM_KIND_COUNT]recorder.Scalar,
    claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
    empty_policy: ClaimPolicyV3,
) Error!usize {
    const segment = proof_kind_selectors[proofKindIndex(.segment_leaf)];
    const binary = proof_kind_selectors[proofKindIndex(.binary_node)];
    const empty = proof_kind_selectors[proofKindIndex(.empty_leaf)];

    for (claim_inputs[UNIVERSAL_PHYSICAL_CLAIM_COUNT..POSEIDON_AUX_START]) |
        claim,
    | try builder.constrainZero(binary.mul(claim));
    for (claim_inputs, 0..) |claim, index| {
        if (empty_policy == .canonical_empty_provider and
            index == CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX) continue;
        try builder.constrainZero(empty.mul(claim));
    }

    const partial_closure = claim_inputs[POSEIDON_AUX_START]
        .add(claim_inputs[POSEIDON_AUX_START + 1])
        .sub(claim_inputs[POSEIDON_ROSTER_ROW]);
    try builder.constrainZero(segment.add(binary).mul(partial_closure));
    try builder.check();
    return if (empty_policy == .canonical_empty_provider)
        CANONICAL_EMPTY_CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT
    else
        CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT;
}

/// Graph-side custody for the proofless-empty provider.  The empty selector
/// gates three independent obligations: the exact 412-word publication, the
/// complete zero sample workspace, and the deterministic public-statement
/// LogUp contribution stored in V3 claim slot 36.  No host-only comparison is
/// relied upon after the graph is recorded.
pub fn recordCanonicalEmptyProviderConstraints(
    builder: *recorder.Builder,
    empty_selector: recorder.Scalar,
    statement_words: *const [STATEMENT_WORD_COUNT]recorder.Scalar,
    sampled_values: []const recorder.Scalar,
    claim_inputs: *const [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
    challenges: *const recorder.ChallengeSet,
    program: CanonicalEmptyProgramV3,
) Error!usize {
    for (statement_words, program.statement_words) |actual, expected| {
        try builder.constrainZero(empty_selector.mul(actual.sub(
            recorder.Scalar.fromBase(expected),
        )));
    }
    for (sampled_values) |sample|
        try builder.constrainZero(empty_selector.mul(sample));

    const challenge = challenges.get(.recursion_statement_word);
    const scope = recorder.Scalar.fromBase(M31.fromU64(
        statement_input.PARENT_STATEMENT_SCOPE,
    ));
    var public_sum = recorder.Scalar.zero();
    for (statement_words, 0..) |word, word_index| {
        const tuple = [_]recorder.Scalar{
            scope,
            recorder.Scalar.fromBase(M31.fromU64(word_index)),
            word,
        };
        public_sum = public_sum.add((try challenge.combine(&tuple)).inverse());
    }
    try builder.constrainZero(empty_selector.mul(
        claim_inputs[CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX].add(public_sum),
    ));
    try builder.check();
    return STATEMENT_WORD_COUNT + sampled_values.len + 1;
}

/// Writes the canonical graph input sequence.  Callers that already validated
/// a trusted configuration can use this hot-path entry and avoid all manifest
/// hashing.  Witness preflight and the write itself allocate nothing.
pub fn writeInputsFromValidatedConfiguration(
    configuration: ConfigurationV3,
    witness: WitnessV3,
    destination: []QM31,
) Error!void {
    try writeInputsFromValidatedProfileAndPolicy(
        configuration.inputProfile(),
        configuration.program_roster.forKind(witness.proof_kind).claim_policy,
        witness,
        destination,
    );
}

/// Shape-only hot path.  The caller must have authenticated a
/// `ConfigurationV3` and pass its exact `inputProfile()` projection; this
/// function deliberately performs no manifest or AIR-program authentication.
pub fn writeInputsFromValidatedProfile(
    input_profile: InputProfileV3,
    witness: WitnessV3,
    destination: []QM31,
) Error!void {
    return writeInputsFromValidatedProfileAndPolicy(
        input_profile,
        descriptorShape(witness.proof_kind).claim_policy,
        witness,
        destination,
    );
}

pub fn writeInputsFromValidatedProfileAndPolicy(
    input_profile: InputProfileV3,
    claim_policy: ClaimPolicyV3,
    witness: WitnessV3,
    destination: []QM31,
) Error!void {
    try input_profile.validate();
    const profile = input_profile.graphProfile();
    const expected_count = graph_mod.recursionInputCount(profile) catch
        return error.InvalidWitnessShape;
    if (destination.len != expected_count or
        witness.sampled_values.len != input_profile.sampled_value_count)
    {
        return error.InvalidWitnessShape;
    }
    try validateClaimInputsForPolicy(
        witness.proof_kind,
        claim_policy,
        witness.claim_inputs,
    );
    try witness.relations.validate();
    for (witness.statement_words) |word| try requireCanonicalM31(word);
    for (witness.sampled_values) |value| try requireCanonicalQm31(value);
    try requireCanonicalQm31(witness.public_wire_boundary);
    try requireCanonicalQm31(witness.composition_randomness);
    try requireCanonicalQm31(witness.oods_seed);
    for (witness.relations.elements) |element| {
        try requireCanonicalQm31(element.z);
        try requireCanonicalQm31(element.alpha);
    }

    const target = std.mem.sliceAsBytes(destination);
    if (overlap(target, std.mem.asBytes(witness.statement_words)) or
        overlap(target, std.mem.sliceAsBytes(witness.sampled_values)) or
        overlap(target, std.mem.asBytes(witness.claim_inputs)) or
        overlap(target, std.mem.asBytes(witness.relations)))
    {
        return error.AliasedInput;
    }

    const proof_kind_selectors = activeProofKindSelectors(
        witness.parent_binary_selector,
        witness.proof_kind,
    );
    for (destination, 0..) |*slot, source_index| {
        const source = graph_mod.expectedRecursionSource(
            profile,
            source_index,
        ) orelse unreachable;
        const word = switch (source) {
            .parent_binary_selector => M31.fromCanonical(
                @intFromBool(witness.parent_binary_selector),
            ),
            .child_kind_selector => |kind| proof_kind_selectors[proofKindIndex(kind)],
            .statement_word => |index| witness.statement_words[index],
            .sampled_value => |coordinate| witness.sampled_values[
                coordinate.item_index
            ].toM31Array()[coordinate.word_index],
            .claimed_sum => |coordinate| witness.claim_inputs[
                coordinate.item_index
            ].toM31Array()[coordinate.word_index],
            .public_wire_boundary => |coordinate| blk: {
                if (coordinate.item_index != input_profile.claimed_sum_count)
                    return error.InvalidWitnessShape;
                break :blk witness.public_wire_boundary.toM31Array()[
                    coordinate.word_index
                ];
            },
            .relation_challenge => |coordinate| blk: {
                const element = witness.relations.elements[coordinate.challenge];
                const value = if (coordinate.word_index < 4)
                    element.z
                else
                    element.alpha;
                break :blk value.toM31Array()[coordinate.word_index % 4];
            },
            .composition_randomness => |word_index| witness.composition_randomness.toM31Array()[word_index],
            .oods_point => |word_index| witness.oods_seed.toM31Array()[word_index],
        };
        slot.* = QM31.fromBase(word);
    }
}

pub fn writeInputs(
    configuration: ConfigurationV3,
    manifests: TrustedManifestsV3,
    air_program_ids: AirProgramIdsV3,
    witness: WitnessV3,
    destination: []QM31,
) Error!void {
    try configuration.validateAgainst(manifests, air_program_ids);
    try writeInputsFromValidatedConfiguration(
        configuration,
        witness,
        destination,
    );
}

pub const DescriptorShape = struct {
    manifest_family: ManifestFamilyV3,
    claim_policy: ClaimPolicyV3,
    source_claim_count: u8,
    program_roster_count: u8,
    poseidon_partial_count: u8,
};

pub fn descriptorShape(kind: ProofKind) DescriptorShape {
    return switch (kind) {
        .segment_leaf => .{
            .manifest_family = .segment_v2,
            .claim_policy = .complete_segment,
            .source_claim_count = SEGMENT_PHYSICAL_CLAIM_COUNT,
            .program_roster_count = SEGMENT_PHYSICAL_CLAIM_COUNT,
            .poseidon_partial_count = POSEIDON_PARTIAL_COUNT,
        },
        .binary_node => .{
            .manifest_family = .universal_v1,
            .claim_policy = .universal_with_zero_tail,
            .source_claim_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
            .program_roster_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
            .poseidon_partial_count = POSEIDON_PARTIAL_COUNT,
        },
        .empty_leaf => .{
            .manifest_family = .universal_v1,
            .claim_policy = .canonical_empty,
            .source_claim_count = EMPTY_PHYSICAL_CLAIM_COUNT,
            .program_roster_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
            .poseidon_partial_count = 0,
        },
    };
}

pub fn canonicalEmptyDescriptorShape() DescriptorShape {
    return .{
        .manifest_family = .universal_v1,
        .claim_policy = .canonical_empty_provider,
        .source_claim_count = 1,
        .program_roster_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
        .poseidon_partial_count = 0,
    };
}

pub fn validateManifests(manifests: TrustedManifestsV3) Error!void {
    try manifests.universal.validate();
    try manifests.segment.validate();
    if (manifests.universal.roster_count != UNIVERSAL_PHYSICAL_CLAIM_COUNT or
        manifests.segment.roster_count != SEGMENT_PHYSICAL_CLAIM_COUNT)
    {
        return error.ManifestAuthorityMismatch;
    }
}
