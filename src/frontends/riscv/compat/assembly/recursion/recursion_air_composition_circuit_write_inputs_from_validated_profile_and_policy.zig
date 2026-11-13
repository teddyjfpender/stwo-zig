//! Internal shard of recursion_air_composition_circuit_v3.zig; use the public facade.

const dependency_0 = @import("recursion_air_composition_circuit_canonical_empty_program.zig");
const dependency_1 = @import("recursion_air_composition_circuit_program_roster.zig");
const dependency_2 = @import("recursion_air_composition_circuit_circuit_view.zig");
const dependency_5 = @import("recursion_air_composition_circuit_authority_validation.zig");

const std = dependency_0.std;
const circle = dependency_0.circle;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const qm31 = dependency_0.qm31;
const verifier_types = dependency_0.verifier_types;
const graph_mod = dependency_0.graph_mod;
const recorder = dependency_0.recorder;
const capture_layout_v3 = dependency_0.capture_layout_v3;
const ProofKind = dependency_0.ProofKind;
const UNIVERSAL_PHYSICAL_CLAIM_COUNT = dependency_0.UNIVERSAL_PHYSICAL_CLAIM_COUNT;
const SEGMENT_PHYSICAL_CLAIM_COUNT = dependency_0.SEGMENT_PHYSICAL_CLAIM_COUNT;
const H1_PHYSICAL_CLAIM_COUNT = dependency_0.H1_PHYSICAL_CLAIM_COUNT;
// Frozen Initial38 descriptor ABI, independent of product execution policy.
pub const INITIAL_PHYSICAL_CLAIM_COUNT = capture_layout_v3.INITIAL_WRAPPER_COMPONENT_COUNT;
const POSEIDON_PARTIAL_COUNT = dependency_0.POSEIDON_PARTIAL_COUNT;
const POSEIDON_ROSTER_ROW = dependency_0.POSEIDON_ROSTER_ROW;
const POSEIDON_AUX_START = dependency_0.POSEIDON_AUX_START;
const H1_POSEIDON_ROSTER_ROW = dependency_0.H1_POSEIDON_ROSTER_ROW;
const H1_POSEIDON_AUX_START = dependency_0.H1_POSEIDON_AUX_START;
const H1_SEMANTIC_CLAIM_INPUT_COUNT =
    dependency_0.H1_SEMANTIC_CLAIM_INPUT_COUNT;
const COMPOSITION_CLAIM_INPUT_COUNT = dependency_0.COMPOSITION_CLAIM_INPUT_COUNT;
const STATEMENT_WORD_COUNT = dependency_0.STATEMENT_WORD_COUNT;
const PROGRAM_KIND_COUNT = dependency_0.PROGRAM_KIND_COUNT;
const CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT = dependency_0.CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT;
const Error = dependency_0.Error;
const ManifestFamilyV3 = dependency_0.ManifestFamilyV3;
const ClaimPolicyV3 = dependency_0.ClaimPolicyV3;
const TrustedManifestsV3 = dependency_0.TrustedManifestsV3;
const AirProgramIdsV3 = dependency_0.AirProgramIdsV3;
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

    /// Cold validation for the append-only ordinary-H1 binary slot. The
    /// retained configuration is re-admitted from the reopened 12-placement
    /// manifest; Segment and Empty remain the frozen legacy programs.
    pub fn validateAuthenticatedH1(
        self: *const RecordedHeterogeneousCircuitStorageV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        h1_manifest: anytype,
    ) !void {
        try self.validateFinalizedRecordingAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
        try self.authority.validateAgainstValidatedConfiguration(
            self.configuration,
            self.graph(),
            self.bindings,
        );
    }

    pub fn validateFinalizedRecordingAuthenticatedH1(
        self: *const RecordedHeterogeneousCircuitStorageV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        h1_manifest: anytype,
    ) !void {
        try self.configuration.validateAgainstAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
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
            @intCast(H1_PHYSICAL_CLAIM_COUNT),
            @intCast(UNIVERSAL_PHYSICAL_CLAIM_COUNT),
        };
        if (!std.meta.eql(self.statistics.roster_rows_per_kind, expected_rows) or
            self.statistics.constraints_per_kind[0] !=
                manifests.segment.total_constraints or
            self.statistics.constraints_per_kind[1] !=
                h1_manifest.total_constraints or
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

/// Manifest-family-aware claim assembler. Legacy callers continue through
/// `writeClaimInputs` above with byte-identical placement. Only an explicitly
/// admitted binary descriptor selects H1 12+2 or Initial38 38+2 placement.
pub fn writeClaimInputsForManifest(
    proof_kind: ProofKind,
    manifest_family: ManifestFamilyV3,
    physical_claims: []const QM31,
    poseidon_partials: []const QM31,
    destination: *[COMPOSITION_CLAIM_INPUT_COUNT]QM31,
) Error!void {
    if (manifest_family == .ethereum_initial_wrapper_v1) {
        if (proof_kind != .binary_node or physical_claims.len != INITIAL_PHYSICAL_CLAIM_COUNT or poseidon_partials.len != POSEIDON_PARTIAL_COUNT)
            return error.InvalidClaimInputCount;
        for (physical_claims) |value| try requireCanonicalQm31(value);
        for (poseidon_partials) |value| try requireCanonicalQm31(value);
        if (!poseidon_partials[0].add(poseidon_partials[1]).eql(physical_claims[POSEIDON_ROSTER_ROW]))
            return error.PoseidonPartialMismatch;
        if (overlap(std.mem.asBytes(destination), std.mem.sliceAsBytes(physical_claims)) or overlap(std.mem.asBytes(destination), std.mem.sliceAsBytes(poseidon_partials)))
            return error.AliasedInput;
        destination.* = [_]QM31{QM31.zero()} ** COMPOSITION_CLAIM_INPUT_COUNT;
        @memcpy(destination[0..INITIAL_PHYSICAL_CLAIM_COUNT], physical_claims);
        @memcpy(destination[POSEIDON_AUX_START..], poseidon_partials);
        return;
    }
    if (manifest_family != .ethereum_poseidon_h1_v1)
        return writeClaimInputs(
            proof_kind,
            physical_claims,
            poseidon_partials,
            destination,
        );
    if (proof_kind != .binary_node or
        physical_claims.len != H1_PHYSICAL_CLAIM_COUNT or
        poseidon_partials.len != POSEIDON_PARTIAL_COUNT)
    {
        return error.InvalidClaimInputCount;
    }
    for (physical_claims) |value| try requireCanonicalQm31(value);
    for (poseidon_partials) |value| try requireCanonicalQm31(value);
    if (!poseidon_partials[0].add(poseidon_partials[1]).eql(
        physical_claims[H1_POSEIDON_ROSTER_ROW],
    )) return error.PoseidonPartialMismatch;
    const target = std.mem.asBytes(destination);
    if (overlap(target, std.mem.sliceAsBytes(physical_claims)) or
        overlap(target, std.mem.sliceAsBytes(poseidon_partials)))
    {
        return error.AliasedInput;
    }
    destination.* = [_]QM31{QM31.zero()} ** COMPOSITION_CLAIM_INPUT_COUNT;
    @memcpy(destination[0..H1_PHYSICAL_CLAIM_COUNT], physical_claims);
    @memcpy(
        destination[H1_POSEIDON_AUX_START .. H1_POSEIDON_AUX_START + POSEIDON_PARTIAL_COUNT],
        poseidon_partials,
    );
}

const ClaimPolicyRecording = @import("recursion_claim_policy_recording.zig");
pub const validateClaimInputs = ClaimPolicyRecording.validateClaimInputs;
pub const validateClaimInputsForPolicy = ClaimPolicyRecording.validateClaimInputsForPolicy;
pub const validateClaimInputsForManifestPolicy = ClaimPolicyRecording.validateClaimInputsForManifestPolicy;
pub const recordClaimPolicyConstraints = ClaimPolicyRecording.recordClaimPolicyConstraints;
pub const recordClaimPolicyConstraintsForPolicy = ClaimPolicyRecording.recordClaimPolicyConstraintsForPolicy;
pub const recordClaimPolicyConstraintsForManifestPolicy = ClaimPolicyRecording.recordClaimPolicyConstraintsForManifestPolicy;
pub const recordCanonicalEmptyProviderConstraints = ClaimPolicyRecording.recordCanonicalEmptyProviderConstraints;

/// Versioned empty-provider policy.  The legacy empty encoding remains all
/// zero; only a descriptor authenticated with `canonical_empty_provider` may
/// place the deterministic public-statement contribution in slot 36.
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
/// H1-aware graph policy with the same three proof-kind selectors. Segment
/// and empty branches retain their exact legacy constraints; only the binary
/// branch's physical/partial coordinates are selected by manifest family.
/// Graph-side custody for the proofless-empty provider.  The empty selector
/// gates three independent obligations: the exact 412-word publication, the
/// complete zero sample workspace, and the deterministic public-statement
/// LogUp contribution stored in V3 claim slot 36.  No host-only comparison is
/// relied upon after the graph is recorded.
/// Writes the canonical graph input sequence.  Callers that already validated
/// a trusted configuration can use this hot-path entry and avoid all manifest
/// hashing.  Witness preflight and the write itself allocate nothing.
pub fn writeInputsFromValidatedConfiguration(
    configuration: ConfigurationV3,
    witness: WitnessV3,
    destination: []QM31,
) Error!void {
    const descriptor = configuration.program_roster.forKind(
        witness.proof_kind,
    );
    try writeInputsFromValidatedProfileAndManifestPolicy(
        configuration.inputProfile(),
        descriptor.manifest_family,
        descriptor.claim_policy,
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
    return writeInputsFromValidatedProfileAndManifestPolicy(
        input_profile,
        descriptorShape(witness.proof_kind).manifest_family,
        claim_policy,
        witness,
        destination,
    );
}

pub fn writeInputsFromValidatedProfileAndManifestPolicy(
    input_profile: InputProfileV3,
    manifest_family: ManifestFamilyV3,
    claim_policy: ClaimPolicyV3,
    witness: WitnessV3,
    destination: []QM31,
) Error!void {
    try input_profile.validate();
    const profile = input_profile.graphProfile();
    const expected_count = graph_mod.recursionInputCount(profile) catch
        return error.InvalidWitnessShape;
    if (destination.len != expected_count or
        witness.field_public_extra_words.len != input_profile.field_public_extra_word_count or
        witness.sampled_values.len != input_profile.sampled_value_count)
    {
        return error.InvalidWitnessShape;
    }
    try validateClaimInputsForManifestPolicy(
        witness.proof_kind,
        manifest_family,
        claim_policy,
        witness.claim_inputs,
    );
    try witness.relations.validate();
    for (witness.statement_words) |word| try requireCanonicalM31(word);
    for (witness.field_public_extra_words) |word| try requireCanonicalM31(word);
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
        overlap(target, std.mem.sliceAsBytes(witness.field_public_extra_words)) or
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
            .field_public_word => |index| witness.field_public_extra_words[if (index < 6) index else index - STATEMENT_WORD_COUNT],
            .sampled_value => |coordinate| witness.sampled_values[
                coordinate.item_index
            ].toM31Array()[coordinate.word_index],
            .claimed_sum => |coordinate| witness.claim_inputs[
                coordinate.item_index
            ].toM31Array()[coordinate.word_index],
            .transcript_claimed_sum => return error.InvalidWitnessShape,
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
    poseidon_roster_row: u8,
};

const DescriptorGeometry = @import("recursion_air_descriptor_geometry.zig");
pub const descriptorShape = DescriptorGeometry.descriptorShape;
pub const canonicalEmptyDescriptorShape = DescriptorGeometry.canonicalEmptyDescriptorShape;
pub const h1DescriptorShape = DescriptorGeometry.h1DescriptorShape;
pub const temporalParentDescriptorShape = DescriptorGeometry.temporalParentDescriptorShape;
pub const commonFoldDescriptorShape = DescriptorGeometry.commonFoldDescriptorShape;
pub const initialWrapperDescriptorShape = DescriptorGeometry.initialWrapperDescriptorShape;
pub const descriptorShapeForManifest = DescriptorGeometry.descriptorShapeForManifest;
pub const validateManifests = DescriptorGeometry.validateManifests;

test "Initial38 composition claims retain both initial lanes and reject malformed admission before writes" {
    var physical = [_]QM31{QM31.zero()} ** INITIAL_PHYSICAL_CLAIM_COUNT;
    physical[36] = QM31.one();
    physical[37] = QM31.one().add(QM31.one());
    const partials = [2]QM31{ QM31.one(), QM31.one() };
    physical[POSEIDON_ROSTER_ROW] = partials[0].add(partials[1]);
    var claims: [COMPOSITION_CLAIM_INPUT_COUNT]QM31 = undefined;
    try writeClaimInputsForManifest(.binary_node, .ethereum_initial_wrapper_v1, &physical, &partials, &claims);
    try std.testing.expectEqualDeep(physical, claims[0..INITIAL_PHYSICAL_CLAIM_COUNT].*);
    try std.testing.expect(claims[38].eql(QM31.zero()));
    try std.testing.expectEqualDeep(partials, claims[POSEIDON_AUX_START..].*);
    try validateClaimInputsForManifestPolicy(.binary_node, .ethereum_initial_wrapper_v1, .ethereum_initial_wrapper_v1, &claims);
    try std.testing.expectError(error.InactiveClaimInputMustBeZero, validateClaimInputs(.binary_node, &claims));
    try std.testing.expectError(error.InvalidProgramRoster, validateClaimInputsForPolicy(.binary_node, .ethereum_initial_wrapper_v1, &claims));
    try std.testing.expectError(error.InvalidProgramRoster, validateClaimInputsForManifestPolicy(.binary_node, .universal_v1, .ethereum_initial_wrapper_v1, &claims));
    try std.testing.expectError(error.InvalidProgramRoster, validateClaimInputsForManifestPolicy(.binary_node, .ethereum_initial_wrapper_v1, .universal_with_zero_tail, &claims));
    const before = claims;
    try std.testing.expectError(error.InvalidClaimInputCount, writeClaimInputsForManifest(.binary_node, .ethereum_initial_wrapper_v1, physical[0..36], &partials, &claims));
    try std.testing.expectEqualDeep(before, claims);
    try std.testing.expectError(error.InvalidClaimInputCount, writeClaimInputsForManifest(.segment_leaf, .ethereum_initial_wrapper_v1, &physical, &partials, &claims));
    try std.testing.expectEqualDeep(before, claims);
    try std.testing.expectError(error.InvalidClaimInputCount, writeClaimInputsForManifest(.binary_node, .ethereum_initial_wrapper_v1, &physical, partials[0..1], &claims));
    try std.testing.expectEqualDeep(before, claims);
    try std.testing.expectError(error.AliasedInput, writeClaimInputsForManifest(.binary_node, .ethereum_initial_wrapper_v1, claims[0..38], &partials, &claims));
    try std.testing.expectEqualDeep(before, claims);
    try std.testing.expectError(error.AliasedInput, writeClaimInputsForManifest(.binary_node, .ethereum_initial_wrapper_v1, &physical, claims[39..41], &claims));
    try std.testing.expectEqualDeep(before, claims);
    physical[POSEIDON_ROSTER_ROW] = QM31.zero();
    try std.testing.expectError(error.PoseidonPartialMismatch, writeClaimInputsForManifest(.binary_node, .ethereum_initial_wrapper_v1, &physical, &partials, &claims));
    try std.testing.expectEqualDeep(before, claims);
}

test "Initial38 composition graph constrains only slot 38 padding and ordered provider closure" {
    const allocator = std.testing.allocator;
    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    try builder.reserve(PROGRAM_KIND_COUNT + COMPOSITION_CLAIM_INPUT_COUNT, 2 * CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT);
    var selectors: [PROGRAM_KIND_COUNT]recorder.Scalar = undefined;
    var claims: [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar = undefined;
    for (&selectors) |*value| value.* = (try builder.input()).value;
    for (&claims) |*value| value.* = (try builder.input()).value;
    try builder.activate();
    try std.testing.expectError(error.InvalidProgramRoster, recordClaimPolicyConstraintsForPolicy(&builder, &selectors, &claims, .ethereum_initial_wrapper_v1));
    try std.testing.expectError(error.InvalidProgramRoster, recordClaimPolicyConstraintsForManifestPolicy(&builder, &selectors, &claims, .universal_v1, .ethereum_initial_wrapper_v1));
    try std.testing.expectError(error.InvalidProgramRoster, recordClaimPolicyConstraintsForManifestPolicy(&builder, &selectors, &claims, .ethereum_initial_wrapper_v1, .universal_with_zero_tail));
    const count = try recordClaimPolicyConstraintsForManifestPolicy(&builder, &selectors, &claims, .ethereum_initial_wrapper_v1, .ethereum_initial_wrapper_v1);
    try std.testing.expectEqual(@as(usize, 43), count);
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    var concrete = [_]QM31{QM31.zero()} ** (PROGRAM_KIND_COUNT + COMPOSITION_CLAIM_INPUT_COUNT);
    concrete[proofKindIndex(.binary_node)] = QM31.one();
    concrete[PROGRAM_KIND_COUNT + 36] = QM31.one();
    concrete[PROGRAM_KIND_COUNT + 37] = QM31.one();
    concrete[PROGRAM_KIND_COUNT + 39] = QM31.one();
    concrete[PROGRAM_KIND_COUNT + 40] = QM31.one();
    concrete[PROGRAM_KIND_COUNT + POSEIDON_ROSTER_ROW] = QM31.one().add(QM31.one());
    const values = try allocator.alloc(QM31, circuit.nodes.len);
    defer allocator.free(values);
    try circuit.evaluateInto(&concrete, values);
    for ([_]usize{ 38, 39, 40, POSEIDON_ROSTER_ROW }) |index| {
        var changed = concrete;
        changed[PROGRAM_KIND_COUNT + index] = changed[PROGRAM_KIND_COUNT + index].add(QM31.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(&changed, values));
        try std.testing.expectError(if (index == 38) error.InactiveClaimInputMustBeZero else error.PoseidonPartialMismatch, validateClaimInputsForManifestPolicy(.binary_node, .ethereum_initial_wrapper_v1, .ethereum_initial_wrapper_v1, changed[PROGRAM_KIND_COUNT..]));
    }
    @memset(&concrete, QM31.zero());
    concrete[proofKindIndex(.empty_leaf)] = QM31.one();
    try circuit.evaluateInto(&concrete, values);
    for (0..COMPOSITION_CLAIM_INPUT_COUNT) |index| {
        var changed = concrete;
        changed[PROGRAM_KIND_COUNT + index] = QM31.one();
        try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(&changed, values));
    }
}
