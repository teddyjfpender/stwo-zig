//! Internal shard of recursion_air_composition_circuit_v3.zig; use the public facade.

const dependency_0 = @import("recursion_air_composition_circuit_v3_canonical_empty_program_v3.zig");
const dependency_1 = @import("recursion_air_composition_circuit_v3_program_roster_v3.zig");
const dependency_2 = @import("recursion_air_composition_circuit_v3_circuit_view_v3.zig");
const dependency_4 = @import("recursion_air_composition_circuit_v3_write_inputs_from_validated_profile_and_policy.zig");
const dependency_5 = @import("recursion_air_composition_circuit_v3_authority_validation.zig");

const std = dependency_0.std;
const circle = dependency_0.circle;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const m31 = dependency_0.m31;
const graph_mod = dependency_0.graph_mod;
const recorder = dependency_0.recorder;
const segment_manifest_mod = dependency_0.segment_manifest_mod;
const universal_manifest_mod = dependency_0.universal_manifest_mod;
const universal = dependency_0.universal;
const statement_input = dependency_0.statement_input;
const span_statement = dependency_0.span_statement;
const capture_layout_v3 = dependency_0.capture_layout_v3;
const segment_recorder_v3 = dependency_0.segment_recorder_v3;
const SEGMENT_PHYSICAL_CLAIM_COUNT = dependency_0.SEGMENT_PHYSICAL_CLAIM_COUNT;
const COMPOSITION_CLAIM_INPUT_COUNT = dependency_0.COMPOSITION_CLAIM_INPUT_COUNT;
const RELATION_CHALLENGE_COUNT = dependency_0.RELATION_CHALLENGE_COUNT;
const STATEMENT_WORD_COUNT = dependency_0.STATEMENT_WORD_COUNT;
const PROGRAM_KIND_COUNT = dependency_0.PROGRAM_KIND_COUNT;
const TrustedManifestsV3 = dependency_0.TrustedManifestsV3;
const AirProgramIdsV3 = dependency_0.AirProgramIdsV3;
const CanonicalEmptyProgramV3 = dependency_0.CanonicalEmptyProgramV3;
const proofKindIndex = dependency_0.proofKindIndex;
const ConfigurationV3 = dependency_1.ConfigurationV3;
const CircuitAuthorityV3 = dependency_1.CircuitAuthorityV3;
const CircuitViewV3 = dependency_2.CircuitViewV3;
const WitnessV3 = dependency_2.WitnessV3;
const RecordedHeterogeneousCircuitStorageV3 = dependency_4.RecordedHeterogeneousCircuitStorageV3;
const takeSecureRecorderInput = dependency_4.takeSecureRecorderInput;
const reconstructSplitCompositionForLayout = dependency_4.reconstructSplitCompositionForLayout;
const recordClaimPolicyConstraintsForPolicy = dependency_4.recordClaimPolicyConstraintsForPolicy;
const recordCanonicalEmptyProviderConstraints = dependency_4.recordCanonicalEmptyProviderConstraints;
const writeInputsFromValidatedConfiguration = dependency_4.writeInputsFromValidatedConfiguration;
const validateManifests = dependency_4.validateManifests;
const mintCircuitAuthorityFromValidatedRecording = dependency_5.mintCircuitAuthorityFromValidatedRecording;
const authorityHandle = dependency_5.authorityHandle;

/// Opaque owned result of the complete three-program recording transaction.
/// The retained authority is minted inside `HeterogeneousSessionV3.finish`,
/// after the private builder is finalized and the complete recording is
/// validated.  Production row-18 admission remains separately fail closed
/// until an independently initialized parent verifier consumes `validatedView`.
pub const RecordedHeterogeneousCircuitV3 = opaque {
    pub fn deinit(self: *RecordedHeterogeneousCircuitV3) void {
        const storage = recordingStorage(self);
        const allocator = storage.allocator;
        storage.deinitOwned();
        allocator.destroy(storage);
    }

    pub fn graph(
        self: *const RecordedHeterogeneousCircuitV3,
    ) graph_mod.CircuitGraph {
        return recordingStorageConst(self).graph();
    }

    /// Returns the pointer-free configuration only after replaying the full
    /// recorder authority check.  This is the narrow descriptor handoff used
    /// by row-18 verifier ingress: exposing a validated value copy cannot mint
    /// a circuit/view capability, while requiring callers to reconstruct the
    /// roster would create a second source of truth for the SegmentV2 ABI.
    pub fn configurationSnapshot(
        self: *const RecordedHeterogeneousCircuitV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
    ) !ConfigurationV3 {
        try self.validate(manifests, air_program_ids);
        return recordingStorageConst(self).configuration;
    }

    pub fn validate(
        self: *const RecordedHeterogeneousCircuitV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
    ) !void {
        try recordingStorageConst(self).validate(manifests, air_program_ids);
    }

    /// Returns a borrow-only row-18 view after replaying the complete cold
    /// authority validation.  The view cannot outlive this recording.
    pub fn validatedView(
        self: *const RecordedHeterogeneousCircuitV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
    ) !*const CircuitViewV3 {
        try self.validate(manifests, air_program_ids);
        return @ptrCast(self);
    }

    pub fn validatedAuthority(
        self: *const RecordedHeterogeneousCircuitV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
    ) !*const CircuitAuthorityV3 {
        try self.validate(manifests, air_program_ids);
        return authorityHandle(&recordingStorageConst(self).authority);
    }

    pub fn evaluateInto(
        self: *const RecordedHeterogeneousCircuitV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        witness: WitnessV3,
        input_scratch: []QM31,
        node_scratch: []QM31,
    ) !void {
        const storage = recordingStorageConst(self);
        try storage.validate(manifests, air_program_ids);
        try writeInputsFromValidatedConfiguration(
            storage.configuration,
            witness,
            input_scratch,
        );
        try storage.recorded.evaluateInto(input_scratch, node_scratch);
    }

    /// Evaluates one SegmentV2 child through this exact finalized recording.
    /// The retained sample authority, rather than the integration caller,
    /// checks that the child's capture layout belongs to the recording and
    /// owns canonical zero-padding into the shared max-sized graph ABI.
    pub fn evaluateSegmentInto(
        self: *const RecordedHeterogeneousCircuitV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        segment_layout: *const capture_layout_v3.CaptureLayoutV3,
        witness: WitnessV3,
        padded_sample_scratch: []QM31,
        input_scratch: []QM31,
        node_scratch: []QM31,
    ) !void {
        const storage = recordingStorageConst(self);
        try storage.validate(manifests, air_program_ids);
        try segment_layout.validateAgainstSegment(manifests.segment);
        try storage.sample_input_authority.validateSelfConsistency();
        if (witness.proof_kind != .segment_leaf or
            !std.mem.eql(
                u8,
                &segment_layout.identity,
                &storage.sample_input_authority.segment_layout_identity,
            ))
        {
            return error.CircuitAuthorityMismatch;
        }
        try storage.sample_input_authority.writePaddedSamples(
            .segment_leaf,
            witness.sampled_values,
            padded_sample_scratch,
        );
        var padded_witness = witness;
        padded_witness.sampled_values = padded_sample_scratch;
        try writeInputsFromValidatedConfiguration(
            storage.configuration,
            padded_witness,
            input_scratch,
        );
        try storage.recorded.evaluateInto(input_scratch, node_scratch);
    }
};

/// Cold, fail-closed construction transaction for the exact SegmentV2,
/// binary, and empty composition programs.  Capture geometry is derived once;
/// all hot row replays use borrowed symbolic inputs and separate denominator
/// caches for the Segment and universal quotient geometries.
pub const HeterogeneousSessionV3 = struct {
    allocator: std.mem.Allocator,
    builder: recorder.Builder,
    bindings: []graph_mod.RecursionInputBinding,
    manifests: TrustedManifestsV3,
    air_program_ids: AirProgramIdsV3,
    configuration: ConfigurationV3,
    sample_input_authority: capture_layout_v3.SampleInputAuthorityV3,
    segment_layout: capture_layout_v3.CaptureLayoutV3,
    binary_layout: capture_layout_v3.CaptureLayoutV3,
    canonical_empty_layout: ?capture_layout_v3.CanonicalEmptyCaptureLayoutV3,
    canonical_empty_program: ?CanonicalEmptyProgramV3,
    sampled_values: []recorder.Scalar,
    parent_binary_selector: recorder.Scalar,
    child_kind_selectors: [PROGRAM_KIND_COUNT]recorder.Scalar,
    statement_words: [STATEMENT_WORD_COUNT]recorder.Scalar,
    claim_inputs: [COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar,
    public_wire_boundary: recorder.Scalar,
    challenges: recorder.ChallengeSet,
    composition_randomness: recorder.Scalar,
    oods_point: circle.CirclePoint(recorder.Scalar),
    segment_split_composition: recorder.Scalar,
    universal_split_composition: recorder.Scalar,
    segment_denominators: recorder.DenominatorCache,
    universal_denominators: recorder.DenominatorCache,
    program_results: [PROGRAM_KIND_COUNT]?segment_recorder_v3.ProgramResultV3 =
        .{null} ** PROGRAM_KIND_COUNT,
    programs_recorded: bool = false,
    failed: bool = false,
    finished: bool = false,

    pub fn create(
        allocator: std.mem.Allocator,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        segment_capture: anytype,
        binary_capture: anytype,
    ) !*HeterogeneousSessionV3 {
        return createInner(
            allocator,
            manifests,
            air_program_ids,
            segment_capture,
            binary_capture,
            null,
        );
    }

    /// V3.1 construction path for the proofless empty base case.  The exact
    /// publication-bound program must use the layout deterministically derived
    /// from the same binary verifier capture retained by this session.
    pub fn createWithCanonicalEmpty(
        allocator: std.mem.Allocator,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        segment_capture: anytype,
        binary_capture: anytype,
        canonical_empty_program: CanonicalEmptyProgramV3,
    ) !*HeterogeneousSessionV3 {
        return createInner(
            allocator,
            manifests,
            air_program_ids,
            segment_capture,
            binary_capture,
            canonical_empty_program,
        );
    }

    fn createInner(
        allocator: std.mem.Allocator,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        segment_capture: anytype,
        binary_capture: anytype,
        canonical_empty_program: ?CanonicalEmptyProgramV3,
    ) !*HeterogeneousSessionV3 {
        try validateManifests(manifests);
        var segment_layout = try capture_layout_v3.CaptureLayoutV3.initSegment(
            allocator,
            manifests.segment,
            segment_capture,
        );
        errdefer segment_layout.deinit();
        var binary_layout = try capture_layout_v3.CaptureLayoutV3.initBinary(
            allocator,
            manifests.universal,
            binary_capture,
        );
        errdefer binary_layout.deinit();
        var canonical_empty_layout: ?capture_layout_v3.CanonicalEmptyCaptureLayoutV3 =
            null;
        errdefer if (canonical_empty_layout) |*layout| layout.deinit();
        if (canonical_empty_program) |program| {
            canonical_empty_layout =
                try capture_layout_v3.CanonicalEmptyCaptureLayoutV3.init(
                    allocator,
                    manifests.universal,
                    &binary_layout,
                );
            try program.validateAgainst(
                manifests.universal,
                &binary_layout,
                &canonical_empty_layout.?,
            );
            if (!std.meta.eql(air_program_ids.empty_leaf, program.air_program_id))
                return error.CanonicalEmptyProgramMismatch;
        }
        const sample_authority = try capture_layout_v3.SampleInputAuthorityV3.seal(
            &segment_layout,
            &binary_layout,
        );
        const configuration = if (canonical_empty_program) |program|
            try ConfigurationV3.sealWithCanonicalEmpty(
                manifests,
                air_program_ids,
                sample_authority.max_sample_count,
                program,
            )
        else
            try ConfigurationV3.seal(
                manifests,
                air_program_ids,
                sample_authority.max_sample_count,
            );
        const profile = configuration.graphInputProfile();
        const input_count = try graph_mod.recursionInputCount(profile);
        if (input_count >= m31.Modulus) return error.InvalidClaimInputProfile;

        const bindings = try allocator.alloc(
            graph_mod.RecursionInputBinding,
            input_count,
        );
        errdefer allocator.free(bindings);
        const sampled_values = try allocator.alloc(
            recorder.Scalar,
            sample_authority.max_sample_count,
        );
        errdefer allocator.free(sampled_values);
        const base_inputs = try allocator.alloc(recorder.Scalar, input_count);
        defer allocator.free(base_inputs);

        const self = try allocator.create(HeterogeneousSessionV3);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .builder = recorder.Builder.init(allocator),
            .bindings = bindings,
            .manifests = manifests,
            .air_program_ids = air_program_ids,
            .configuration = configuration,
            .sample_input_authority = sample_authority,
            .segment_layout = segment_layout,
            .binary_layout = binary_layout,
            .canonical_empty_layout = canonical_empty_layout,
            .canonical_empty_program = canonical_empty_program,
            .sampled_values = sampled_values,
            .parent_binary_selector = undefined,
            .child_kind_selectors = undefined,
            .statement_words = undefined,
            .claim_inputs = undefined,
            .public_wire_boundary = undefined,
            .challenges = undefined,
            .composition_randomness = undefined,
            .oods_point = undefined,
            .segment_split_composition = undefined,
            .universal_split_composition = undefined,
            .segment_denominators = .{null} ** circle.M31_CIRCLE_LOG_ORDER,
            .universal_denominators = .{null} ** circle.M31_CIRCLE_LOG_ORDER,
        };
        errdefer self.builder.deinit();

        const program_constraints = std.math.add(
            usize,
            manifests.segment.total_constraints,
            std.math.mul(
                usize,
                manifests.universal.total_constraints,
                2,
            ) catch return error.InvalidHeterogeneousProgram,
        ) catch return error.InvalidHeterogeneousProgram;
        const empty_provider_hint = if (canonical_empty_program != null)
            STATEMENT_WORD_COUNT + sample_authority.max_sample_count + 1
        else
            0;
        try self.builder.reserve(
            input_count,
            std.math.add(
                usize,
                program_constraints,
                empty_provider_hint,
            ) catch return error.InvalidHeterogeneousProgram,
        );
        for (base_inputs, bindings, 0..) |*value, *binding, index| {
            const input = try self.builder.input();
            const source = graph_mod.expectedRecursionSource(profile, index) orelse
                return error.InvalidHeterogeneousProgram;
            value.* = input.value;
            binding.* = .{ .node_id = input.node_id, .source = source };
        }

        try self.builder.activate();
        errdefer if (self.builder.active) self.builder.deactivate();

        var cursor: usize = 0;
        self.parent_binary_selector = base_inputs[cursor];
        cursor += 1;
        @memcpy(
            &self.child_kind_selectors,
            base_inputs[cursor..][0..PROGRAM_KIND_COUNT],
        );
        cursor += PROGRAM_KIND_COUNT;
        @memcpy(
            &self.statement_words,
            base_inputs[cursor..][0..STATEMENT_WORD_COUNT],
        );
        cursor += STATEMENT_WORD_COUNT;
        for (self.sampled_values) |*value|
            value.* = takeSecureRecorderInput(base_inputs, &cursor);
        for (&self.claim_inputs) |*value|
            value.* = takeSecureRecorderInput(base_inputs, &cursor);
        self.public_wire_boundary = takeSecureRecorderInput(base_inputs, &cursor);
        var challenge_draws: [RELATION_CHALLENGE_COUNT][2]recorder.Scalar =
            undefined;
        for (&challenge_draws) |*draw| {
            draw[0] = takeSecureRecorderInput(base_inputs, &cursor);
            draw[1] = takeSecureRecorderInput(base_inputs, &cursor);
        }
        self.composition_randomness = takeSecureRecorderInput(base_inputs, &cursor);
        const oods_seed = takeSecureRecorderInput(base_inputs, &cursor);
        if (cursor != input_count) return error.InvalidHeterogeneousProgram;
        self.challenges = try recorder.ChallengeSet.init(challenge_draws);
        self.oods_point = recorder.pointFromSeed(oods_seed);
        self.segment_split_composition = try reconstructSplitCompositionForLayout(
            &self.segment_layout,
            self.sampled_values[0..self.segment_layout.sampled_value_count],
            self.oods_point,
        );
        self.universal_split_composition = try reconstructSplitCompositionForLayout(
            &self.binary_layout,
            self.sampled_values[0..self.binary_layout.sampled_value_count],
            self.oods_point,
        );
        try self.bindChildKind();
        const empty_policy = configuration.program_roster
            .forKind(.empty_leaf).claim_policy;
        _ = try recordClaimPolicyConstraintsForPolicy(
            &self.builder,
            &self.child_kind_selectors,
            &self.claim_inputs,
            empty_policy,
        );
        if (canonical_empty_program) |program| _ =
            try recordCanonicalEmptyProviderConstraints(
                &self.builder,
                self.child_kind_selectors[proofKindIndex(.empty_leaf)],
                &self.statement_words,
                self.sampled_values,
                &self.claim_inputs,
                &self.challenges,
                program,
            );
        try self.constrainGlobalLogup();
        try self.builder.check();

        segment_layout = undefined;
        binary_layout = undefined;
        canonical_empty_layout = null;
        return self;
    }

    pub fn deinit(self: *HeterogeneousSessionV3) void {
        if (self.builder.active) self.builder.deactivate();
        self.builder.deinit();
        self.segment_layout.deinit();
        self.binary_layout.deinit();
        if (self.canonical_empty_layout) |*layout| layout.deinit();
        self.allocator.free(self.sampled_values);
        self.allocator.free(self.bindings);
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn recordPrograms(
        self: *HeterogeneousSessionV3,
        segment_components: anytype,
        binary_components: anytype,
        empty_components: anytype,
    ) !void {
        if (self.finished or self.programs_recorded or self.failed or
            !self.builder.active)
        {
            return error.InvalidHeterogeneousProgram;
        }
        self.recordProgramsInner(
            segment_components,
            binary_components,
            empty_components,
        ) catch |err| {
            self.failed = true;
            return err;
        };
        self.programs_recorded = true;
    }

    /// Variant used by the protocol-owned canonical empty program.  Its 34
    /// logical adapters are already generated in universal-catalog order, so
    /// replay consumes that tuple directly and appends the two authenticated
    /// provider adapters without introducing another named-field assembly.
    pub fn recordProgramsWithEmptyCatalog(
        self: *HeterogeneousSessionV3,
        segment_components: anytype,
        binary_components: anytype,
        empty_owners: anytype,
        empty_poseidon: *const segment_recorder_v3.EmptyProgramRecorderV3.PoseidonAdapter,
        empty_range: *const segment_recorder_v3.EmptyProgramRecorderV3.RangeCheck8x8Adapter,
    ) !void {
        if (self.finished or self.programs_recorded or self.failed or
            !self.builder.active)
        {
            return error.InvalidHeterogeneousProgram;
        }
        self.recordSegmentProgram(segment_components) catch |err| {
            self.failed = true;
            return err;
        };
        self.recordBinaryProgram(binary_components) catch |err| {
            self.failed = true;
            return err;
        };
        var empty_program = self.beginEmptyProgram() catch |err| {
            self.failed = true;
            return err;
        };
        self.program_results[proofKindIndex(.empty_leaf)] =
            empty_program.recordCompleteCanonicalEmptyCatalog(
                empty_owners,
                empty_poseidon,
                empty_range,
            ) catch |err| {
                self.failed = true;
                return err;
            };
        self.programs_recorded = true;
    }

    /// Records the real 36-row proofless-empty cohort under its dedicated
    /// layout authority.  The Segment and Binary paths are unchanged; this
    /// method is available only on a `createWithCanonicalEmpty` session.
    pub fn recordProgramsWithCanonicalEmptyCatalog(
        self: *HeterogeneousSessionV3,
        segment_components: anytype,
        binary_components: anytype,
        empty_owners: anytype,
        empty_poseidon: *const segment_recorder_v3.EmptyProgramRecorderV3.PoseidonAdapter,
        empty_range: *const segment_recorder_v3.EmptyProgramRecorderV3.RangeCheck8x8Adapter,
    ) !void {
        if (self.finished or self.programs_recorded or self.failed or
            !self.builder.active or self.canonical_empty_program == null or
            self.canonical_empty_layout == null)
        {
            return error.InvalidHeterogeneousProgram;
        }
        self.recordSegmentProgram(segment_components) catch |err| {
            self.failed = true;
            return err;
        };
        self.recordBinaryProgram(binary_components) catch |err| {
            self.failed = true;
            return err;
        };
        var empty_program = self.beginCanonicalEmptyProgram() catch |err| {
            self.failed = true;
            return err;
        };
        self.program_results[proofKindIndex(.empty_leaf)] =
            empty_program.recordCompleteUniversalCatalog(
                empty_owners,
                empty_poseidon,
                empty_range,
            ) catch |err| {
                self.failed = true;
                return err;
            };
        self.programs_recorded = true;
    }

    fn recordProgramsInner(
        self: *HeterogeneousSessionV3,
        segment_components: anytype,
        binary_components: anytype,
        empty_components: anytype,
    ) !void {
        try self.recordSegmentProgram(segment_components);
        try self.recordBinaryProgram(binary_components);
        var empty_program = try self.beginEmptyProgram();
        self.program_results[proofKindIndex(.empty_leaf)] =
            try empty_program.recordCompleteUniversalCohort(empty_components);
    }

    fn recordSegmentProgram(
        self: *HeterogeneousSessionV3,
        segment_components: anytype,
    ) !void {
        var segment_program = try segment_recorder_v3.SegmentProgramRecorderV3.init(
            &self.builder,
            self.configurationManifestSegment(),
            &self.segment_layout,
            self.sampled_values[0..self.segment_layout.sampled_value_count],
            &self.claim_inputs,
            &self.challenges,
            self.composition_randomness,
            self.oods_point,
            &self.segment_denominators,
        );
        self.program_results[proofKindIndex(.segment_leaf)] =
            try segment_program.recordCompleteCohort(segment_components);
    }

    fn recordBinaryProgram(
        self: *HeterogeneousSessionV3,
        binary_components: anytype,
    ) !void {
        var binary_program = try segment_recorder_v3.UniversalProgramRecorderV3.init(
            &self.builder,
            self.configurationManifestUniversal(),
            &self.binary_layout,
            self.sampled_values[0..self.binary_layout.sampled_value_count],
            &self.claim_inputs,
            &self.challenges,
            self.composition_randomness,
            self.oods_point,
            &self.universal_denominators,
        );
        self.program_results[proofKindIndex(.binary_node)] =
            try binary_program.recordCompleteUniversalCohort(binary_components);
    }

    fn beginEmptyProgram(
        self: *HeterogeneousSessionV3,
    ) !segment_recorder_v3.EmptyProgramRecorderV3 {
        return segment_recorder_v3.EmptyProgramRecorderV3.init(
            &self.builder,
            self.configurationManifestUniversal(),
            &self.binary_layout,
            self.sampled_values[0..self.binary_layout.sampled_value_count],
            &self.claim_inputs,
            &self.challenges,
            self.composition_randomness,
            self.oods_point,
            &self.universal_denominators,
        );
    }

    fn beginCanonicalEmptyProgram(
        self: *HeterogeneousSessionV3,
    ) !segment_recorder_v3.EmptyProgramRecorderV3 {
        const layout = if (self.canonical_empty_layout) |*value|
            value
        else
            return error.InvalidHeterogeneousProgram;
        return segment_recorder_v3.EmptyProgramRecorderV3.initCanonicalEmpty(
            &self.builder,
            self.configurationManifestUniversal(),
            layout,
            self.sampled_values[0..layout.internal_sample_count],
            &self.claim_inputs,
            &self.challenges,
            self.composition_randomness,
            self.oods_point,
            &self.universal_denominators,
        );
    }

    /// Finalizes an owned graph but deliberately withholds production circuit
    /// authority until the real empty-cohort integration gate is present.
    pub fn finish(
        self: *HeterogeneousSessionV3,
    ) !*RecordedHeterogeneousCircuitV3 {
        if (self.finished or self.failed or !self.programs_recorded or
            !self.builder.active)
        {
            return error.IncompleteHeterogeneousProgram;
        }
        const segment = self.program_results[proofKindIndex(.segment_leaf)] orelse
            return error.IncompleteHeterogeneousProgram;
        const binary = self.program_results[proofKindIndex(.binary_node)] orelse
            return error.IncompleteHeterogeneousProgram;
        const empty = self.program_results[proofKindIndex(.empty_leaf)] orelse
            return error.IncompleteHeterogeneousProgram;

        try self.builder.constrainZero(
            self.child_kind_selectors[proofKindIndex(.segment_leaf)].mul(
                self.segment_split_composition.sub(segment.accumulation),
            ),
        );
        try self.builder.constrainZero(
            self.child_kind_selectors[proofKindIndex(.binary_node)].mul(
                self.universal_split_composition.sub(binary.accumulation),
            ),
        );
        try self.builder.constrainZero(
            self.child_kind_selectors[proofKindIndex(.empty_leaf)].mul(
                self.universal_split_composition.sub(empty.accumulation),
            ),
        );
        try self.builder.check();
        self.builder.deactivate();
        self.finished = true;

        var recorded = try self.builder.finish();
        errdefer recorded.deinit();
        const result = try self.allocator.create(
            RecordedHeterogeneousCircuitStorageV3,
        );
        errdefer self.allocator.destroy(result);
        result.* = .{
            .allocator = self.allocator,
            .recorded = recorded,
            .bindings = self.bindings,
            .configuration = self.configuration,
            .sample_input_authority = self.sample_input_authority,
            .statistics = .{
                .constraints_per_kind = .{
                    segment.constraint_count,
                    binary.constraint_count,
                    empty.constraint_count,
                },
                .roster_rows_per_kind = .{
                    segment.row_count,
                    binary.row_count,
                    empty.row_count,
                },
                .sampled_values = self.sample_input_authority.max_sample_count,
                .graph_inputs = recorded.input_count,
                .graph_nodes = recorded.nodes.len,
                .graph_outputs = recorded.outputs.len,
            },
            .authority = undefined,
        };
        try result.validateFinalizedRecording(
            self.manifests,
            self.air_program_ids,
        );
        result.authority = try mintCircuitAuthorityFromValidatedRecording(
            result,
        );
        try result.validate(self.manifests, self.air_program_ids);

        self.segment_layout.deinit();
        self.binary_layout.deinit();
        if (self.canonical_empty_layout) |*layout| layout.deinit();
        self.allocator.free(self.sampled_values);
        self.builder.deinit();
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
        return @ptrCast(result);
    }

    // The retained pointers are deliberately not copied into ConfigurationV3;
    // these helpers make their construction-time custody explicit to Zig's
    // generic recorder without widening the public serialized authority.
    fn configurationManifestSegment(
        self: *const HeterogeneousSessionV3,
    ) *const segment_manifest_mod.Manifest {
        return self.manifests.segment;
    }

    fn configurationManifestUniversal(
        self: *const HeterogeneousSessionV3,
    ) *const universal_manifest_mod.Manifest {
        return self.manifests.universal;
    }

    fn bindChildKind(self: *HeterogeneousSessionV3) !void {
        const one = recorder.Scalar.one();
        const segment = self.child_kind_selectors[proofKindIndex(.segment_leaf)];
        const binary = self.child_kind_selectors[proofKindIndex(.binary_node)];
        const empty = self.child_kind_selectors[proofKindIndex(.empty_leaf)];
        try self.builder.constrainZero(
            self.parent_binary_selector.mul(one.sub(self.parent_binary_selector)),
        );
        for (self.child_kind_selectors) |selector|
            try self.builder.constrainZero(selector.mul(one.sub(selector)));
        try self.builder.constrainZero(
            segment.add(binary).add(empty).sub(self.parent_binary_selector),
        );

        const height = self.statement_words[span_statement.canonical_layout.slot_height];
        try self.constrainActive(segment.add(empty).mul(height));
        const safe_height = height.add(one).sub(binary);
        const height_inverse = safe_height.inverse();
        try self.constrainActive(safe_height.mul(height_inverse).sub(one));
        try self.constrainActive(height.mul(height_inverse).sub(binary));

        const body_tag = self.statement_words[
            span_statement.canonical_layout.body_tag
        ];
        try self.constrainActive(segment.mul(body_tag.sub(
            recorder.Scalar.fromBase(M31.fromU64(@intFromEnum(
                span_statement.Tag.executed_body,
            ))),
        )));
        try self.constrainActive(empty.mul(body_tag.sub(
            recorder.Scalar.fromBase(M31.fromU64(@intFromEnum(
                span_statement.Tag.empty_body,
            ))),
        )));
    }

    fn constrainGlobalLogup(self: *HeterogeneousSessionV3) !void {
        const challenge = self.challenges.get(.recursion_statement_word);
        var public_sum = recorder.Scalar.zero();
        const scope = recorder.Scalar.fromBase(M31.fromU64(
            statement_input.PARENT_STATEMENT_SCOPE,
        ));
        for (self.statement_words, 0..) |word, word_index| {
            const tuple = [_]recorder.Scalar{
                scope,
                recorder.Scalar.fromBase(M31.fromU64(word_index)),
                word,
            };
            public_sum = public_sum.add((try challenge.combine(&tuple)).inverse());
        }
        var claimed_total = recorder.Scalar.zero();
        for (self.claim_inputs[0..SEGMENT_PHYSICAL_CLAIM_COUNT]) |claim|
            claimed_total = claimed_total.add(claim);
        const segment = self.child_kind_selectors[proofKindIndex(.segment_leaf)];
        const universal_branch = self.child_kind_selectors[
            proofKindIndex(.binary_node)
        ].add(self.child_kind_selectors[proofKindIndex(.empty_leaf)]);
        try self.builder.constrainZero(segment.mul(
            claimed_total.add(self.public_wire_boundary),
        ));
        try self.builder.constrainZero(universal_branch.mul(
            claimed_total.add(public_sum),
        ));
        try self.builder.constrainZero(
            universal_branch.mul(self.public_wire_boundary),
        );
    }

    fn constrainActive(
        self: *HeterogeneousSessionV3,
        value: recorder.Scalar,
    ) !void {
        try self.builder.constrainZero(self.parent_binary_selector.mul(value));
    }
};

pub fn recordingStorage(
    recording: *RecordedHeterogeneousCircuitV3,
) *RecordedHeterogeneousCircuitStorageV3 {
    return @ptrCast(@alignCast(recording));
}

pub fn recordingStorageConst(
    recording: *const RecordedHeterogeneousCircuitV3,
) *const RecordedHeterogeneousCircuitStorageV3 {
    return @ptrCast(@alignCast(recording));
}
