//! Internal shard of recursion_air_composition_circuit_v3.zig; use the public facade.

const dependency_0 = @import("recursion_air_composition_circuit_canonical_empty_program.zig");
const dependency_1 = @import("recursion_air_composition_circuit_program_roster.zig");
const dependency_2 = @import("recursion_air_composition_circuit_circuit_view.zig");
const dependency_4 = @import("recursion_air_composition_circuit_write_inputs_from_validated_profile_and_policy.zig");
const dependency_5 = @import("recursion_air_composition_circuit_authority_validation.zig");

const std = dependency_0.std;
const circle = dependency_0.circle;
const QM31 = dependency_0.QM31;
const graph_mod = dependency_0.graph_mod;
const recorder = dependency_0.recorder;
const segment_manifest_mod = dependency_0.segment_manifest_mod;
const universal_manifest_mod = dependency_0.universal_manifest_mod;
const capture_layout_v3 = dependency_0.capture_layout_v3;
const segment_recorder_v3 = dependency_0.segment_recorder_v3;
const COMPOSITION_CLAIM_INPUT_COUNT = dependency_0.COMPOSITION_CLAIM_INPUT_COUNT;
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
const recordClaimPolicyConstraintsForManifestPolicy =
    dependency_4.recordClaimPolicyConstraintsForManifestPolicy;
const writeInputsFromValidatedConfiguration = dependency_4.writeInputsFromValidatedConfiguration;
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

    pub fn configurationSnapshotAuthenticatedH1(
        self: *const RecordedHeterogeneousCircuitV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        h1_manifest: anytype,
    ) !ConfigurationV3 {
        try self.validateAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
        return recordingStorageConst(self).configuration;
    }

    pub fn validate(
        self: *const RecordedHeterogeneousCircuitV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
    ) !void {
        try recordingStorageConst(self).validate(manifests, air_program_ids);
    }

    pub fn validateAuthenticatedH1(
        self: *const RecordedHeterogeneousCircuitV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        h1_manifest: anytype,
    ) !void {
        try recordingStorageConst(self).validateAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
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

    pub fn validatedViewAuthenticatedH1(
        self: *const RecordedHeterogeneousCircuitV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        h1_manifest: anytype,
    ) !*const CircuitViewV3 {
        try self.validateAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
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

    pub fn validatedAuthorityAuthenticatedH1(
        self: *const RecordedHeterogeneousCircuitV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        h1_manifest: anytype,
    ) !*const CircuitAuthorityV3 {
        try self.validateAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
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
    authenticated_h1_empty_layout: ?capture_layout_v3.CaptureLayoutV3 = null,
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
    authenticated_h1_empty_split_composition: recorder.Scalar = undefined,
    segment_denominators: recorder.DenominatorCache,
    universal_denominators: recorder.DenominatorCache,
    authenticated_h1_empty_denominators: recorder.DenominatorCache =
        .{null} ** circle.M31_CIRCLE_LOG_ORDER,
    program_results: [PROGRAM_KIND_COUNT]?segment_recorder_v3.ProgramResultV3 =
        .{null} ** PROGRAM_KIND_COUNT,
    programs_recorded: bool = false,
    failed: bool = false,
    finished: bool = false,

    const Construction = @import("recursion_heterogeneous_construction.zig");
    pub const create = Construction.create;
    pub const createWithCanonicalEmpty = Construction.createWithCanonicalEmpty;
    pub const createWithAuthenticatedH1 = Construction.createWithAuthenticatedH1;
    pub const createWithAuthenticatedH1AndCanonicalEmpty = Construction.createWithAuthenticatedH1AndCanonicalEmpty;
    const createAuthenticatedH1Inner = Construction.createAuthenticatedH1Inner;
    const createInner = Construction.createInner;
    const bindInputs = Construction.bindInputs;
    const bindChildKind = Construction.bindChildKind;
    const constrainGlobalLogup = Construction.constrainGlobalLogup;
    const constrainActive = Construction.constrainActive;

    /// V3.1 construction path for the proofless empty base case.  The exact
    /// publication-bound program must use the layout deterministically derived
    /// from the same binary verifier capture retained by this session.
    /// Append-only ordinary-H1 construction. The Binary selector is backed by
    /// the authenticated 12-placement H1 manifest, while Empty retains a
    /// separately validated universal layout. Candidate 44-claim captures
    /// cannot pass the descriptor's exact 12-row admission.
    /// The ordinary-H1 Binary program and proofless canonical Empty program
    /// share the frozen three-selector ABI without sharing capture authority.
    /// `universal_empty_capture` authenticates only the universal shell from
    /// which the canonical-empty layout was sealed; H1 retains its distinct
    /// 12-placement layout and provider row.
    pub fn deinit(self: *HeterogeneousSessionV3) void {
        if (self.builder.active) self.builder.deactivate();
        self.builder.deinit();
        self.segment_layout.deinit();
        self.binary_layout.deinit();
        if (self.authenticated_h1_empty_layout) |*layout| layout.deinit();
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

    /// Records Segment and Empty through their frozen programs while the
    /// Binary slot uses the manifest-parametric 12-row H1 recorder. The
    /// callback is the manifest owner's exact ordered cohort implementation;
    /// `finishProgram` still enforces every row and placement.
    pub fn recordProgramsWithAuthenticatedH1(
        self: *HeterogeneousSessionV3,
        comptime h1_manifest_contract: type,
        h1_manifest: *const h1_manifest_contract.Manifest,
        segment_components: anytype,
        h1_components: anytype,
        comptime record_h1_cohort: anytype,
        empty_components: anytype,
    ) !void {
        if (self.finished or self.programs_recorded or self.failed or
            !self.builder.active or self.authenticated_h1_empty_layout == null)
        {
            return error.InvalidHeterogeneousProgram;
        }
        self.configuration.validateAgainstAuthenticatedH1(
            self.manifests,
            self.air_program_ids,
            h1_manifest,
        ) catch |err| {
            self.failed = true;
            return err;
        };
        self.recordSegmentProgram(segment_components) catch |err| {
            self.failed = true;
            return err;
        };
        self.recordAuthenticatedH1Program(
            h1_manifest_contract,
            h1_manifest,
            h1_components,
            record_h1_cohort,
        ) catch |err| {
            self.failed = true;
            return err;
        };
        var empty_program = self.beginEmptyProgram() catch |err| {
            self.failed = true;
            return err;
        };
        self.program_results[proofKindIndex(.empty_leaf)] =
            empty_program.recordCompleteUniversalCohort(empty_components) catch |err| {
                self.failed = true;
                return err;
            };
        self.programs_recorded = true;
    }

    /// Records the same authenticated ordinary-H1 Binary cohort while Empty
    /// consumes its separately sealed proofless canonical catalog. Neither
    /// lane may borrow the other's capture layout or denominator cache.
    pub fn recordProgramsWithAuthenticatedH1AndCanonicalEmptyCatalog(
        self: *HeterogeneousSessionV3,
        comptime h1_manifest_contract: type,
        h1_manifest: *const h1_manifest_contract.Manifest,
        segment_components: anytype,
        h1_components: anytype,
        comptime record_h1_cohort: anytype,
        empty_owners: anytype,
        empty_poseidon: *const segment_recorder_v3.EmptyProgramRecorderV3.PoseidonAdapter,
        empty_range: *const segment_recorder_v3.EmptyProgramRecorderV3.RangeCheck8x8Adapter,
    ) !void {
        if (self.finished or self.programs_recorded or self.failed or
            !self.builder.active or self.authenticated_h1_empty_layout == null or
            self.canonical_empty_program == null or
            self.canonical_empty_layout == null)
        {
            return error.InvalidHeterogeneousProgram;
        }
        self.configuration.validateAgainstAuthenticatedH1(
            self.manifests,
            self.air_program_ids,
            h1_manifest,
        ) catch |err| {
            self.failed = true;
            return err;
        };
        self.recordSegmentProgram(segment_components) catch |err| {
            self.failed = true;
            return err;
        };
        self.recordAuthenticatedH1Program(
            h1_manifest_contract,
            h1_manifest,
            h1_components,
            record_h1_cohort,
        ) catch |err| {
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

    fn recordAuthenticatedH1Program(
        self: *HeterogeneousSessionV3,
        comptime h1_manifest_contract: type,
        h1_manifest: *const h1_manifest_contract.Manifest,
        h1_components: anytype,
        comptime record_h1_cohort: anytype,
    ) !void {
        const H1ProgramRecorder = segment_recorder_v3.ProgramRecorderForManifest(
            h1_manifest_contract,
            .binary_node,
            dependency_0.H1_PHYSICAL_CLAIM_COUNT,
        );
        var binary_program = try H1ProgramRecorder.initAuthenticatedBinary(
            &self.builder,
            h1_manifest,
            .ethereum_poseidon_h1_v1,
            &self.binary_layout,
            self.sampled_values[0..self.binary_layout.sampled_value_count],
            &self.claim_inputs,
            &self.challenges,
            self.composition_randomness,
            self.oods_point,
            &self.universal_denominators,
        );
        self.program_results[proofKindIndex(.binary_node)] =
            try record_h1_cohort(&binary_program, h1_components);
    }

    fn beginEmptyProgram(
        self: *HeterogeneousSessionV3,
    ) !segment_recorder_v3.EmptyProgramRecorderV3 {
        const layout = if (self.authenticated_h1_empty_layout) |*value|
            value
        else
            &self.binary_layout;
        const denominators = if (self.authenticated_h1_empty_layout != null)
            &self.authenticated_h1_empty_denominators
        else
            &self.universal_denominators;
        return segment_recorder_v3.EmptyProgramRecorderV3.init(
            &self.builder,
            self.configurationManifestUniversal(),
            layout,
            self.sampled_values[0..layout.sampled_value_count],
            &self.claim_inputs,
            &self.challenges,
            self.composition_randomness,
            self.oods_point,
            denominators,
        );
    }

    fn beginCanonicalEmptyProgram(
        self: *HeterogeneousSessionV3,
    ) !segment_recorder_v3.EmptyProgramRecorderV3 {
        const layout = if (self.canonical_empty_layout) |*value|
            value
        else
            return error.InvalidHeterogeneousProgram;
        const denominators = if (self.authenticated_h1_empty_layout != null)
            &self.authenticated_h1_empty_denominators
        else
            &self.universal_denominators;
        return segment_recorder_v3.EmptyProgramRecorderV3.initCanonicalEmpty(
            &self.builder,
            self.configurationManifestUniversal(),
            layout,
            self.sampled_values[0..layout.internal_sample_count],
            &self.claim_inputs,
            &self.challenges,
            self.composition_randomness,
            self.oods_point,
            denominators,
        );
    }

    /// Finalizes an owned graph but deliberately withholds production circuit
    /// authority until the real empty-cohort integration gate is present.
    const Publication = @import("recursion_heterogeneous_publication.zig");
    pub const finish = Publication.finish;
    pub const finishAuthenticatedH1 = Publication.finishAuthenticatedH1;

    /// Finalizes the ordinary-H1 three-selector graph and cold-validates its
    /// binary descriptor and statistics against the reopened H1 manifest.
    /// This remains a nonproduction recorder capability.

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
