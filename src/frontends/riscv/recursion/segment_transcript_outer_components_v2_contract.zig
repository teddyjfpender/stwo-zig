//! Internal segment transcript outer components v2 authority shard; use segment_transcript_outer_components_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const PcsConfig = stwo_core.pcs.PcsConfig;

pub const public_data_v2 = @import("../air/public_data_v2.zig");
pub const statement_v1 = @import("../air/statement.zig");
pub const direct_program = @import("air/direct_constraint_program.zig");
pub const framework = @import("air/framework_interaction.zig");
pub const binding = @import("air/universal_relation_binding.zig");
pub const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
pub const relation_interaction = @import("air/relation_interaction.zig");
pub const roster = @import("air/universal_roster.zig");
pub const schedule = @import("air/verifier_schedule.zig");
pub const typed_component = @import("air/universal_typed_component.zig");
pub const universal = @import("air/universal_challenges.zig");
pub const source_v2 = @import("segment_transcript_outer_source_v2.zig");
pub const transcript = @import("transcript_program_v2.zig");

pub const control_air = @import("air/control.zig");
pub const control_witness = @import("air/control_witness.zig");
pub const transcript_air = @import("air/transcript_air.zig");
pub const transcript_air_witness = @import("air/transcript_air_witness.zig");
pub const transcript_binding_air = @import("air/transcript_binding.zig");
pub const transcript_binding_witness = @import("air/transcript_binding_witness.zig");
pub const transcript_state_air = @import("air/transcript_state.zig");
pub const transcript_state_witness = @import("air/transcript_state_witness.zig");
pub const transcript_word_air = @import("air/transcript_word.zig");
pub const transcript_word_witness = @import("air/transcript_word_witness.zig");
pub const transcript_payload_air = @import("air/transcript_payload.zig");
pub const pow_check_air = @import("air/pow_check.zig");
pub const pow_frame_air = @import("air/pow_frame.zig");
pub const relation_challenge_air = @import("air/relation_challenge.zig");
pub const relation_challenge_witness = @import("air/relation_challenge_witness.zig");
pub const verifier_randomness_air = @import("air/verifier_randomness.zig");
pub const verifier_randomness_witness = @import("air/verifier_randomness_witness.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const FIRST_ROW: usize = source_v2.FIRST_ROW;
pub const ROW_COUNT: usize = source_v2.ROW_COUNT;
pub const LAST_ROW: usize = source_v2.LAST_ROW;
pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const TREE_WRITES_FAIL_BEFORE_FIRST_WRITE = true;
pub const SHARED_PROVIDER_COMPONENT_COUNT: usize = 1;
pub const PRODUCTION_ACTIVATION = false;

pub const WORKSPACE_DOMAIN =
    "stwo-zig/typed-air/segment-transcript-components-v2/workspace/v1\x00";

pub const ControlRelation = binding.Binding(control_air);
pub const TranscriptAirRelation = binding.Binding(transcript_air);
pub const TranscriptBindingRelation = binding.Binding(transcript_binding_air);
pub const TranscriptStateRelation = binding.Binding(transcript_state_air);
pub const TranscriptWordRelation = binding.Binding(transcript_word_air);
pub const TranscriptPayloadRelation = binding.Binding(transcript_payload_air);
pub const PowCheckRelation = binding.Binding(pow_check_air);
pub const PowFrameRelation = binding.Binding(pow_frame_air);
pub const RelationChallengeRelation = binding.Binding(relation_challenge_air);
pub const VerifierRandomnessRelation = binding.Binding(verifier_randomness_air);

pub const ControlFramework = framework.Runtime(ControlRelation.Runtime);
pub const TranscriptAirFramework = framework.Runtime(TranscriptAirRelation.Runtime);
pub const TranscriptBindingFramework = framework.Runtime(TranscriptBindingRelation.Runtime);
pub const TranscriptStateFramework = framework.Runtime(TranscriptStateRelation.Runtime);
pub const TranscriptWordFramework = framework.Runtime(TranscriptWordRelation.Runtime);
pub const TranscriptPayloadFramework = framework.Runtime(TranscriptPayloadRelation.Runtime);
pub const PowCheckFramework = framework.Runtime(PowCheckRelation.Runtime);
pub const PowFrameFramework = framework.Runtime(PowFrameRelation.Runtime);
pub const RelationChallengeFramework = framework.Runtime(RelationChallengeRelation.Runtime);
pub const VerifierRandomnessFramework = framework.Runtime(VerifierRandomnessRelation.Runtime);

pub const ControlAdapter = typed_component.ComponentForManifest(
    control_air,
    ControlRelation,
    manifest_mod,
);
pub const TranscriptAirAdapter = typed_component.ComponentForManifest(
    transcript_air,
    TranscriptAirRelation,
    manifest_mod,
);
pub const TranscriptBindingAdapter = typed_component.ComponentForManifest(
    transcript_binding_air,
    TranscriptBindingRelation,
    manifest_mod,
);
pub const TranscriptStateAdapter = typed_component.ComponentForManifest(
    transcript_state_air,
    TranscriptStateRelation,
    manifest_mod,
);
pub const TranscriptWordAdapter = typed_component.ComponentForManifest(
    transcript_word_air,
    TranscriptWordRelation,
    manifest_mod,
);
pub const TranscriptPayloadAdapter = typed_component.ComponentForManifest(
    transcript_payload_air,
    TranscriptPayloadRelation,
    manifest_mod,
);
pub const PowCheckAdapter = typed_component.ComponentForManifest(
    pow_check_air,
    PowCheckRelation,
    manifest_mod,
);
pub const PowFrameAdapter = typed_component.ComponentForManifest(
    pow_frame_air,
    PowFrameRelation,
    manifest_mod,
);
pub const RelationChallengeAdapter = typed_component.ComponentForManifest(
    relation_challenge_air,
    RelationChallengeRelation,
    manifest_mod,
);
pub const VerifierRandomnessAdapter = typed_component.ComponentForManifest(
    verifier_randomness_air,
    VerifierRandomnessRelation,
    manifest_mod,
);

pub const Error = error{
    ArithmeticOverflow,
    CacheNotPrepared,
    ConstraintViolation,
    DestinationAlias,
    DestinationColumnCountMismatch,
    DestinationLogSizeMismatch,
    EventProjectionMismatch,
    InvalidProviderRange,
    InvalidTreeIndex,
    ManifestGeometryMismatch,
    PreparedAuthorityMismatch,
    WorkspaceGeometryMismatch,
    WorkspaceSealMismatch,
};

pub const NativeInputs = struct {
    program: *const transcript.Program,
    execution: *const transcript.Execution,
    evidence: *const transcript.Evidence,
    plan: *const schedule.Plan,
    pcs_config: PcsConfig,
    data: *const public_data_v2.PublicDataV2,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
};

pub const Claims = struct {
    control: QM31,
    transcript_air: QM31,
    transcript_binding: QM31,
    transcript_state: QM31,
    transcript_word: QM31,
    transcript_payload: QM31,
    pow_check: QM31,
    pow_frame: QM31,
    relation_challenge: QM31,
    verifier_randomness: QM31,

    pub fn asArray(self: Claims) [ROW_COUNT]QM31 {
        return .{
            self.control,
            self.transcript_air,
            self.transcript_binding,
            self.transcript_state,
            self.transcript_word,
            self.transcript_payload,
            self.pow_check,
            self.pow_frame,
            self.relation_challenge,
            self.verifier_randomness,
        };
    }

    pub fn bindInto(
        self: Claims,
        vector: *manifest_mod.ClaimVector,
    ) !void {
        for (self.asArray(), 0..) |value, index| {
            try vector.bind(@enumFromInt(FIRST_ROW + index), value);
        }
    }
};

pub const Components = struct {
    control: ControlAdapter,
    transcript_air: TranscriptAirAdapter,
    transcript_binding: TranscriptBindingAdapter,
    transcript_state: TranscriptStateAdapter,
    transcript_word: TranscriptWordAdapter,
    transcript_payload: TranscriptPayloadAdapter,
    pow_check: PowCheckAdapter,
    pow_frame: PowFrameAdapter,
    relation_challenge: RelationChallengeAdapter,
    verifier_randomness: VerifierRandomnessAdapter,

    /// Appends exactly universal rows 0--9. The V2 proof gate remains open for
    /// rows 10--37 and refuses any out-of-order binding.
    pub fn appendToGate(
        self: *const Components,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try gate.append(manifest, try self.control.binding(manifest));
        try gate.append(manifest, try self.transcript_air.binding(manifest));
        try gate.append(manifest, try self.transcript_binding.binding(manifest));
        try gate.append(manifest, try self.transcript_state.binding(manifest));
        try gate.append(manifest, try self.transcript_word.binding(manifest));
        try gate.append(manifest, try self.transcript_payload.binding(manifest));
        try gate.append(manifest, try self.pow_check.binding(manifest));
        try gate.append(manifest, try self.pow_frame.binding(manifest));
        try gate.append(manifest, try self.relation_challenge.binding(manifest));
        try gate.append(manifest, try self.verifier_randomness.binding(manifest));
    }
};

pub fn AirOwner(comptime Air: type, comptime Relation: type) type {
    return struct {
        definition: Air.Definition,
        relation: Relation.Plan,
        direct: direct_program.Program,

        fn init(allocator: std.mem.Allocator) !@This() {
            var definition = try Air.build(allocator);
            errdefer definition.deinit();
            return .{
                .relation = try Relation.authenticate(&definition),
                .direct = try direct_program.authenticate(
                    &definition.arena,
                    Air.SEMANTIC_DIGEST,
                    Air.LOGICAL_INPUT_COUNT,
                ),
                .definition = definition,
            };
        }

        fn validate(self: *const @This()) !void {
            try self.definition.validate();
            try self.relation.validateAgainst(
                &self.definition.arena,
                Air.SEMANTIC_DIGEST,
                Relation.events(&self.definition),
            );
            const expected = try direct_program.authenticate(
                &self.definition.arena,
                Air.SEMANTIC_DIGEST,
                Air.LOGICAL_INPUT_COUNT,
            );
            if (!std.meta.eql(expected, self.direct))
                return error.PreparedAuthorityMismatch;
        }

        fn deinit(self: *@This()) void {
            self.definition.deinit();
            self.* = undefined;
        }
    };
}

pub const Owners = struct {
    control: AirOwner(control_air, ControlRelation),
    transcript_air: AirOwner(transcript_air, TranscriptAirRelation),
    transcript_binding: AirOwner(transcript_binding_air, TranscriptBindingRelation),
    transcript_state: AirOwner(transcript_state_air, TranscriptStateRelation),
    transcript_word: AirOwner(transcript_word_air, TranscriptWordRelation),
    transcript_payload: AirOwner(transcript_payload_air, TranscriptPayloadRelation),
    pow_check: AirOwner(pow_check_air, PowCheckRelation),
    pow_frame: AirOwner(pow_frame_air, PowFrameRelation),
    relation_challenge: AirOwner(relation_challenge_air, RelationChallengeRelation),
    verifier_randomness: AirOwner(verifier_randomness_air, VerifierRandomnessRelation),

    pub fn init(allocator: std.mem.Allocator) !Owners {
        var control = try AirOwner(control_air, ControlRelation).init(allocator);
        errdefer control.deinit();
        var transcript_air_owner = try AirOwner(
            transcript_air,
            TranscriptAirRelation,
        ).init(allocator);
        errdefer transcript_air_owner.deinit();
        var transcript_binding = try AirOwner(
            transcript_binding_air,
            TranscriptBindingRelation,
        ).init(allocator);
        errdefer transcript_binding.deinit();
        var transcript_state = try AirOwner(
            transcript_state_air,
            TranscriptStateRelation,
        ).init(allocator);
        errdefer transcript_state.deinit();
        var transcript_word = try AirOwner(
            transcript_word_air,
            TranscriptWordRelation,
        ).init(allocator);
        errdefer transcript_word.deinit();
        var transcript_payload = try AirOwner(
            transcript_payload_air,
            TranscriptPayloadRelation,
        ).init(allocator);
        errdefer transcript_payload.deinit();
        var pow_check = try AirOwner(pow_check_air, PowCheckRelation).init(allocator);
        errdefer pow_check.deinit();
        var pow_frame = try AirOwner(pow_frame_air, PowFrameRelation).init(allocator);
        errdefer pow_frame.deinit();
        var relation_challenge = try AirOwner(
            relation_challenge_air,
            RelationChallengeRelation,
        ).init(allocator);
        errdefer relation_challenge.deinit();
        var verifier_randomness = try AirOwner(
            verifier_randomness_air,
            VerifierRandomnessRelation,
        ).init(allocator);
        errdefer verifier_randomness.deinit();
        return .{
            .control = control,
            .transcript_air = transcript_air_owner,
            .transcript_binding = transcript_binding,
            .transcript_state = transcript_state,
            .transcript_word = transcript_word,
            .transcript_payload = transcript_payload,
            .pow_check = pow_check,
            .pow_frame = pow_frame,
            .relation_challenge = relation_challenge,
            .verifier_randomness = verifier_randomness,
        };
    }

    pub fn validate(self: *const Owners) !void {
        try self.control.validate();
        try self.transcript_air.validate();
        try self.transcript_binding.validate();
        try self.transcript_state.validate();
        try self.transcript_word.validate();
        try self.transcript_payload.validate();
        try self.pow_check.validate();
        try self.pow_frame.validate();
        try self.relation_challenge.validate();
        try self.verifier_randomness.validate();
    }

    pub fn deinit(self: *Owners) void {
        self.verifier_randomness.deinit();
        self.relation_challenge.deinit();
        self.pow_frame.deinit();
        self.pow_check.deinit();
        self.transcript_payload.deinit();
        self.transcript_word.deinit();
        self.transcript_state.deinit();
        self.transcript_binding.deinit();
        self.transcript_air.deinit();
        self.control.deinit();
        self.* = undefined;
    }
};

pub const Parameters = struct {
    control: [ControlAdapter.PARAMETER_COLUMN_COUNT]M31,
    transcript_air: [TranscriptAirAdapter.PARAMETER_COLUMN_COUNT]M31,
    transcript_binding: [TranscriptBindingAdapter.PARAMETER_COLUMN_COUNT]M31,
    transcript_state: [TranscriptStateAdapter.PARAMETER_COLUMN_COUNT]M31,
    transcript_word: [TranscriptWordAdapter.PARAMETER_COLUMN_COUNT]M31,
    transcript_payload: [TranscriptPayloadAdapter.PARAMETER_COLUMN_COUNT]M31,
    pow_check: [PowCheckAdapter.PARAMETER_COLUMN_COUNT]M31,
    pow_frame: [PowFrameAdapter.PARAMETER_COLUMN_COUNT]M31,
    relation_challenge: [RelationChallengeAdapter.PARAMETER_COLUMN_COUNT]M31,
    verifier_randomness: [VerifierRandomnessAdapter.PARAMETER_COLUMN_COUNT]M31,

    pub fn segmentV2() Parameters {
        const selectors = control_witness.ProofKind.segment_leaf.selectors();
        return .{
            .control = selectors[0..2].*,
            .transcript_air = .{},
            .transcript_binding = selectors[0..2].*,
            .transcript_state = selectors[0..2].*,
            .transcript_word = selectors[0..2].*,
            .transcript_payload = selectors[0..2].*,
            .pow_check = .{},
            .pow_frame = .{},
            .relation_challenge = selectors[0..2].* ++ .{
                M31.fromCanonical(
                    relation_challenge_witness.AIR_EVALUATION_CHALLENGE_SCOPE,
                ),
                M31.fromCanonical(
                    relation_challenge_witness.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE,
                ),
            },
            .verifier_randomness = selectors[0..2].*,
        };
    }
};

pub fn rowIndex(key: manifest_mod.ComponentKey) usize {
    const index = manifest_mod.keyIndex(key);
    std.debug.assert(index >= FIRST_ROW and index <= LAST_ROW);
    return index - FIRST_ROW;
}

pub fn expectedGeometry(
    key: manifest_mod.ComponentKey,
    log_size: u32,
) manifest_mod.Geometry {
    return switch (key) {
        .control => ControlAdapter.manifestGeometry(.control, log_size),
        .transcript_air => TranscriptAirAdapter.manifestGeometry(
            .transcript_air,
            log_size,
        ),
        .transcript_binding => TranscriptBindingAdapter.manifestGeometry(
            .transcript_binding,
            log_size,
        ),
        .transcript_state => TranscriptStateAdapter.manifestGeometry(
            .transcript_state,
            log_size,
        ),
        .transcript_word => TranscriptWordAdapter.manifestGeometry(
            .transcript_word,
            log_size,
        ),
        .transcript_payload => TranscriptPayloadAdapter.manifestGeometry(
            .transcript_payload,
            log_size,
        ),
        .pow_check => PowCheckAdapter.manifestGeometry(.pow_check, log_size),
        .pow_frame => PowFrameAdapter.manifestGeometry(.pow_frame, log_size),
        .relation_challenge => RelationChallengeAdapter.manifestGeometry(
            .relation_challenge,
            log_size,
        ),
        .verifier_randomness => VerifierRandomnessAdapter.manifestGeometry(
            .verifier_randomness,
            log_size,
        ),
        else => unreachable,
    };
}
