//! Typed component owner for schema-3 role-0 transcript rows 0--9.
//!
//! This constructor consumes only the opaque fresh-capture row owner. It does
//! not accept SegmentV2 `Program`, detached row slices, or a source digest as
//! admission. The sibling transcript cohort owns tree publication.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const rows_mod =
    @import("recursive_common_ethereum_incremental_leaf_transcript_rows_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const air = frontend.recursion.air;
const binding = air.universal_relation_binding;
const direct_program = air.direct_constraint_program;
const typed_component = air.universal_typed_component;
const universal = air.universal_challenges;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const FIRST_ROW: usize = 0;
pub const LAST_ROW: usize = 9;
pub const ROW_COUNT: usize = 10;
pub const ROWS_BASED_CONSTRUCTOR_AVAILABLE = true;
pub const SEGMENT_V2_NOMINAL_INPUT_ADMITTED = false;
pub const TREE_PUBLICATION_AVAILABLE = true;
pub const PRODUCTION_ACTIVATION = false;

pub const Error = error{
    EthereumIncrementalTranscriptComponentsMismatchV4,
};

pub const ControlRelation = binding.Binding(air.control);
pub const TranscriptAirRelation = binding.Binding(air.transcript_air);
pub const TranscriptBindingRelation = binding.Binding(air.transcript_binding);
pub const TranscriptStateRelation = binding.Binding(air.transcript_state);
pub const TranscriptWordRelation = binding.Binding(air.transcript_word);
pub const TranscriptPayloadRelation = binding.Binding(air.transcript_payload);
pub const PowCheckRelation = binding.Binding(air.pow_check);
pub const PowFrameRelation = binding.Binding(air.pow_frame);
pub const RelationChallengeRelation = binding.Binding(air.relation_challenge);
pub const VerifierRandomnessRelation = binding.Binding(air.verifier_randomness);

pub const ControlFramework = air.framework_interaction.Runtime(
    ControlRelation.Runtime,
);
pub const TranscriptAirFramework = air.framework_interaction.Runtime(
    TranscriptAirRelation.Runtime,
);
pub const TranscriptBindingFramework = air.framework_interaction.Runtime(
    TranscriptBindingRelation.Runtime,
);
pub const TranscriptStateFramework = air.framework_interaction.Runtime(
    TranscriptStateRelation.Runtime,
);
pub const TranscriptWordFramework = air.framework_interaction.Runtime(
    TranscriptWordRelation.Runtime,
);
pub const TranscriptPayloadFramework = air.framework_interaction.Runtime(
    TranscriptPayloadRelation.Runtime,
);
pub const PowCheckFramework = air.framework_interaction.Runtime(
    PowCheckRelation.Runtime,
);
pub const PowFrameFramework = air.framework_interaction.Runtime(
    PowFrameRelation.Runtime,
);
pub const RelationChallengeFramework = air.framework_interaction.Runtime(
    RelationChallengeRelation.Runtime,
);
pub const VerifierRandomnessFramework = air.framework_interaction.Runtime(
    VerifierRandomnessRelation.Runtime,
);

const ControlAdapter = typed_component.ComponentForManifest(
    air.control,
    ControlRelation,
    manifest_mod,
);
const TranscriptAirAdapter = typed_component.ComponentForManifest(
    air.transcript_air,
    TranscriptAirRelation,
    manifest_mod,
);
const TranscriptBindingAdapter = typed_component.ComponentForManifest(
    air.transcript_binding,
    TranscriptBindingRelation,
    manifest_mod,
);
const TranscriptStateAdapter = typed_component.ComponentForManifest(
    air.transcript_state,
    TranscriptStateRelation,
    manifest_mod,
);
const TranscriptWordAdapter = typed_component.ComponentForManifest(
    air.transcript_word,
    TranscriptWordRelation,
    manifest_mod,
);
const TranscriptPayloadAdapter = typed_component.ComponentForManifest(
    air.transcript_payload,
    TranscriptPayloadRelation,
    manifest_mod,
);
const PowCheckAdapter = typed_component.ComponentForManifest(
    air.pow_check,
    PowCheckRelation,
    manifest_mod,
);
const PowFrameAdapter = typed_component.ComponentForManifest(
    air.pow_frame,
    PowFrameRelation,
    manifest_mod,
);
const RelationChallengeAdapter = typed_component.ComponentForManifest(
    air.relation_challenge,
    RelationChallengeRelation,
    manifest_mod,
);
const VerifierRandomnessAdapter = typed_component.ComponentForManifest(
    air.verifier_randomness,
    VerifierRandomnessRelation,
    manifest_mod,
);

pub const ClaimsV4 = struct {
    values: [ROW_COUNT]QM31,

    pub fn bindInto(
        self: ClaimsV4,
        destination: *manifest_mod.ClaimVector,
    ) !void {
        for (self.values, 0..) |value, index|
            try destination.bind(@enumFromInt(index), value);
    }
};

pub const ComponentsV4 = struct {
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

    pub fn appendToGate(
        self: *const ComponentsV4,
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

pub fn OwnerV4(comptime Engine: type) type {
    const Rows = rows_mod.OwnerV4(Engine);

    return struct {
        allocator: std.mem.Allocator,
        rows: *const Rows,
        log_sizes: [ROW_COUNT]u32,
        parameters: ParametersV4,
        owners: OwnersV4,

        pub fn init(
            allocator: std.mem.Allocator,
            rows: *const Rows,
            manifest: *const manifest_mod.Manifest,
        ) !@This() {
            try rows.validate();
            try manifest.validate();
            var selected_logs: [ROW_COUNT]u32 = undefined;
            inline for (0..ROW_COUNT) |index| {
                const key: manifest_mod.ComponentKey = @enumFromInt(index);
                selected_logs[index] = (try manifest.placement(key))
                    .geometry.log_size;
            }
            var owners = try OwnersV4.init(allocator);
            errdefer owners.deinit();
            var result = @This(){
                .allocator = allocator,
                .rows = rows,
                .log_sizes = selected_logs,
                .parameters = ParametersV4.role0(),
                .owners = owners,
            };
            try result.validateAgainst(manifest);
            return result;
        }

        pub fn deinit(self: *@This()) void {
            self.owners.deinit();
            self.* = undefined;
        }

        pub fn validateAgainst(
            self: *const @This(),
            manifest: *const manifest_mod.Manifest,
        ) !void {
            try self.rows.validate();
            try manifest.validate();
            try self.owners.validate();
            const view = try self.rows.views();
            if (!std.meta.eql(self.parameters, ParametersV4.role0())) {
                return error.EthereumIncrementalTranscriptComponentsMismatchV4;
            }
            inline for (0..ROW_COUNT) |index| {
                const key: manifest_mod.ComponentKey = @enumFromInt(index);
                const placement = try manifest.placement(key);
                if (self.log_sizes[index] < view.log_sizes[index] or
                    self.log_sizes[index] >= 31 or
                    placement.geometry.log_size != self.log_sizes[index] or
                    !std.meta.eql(
                        placement.geometry,
                        expectedGeometry(key, self.log_sizes[index]),
                    ))
                {
                    return error.EthereumIncrementalTranscriptComponentsMismatchV4;
                }
            }
        }

        pub fn initComponents(
            self: *const @This(),
            manifest: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
            claims: ClaimsV4,
        ) !ComponentsV4 {
            try self.validateAgainst(manifest);
            try relations.validate();
            return .{
                .control = try ControlAdapter.init(
                    &self.owners.control.definition,
                    self.owners.control.relation,
                    manifest,
                    .control,
                    self.log_sizes[0],
                    self.parameters.control,
                    relations,
                    claims.values[0],
                ),
                .transcript_air = try TranscriptAirAdapter.init(
                    &self.owners.transcript_air.definition,
                    self.owners.transcript_air.relation,
                    manifest,
                    .transcript_air,
                    self.log_sizes[1],
                    self.parameters.transcript_air,
                    relations,
                    claims.values[1],
                ),
                .transcript_binding = try TranscriptBindingAdapter.init(
                    &self.owners.transcript_binding.definition,
                    self.owners.transcript_binding.relation,
                    manifest,
                    .transcript_binding,
                    self.log_sizes[2],
                    self.parameters.transcript_binding,
                    relations,
                    claims.values[2],
                ),
                .transcript_state = try TranscriptStateAdapter.init(
                    &self.owners.transcript_state.definition,
                    self.owners.transcript_state.relation,
                    manifest,
                    .transcript_state,
                    self.log_sizes[3],
                    self.parameters.transcript_state,
                    relations,
                    claims.values[3],
                ),
                .transcript_word = try TranscriptWordAdapter.init(
                    &self.owners.transcript_word.definition,
                    self.owners.transcript_word.relation,
                    manifest,
                    .transcript_word,
                    self.log_sizes[4],
                    self.parameters.transcript_word,
                    relations,
                    claims.values[4],
                ),
                .transcript_payload = try TranscriptPayloadAdapter.init(
                    &self.owners.transcript_payload.definition,
                    self.owners.transcript_payload.relation,
                    manifest,
                    .transcript_payload,
                    self.log_sizes[5],
                    self.parameters.transcript_payload,
                    relations,
                    claims.values[5],
                ),
                .pow_check = try PowCheckAdapter.init(
                    &self.owners.pow_check.definition,
                    self.owners.pow_check.relation,
                    manifest,
                    .pow_check,
                    self.log_sizes[6],
                    self.parameters.pow_check,
                    relations,
                    claims.values[6],
                ),
                .pow_frame = try PowFrameAdapter.init(
                    &self.owners.pow_frame.definition,
                    self.owners.pow_frame.relation,
                    manifest,
                    .pow_frame,
                    self.log_sizes[7],
                    self.parameters.pow_frame,
                    relations,
                    claims.values[7],
                ),
                .relation_challenge = try RelationChallengeAdapter.init(
                    &self.owners.relation_challenge.definition,
                    self.owners.relation_challenge.relation,
                    manifest,
                    .relation_challenge,
                    self.log_sizes[8],
                    self.parameters.relation_challenge,
                    relations,
                    claims.values[8],
                ),
                .verifier_randomness = try VerifierRandomnessAdapter.init(
                    &self.owners.verifier_randomness.definition,
                    self.owners.verifier_randomness.relation,
                    manifest,
                    .verifier_randomness,
                    self.log_sizes[9],
                    self.parameters.verifier_randomness,
                    relations,
                    claims.values[9],
                ),
            };
        }
    };
}

const ParametersV4 = struct {
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

    fn role0() ParametersV4 {
        const selectors = air.control_witness.ProofKind.segment_leaf.selectors();
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
                    air.relation_challenge_witness
                        .AIR_EVALUATION_CHALLENGE_SCOPE,
                ),
                M31.fromCanonical(
                    air.relation_challenge_witness
                        .VM_PUBLIC_LOGUP_CHALLENGE_SCOPE,
                ),
            },
            .verifier_randomness = selectors[0..2].*,
        };
    }
};

fn AirOwner(
    comptime Air: type,
    comptime Relation: type,
) type {
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
                return error.EthereumIncrementalTranscriptComponentsMismatchV4;
        }

        fn deinit(self: *@This()) void {
            self.definition.deinit();
            self.* = undefined;
        }
    };
}

pub const OwnersV4 = struct {
    control: AirOwner(air.control, ControlRelation),
    transcript_air: AirOwner(air.transcript_air, TranscriptAirRelation),
    transcript_binding: AirOwner(air.transcript_binding, TranscriptBindingRelation),
    transcript_state: AirOwner(air.transcript_state, TranscriptStateRelation),
    transcript_word: AirOwner(air.transcript_word, TranscriptWordRelation),
    transcript_payload: AirOwner(air.transcript_payload, TranscriptPayloadRelation),
    pow_check: AirOwner(air.pow_check, PowCheckRelation),
    pow_frame: AirOwner(air.pow_frame, PowFrameRelation),
    relation_challenge: AirOwner(air.relation_challenge, RelationChallengeRelation),
    verifier_randomness: AirOwner(air.verifier_randomness, VerifierRandomnessRelation),

    fn init(allocator: std.mem.Allocator) !OwnersV4 {
        var control = try AirOwner(air.control, ControlRelation).init(allocator);
        errdefer control.deinit();
        var transcript_air = try AirOwner(
            air.transcript_air,
            TranscriptAirRelation,
        ).init(allocator);
        errdefer transcript_air.deinit();
        var transcript_binding = try AirOwner(
            air.transcript_binding,
            TranscriptBindingRelation,
        ).init(allocator);
        errdefer transcript_binding.deinit();
        var transcript_state = try AirOwner(
            air.transcript_state,
            TranscriptStateRelation,
        ).init(allocator);
        errdefer transcript_state.deinit();
        var transcript_word = try AirOwner(
            air.transcript_word,
            TranscriptWordRelation,
        ).init(allocator);
        errdefer transcript_word.deinit();
        var transcript_payload = try AirOwner(
            air.transcript_payload,
            TranscriptPayloadRelation,
        ).init(allocator);
        errdefer transcript_payload.deinit();
        var pow_check = try AirOwner(
            air.pow_check,
            PowCheckRelation,
        ).init(allocator);
        errdefer pow_check.deinit();
        var pow_frame = try AirOwner(
            air.pow_frame,
            PowFrameRelation,
        ).init(allocator);
        errdefer pow_frame.deinit();
        var relation_challenge = try AirOwner(
            air.relation_challenge,
            RelationChallengeRelation,
        ).init(allocator);
        errdefer relation_challenge.deinit();
        var verifier_randomness = try AirOwner(
            air.verifier_randomness,
            VerifierRandomnessRelation,
        ).init(allocator);
        errdefer verifier_randomness.deinit();
        return .{
            .control = control,
            .transcript_air = transcript_air,
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

    fn validate(self: *const OwnersV4) !void {
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

    fn deinit(self: *OwnersV4) void {
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

fn expectedGeometry(
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

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or FIRST_ROW != 0 or
        LAST_ROW != 9 or ROW_COUNT != 10 or !ROWS_BASED_CONSTRUCTOR_AVAILABLE or
        SEGMENT_V2_NOMINAL_INPUT_ADMITTED or !TREE_PUBLICATION_AVAILABLE or
        PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental transcript components V4 drifted");
    }
}
