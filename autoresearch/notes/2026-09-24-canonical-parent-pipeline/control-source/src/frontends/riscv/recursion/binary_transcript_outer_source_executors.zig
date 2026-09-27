//! Internal shard of binary_transcript_outer_source.zig; use the public facade.

const dependency_2 = @import("binary_transcript_outer_source_stage.zig");
const dependency_3 = @import("binary_transcript_outer_source_source_column_count.zig");

const validateExecutorBinding = dependency_2.validateExecutorBinding;
const traceSize = dependency_3.traceSize;

pub const std = @import("std");

pub const interaction_workspace = @import("binary_transcript_outer_source_interaction_workspace.zig");

pub const domain_audit = @import("binary_transcript_outer_source_domain_audit.zig");

pub const component_init = @import("binary_transcript_outer_source_component_init.zig");

pub const interaction_fill = @import("binary_transcript_outer_source_interaction_fill.zig");

pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;

pub const QM31 = stwo_core.fields.qm31.QM31;

pub const fixed_wire = @import("fixed_wire.zig");

pub const binary_authority = @import("binary_pair_authority.zig");

pub const air = @import("air/mod.zig");

pub const adapter = air.universal_typed_component;

pub const framework = air.framework_interaction;

pub const relation_interaction = air.relation_interaction;

pub const manifest_mod = air.universal_adapter_manifest;

pub const binding = air.universal_relation_binding;

pub const roster = air.universal_roster;

pub const schedule = air.verifier_schedule;

pub const universal = air.universal_challenges;

pub const universal_manifest = air.universal_manifest;

pub const control_air = air.control;

pub const control_witness = air.control_witness;

pub const transcript_air = air.transcript_air;

pub const transcript_air_witness = air.transcript_air_witness;

pub const transcript_binding_air = air.transcript_binding;

pub const transcript_binding_witness = air.transcript_binding_witness;

pub const transcript_state_air = air.transcript_state;

pub const transcript_state_witness = air.transcript_state_witness;

pub const transcript_word_air = air.transcript_word;

pub const transcript_word_witness = air.transcript_word_witness;

pub const transcript_payload_air = air.transcript_payload;

pub const transcript_payload_witness = air.transcript_payload_witness;

pub const pow_check_air = air.pow_check;

pub const pow_check_witness = air.pow_check_witness;

pub const pow_frame_air = air.pow_frame;

pub const pow_frame_witness = air.pow_frame_witness;

pub const relation_challenge_air = air.relation_challenge;

pub const relation_challenge_witness = air.relation_challenge_witness;

pub const verifier_randomness_air = air.verifier_randomness;

pub const verifier_randomness_witness = air.verifier_randomness_witness;

pub const FORMAT_VERSION: u16 = 1;

pub const FIRST_ROW: usize = @intFromEnum(roster.Component.control);

pub const ROW_COUNT: usize = 10;

pub const LAST_ROW: usize = FIRST_ROW + ROW_COUNT - 1;

pub const MIN_LOG_SIZE: u32 = 4;

pub const MAX_LOG_SIZE: u32 = 30;

/// One-time construction cost for the ten authenticated typed AIR owners,
/// their canonical executors, and row-0 preprocessing.
pub const COLD_SOURCE_HEAP_ALLOCATIONS: usize = 771;

/// Fresh, zero-owned destinations and a retained interaction workspace are
/// allocation-free across all three trees.
pub const HOT_REUSED_TREE_HEAP_ALLOCATIONS = [manifest_mod.TREE_COUNT]usize{ 0, 0, 0 };

pub const HOT_REUSED_ALL_TREES_HEAP_ALLOCATIONS: usize = 0;

/// Compatibility `fillInteractionInto` constructs one ten-row logical slab
/// and ten framework workspaces, then delegates to the reusable hot API.
pub const COMPAT_INTERACTION_HEAP_ALLOCATIONS: usize = 11;

pub const INTERACTION_WORKSPACE_HEAP_ALLOCATIONS: usize = 11;

pub const HOT_TREE_HEAP_ALLOCATIONS = [manifest_mod.TREE_COUNT]usize{
    0,
    0,
    COMPAT_INTERACTION_HEAP_ALLOCATIONS,
};

pub const HOT_ALL_TREES_HEAP_ALLOCATIONS: usize = COMPAT_INTERACTION_HEAP_ALLOCATIONS;

pub const HOT_PAIR_AUTHENTICATIONS_PER_TREE: usize = 0;

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

pub const ControlAdapter = adapter.Component(control_air, ControlRelation);

pub const TranscriptAirAdapter = adapter.Component(transcript_air, TranscriptAirRelation);

pub const TranscriptBindingAdapter = adapter.Component(
    transcript_binding_air,
    TranscriptBindingRelation,
);

pub const TranscriptStateAdapter = adapter.Component(
    transcript_state_air,
    TranscriptStateRelation,
);

pub const TranscriptWordAdapter = adapter.Component(transcript_word_air, TranscriptWordRelation);

pub const TranscriptPayloadAdapter = adapter.Component(
    transcript_payload_air,
    TranscriptPayloadRelation,
);

pub const PowCheckAdapter = adapter.Component(pow_check_air, PowCheckRelation);

pub const PowFrameAdapter = adapter.Component(pow_frame_air, PowFrameRelation);

pub const RelationChallengeAdapter = adapter.Component(
    relation_challenge_air,
    RelationChallengeRelation,
);

pub const VerifierRandomnessAdapter = adapter.Component(
    verifier_randomness_air,
    VerifierRandomnessRelation,
);

pub const LogSizes = [ROW_COUNT]u32;

pub const DomainAudits = [ROW_COUNT]relation_interaction.DomainAudit;

/// Rows 6 and 7 deliberately have no preprocessing owner and their witness
/// executors accept a caller-selected trace size.  Until a frozen whole-AIR
/// profile owns those two numbers, this explicit verifier input prevents this
/// bridge from silently inventing them from a proof's invocation count.
pub const PowLogSizes = struct {
    check: u32,
    frame: u32,

    pub fn init(check: u32, frame: u32) !PowLogSizes {
        const result = PowLogSizes{ .check = check, .frame = frame };
        try result.validateRange();
        return result;
    }

    pub fn validateFor(self: PowLogSizes, prepared: anytype) !void {
        try self.validateRange();
        if (prepared.pow_check.invocations.len > try traceSize(self.check) or
            prepared.pow_frame.invocations.len > try traceSize(self.frame))
        {
            return error.SourceLogSizeMismatch;
        }
    }

    fn validateRange(self: PowLogSizes) !void {
        if (self.check < MIN_LOG_SIZE or self.check > MAX_LOG_SIZE or
            self.frame < MIN_LOG_SIZE or self.frame > MAX_LOG_SIZE)
        {
            return error.SourceLogSizeMismatch;
        }
    }
};

/// Exact verifier-owned scalar parameters in universal roster order.  Empty
/// arrays are explicit: transcript, PoW-check, and PoW-frame have no hidden
/// parameter columns.
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

    pub fn binaryNode() Parameters {
        const selectors = control_witness.ProofKind.binary_node.selectors();
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
                M31.fromCanonical(relation_challenge_witness.AIR_EVALUATION_CHALLENGE_SCOPE),
                M31.fromCanonical(relation_challenge_witness.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE),
            },
            .verifier_randomness = selectors[0..2].*,
        };
    }
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

    // These are component-local framework claims, not a declaration that the
    // rows 0--9 subset closes every relation by itself.  The full driver must
    // append rows 10--35 (including shared providers) before asserting global
    // universal-relation cancellation.

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
};

pub fn AirOwner(comptime Air: type, comptime Relation: type) type {
    return struct {
        definition: Air.Definition,
        relation: Relation.Plan,

        fn init(allocator: std.mem.Allocator) !@This() {
            var definition = try Air.build(allocator);
            errdefer definition.deinit();
            return .{
                .relation = try Relation.authenticate(&definition),
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
        var transcript_air_value = try AirOwner(
            transcript_air,
            TranscriptAirRelation,
        ).init(allocator);
        errdefer transcript_air_value.deinit();
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
            .transcript_air = transcript_air_value,
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

pub const Executors = struct {
    transcript_air: transcript_air_witness.Executor,
    transcript_binding: transcript_binding_witness.Executor,
    transcript_state: transcript_state_witness.Executor,
    transcript_word: transcript_word_witness.Executor,
    transcript_payload: transcript_payload_witness.Executor,
    pow_check: pow_check_witness.Executor,
    pow_frame: pow_frame_witness.Executor,
    relation_challenge: relation_challenge_witness.Executor,
    verifier_randomness: verifier_randomness_witness.Executor,

    pub fn init(owners: *const Owners) !Executors {
        const transcript_air_binding = try transcript_air_witness.Binding.canonical(
            &owners.transcript_air.definition,
        );
        const transcript_binding_binding = try transcript_binding_witness.Binding.canonical(
            &owners.transcript_binding.definition,
        );
        const transcript_state_binding = try transcript_state_witness.Binding.canonical(
            &owners.transcript_state.definition,
        );
        const transcript_word_binding = try transcript_word_witness.Binding.canonical(
            &owners.transcript_word.definition,
        );
        const transcript_payload_binding = try transcript_payload_witness.Binding.canonical(
            &owners.transcript_payload.definition,
        );
        const pow_check_binding = try pow_check_witness.Binding.canonical(
            &owners.pow_check.definition,
        );
        const pow_frame_binding = try pow_frame_witness.Binding.canonical(
            &owners.pow_frame.definition,
        );
        const relation_challenge_binding = try relation_challenge_witness.Binding.canonical(
            &owners.relation_challenge.definition,
        );
        const verifier_randomness_binding = try verifier_randomness_witness.Binding.canonical(
            &owners.verifier_randomness.definition,
        );
        return .{
            .transcript_air = try transcript_air_witness.Executor.init(
                &owners.transcript_air.definition,
                &transcript_air_binding,
            ),
            .transcript_binding = try transcript_binding_witness.Executor.init(
                &owners.transcript_binding.definition,
                &transcript_binding_binding,
            ),
            .transcript_state = try transcript_state_witness.Executor.init(
                &owners.transcript_state.definition,
                &transcript_state_binding,
            ),
            .transcript_word = try transcript_word_witness.Executor.init(
                &owners.transcript_word.definition,
                &transcript_word_binding,
            ),
            .transcript_payload = try transcript_payload_witness.Executor.init(
                &owners.transcript_payload.definition,
                &transcript_payload_binding,
            ),
            .pow_check = try pow_check_witness.Executor.init(
                &owners.pow_check.definition,
                &pow_check_binding,
            ),
            .pow_frame = try pow_frame_witness.Executor.init(
                &owners.pow_frame.definition,
                &pow_frame_binding,
            ),
            .relation_challenge = try relation_challenge_witness.Executor.init(
                &owners.relation_challenge.definition,
                &relation_challenge_binding,
            ),
            .verifier_randomness = try verifier_randomness_witness.Executor.init(
                &owners.verifier_randomness.definition,
                &verifier_randomness_binding,
            ),
        };
    }

    pub fn validate(self: *const Executors, owners: *const Owners) !void {
        try self.transcript_air.validate();
        try self.transcript_binding.validate();
        try self.transcript_state.validate();
        try self.transcript_word.validate();
        try self.transcript_payload.validate();
        try self.pow_check.validate();
        try self.pow_frame.validate();
        try validateExecutorBinding(
            relation_challenge_witness,
            &owners.relation_challenge.definition,
            &self.relation_challenge,
        );
        try validateExecutorBinding(
            verifier_randomness_witness,
            &owners.verifier_randomness.definition,
            &self.verifier_randomness,
        );
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

    /// Appends precisely rows 0--9. The universal gate remains open for the
    /// caller to append rows 10--35 before sealing.
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
