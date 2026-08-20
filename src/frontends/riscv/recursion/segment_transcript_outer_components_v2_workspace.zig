//! Internal segment transcript outer components v2 authority shard; use segment_transcript_outer_components_v2.zig publicly.

const dependency_0 = @import("segment_transcript_outer_components_v2_contract.zig");
const dependency_1 = @import("segment_transcript_outer_components_v2_source.zig");

const ControlFramework = dependency_0.ControlFramework;
const ControlRelation = dependency_0.ControlRelation;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const M31 = dependency_0.M31;
const NativeInputs = dependency_0.NativeInputs;
const PowCheckFramework = dependency_0.PowCheckFramework;
const PowCheckRelation = dependency_0.PowCheckRelation;
const PowFrameFramework = dependency_0.PowFrameFramework;
const PowFrameRelation = dependency_0.PowFrameRelation;
const ROW_COUNT = dependency_0.ROW_COUNT;
const RelationChallengeFramework = dependency_0.RelationChallengeFramework;
const RelationChallengeRelation = dependency_0.RelationChallengeRelation;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const Source = dependency_1.Source;
const TranscriptAirFramework = dependency_0.TranscriptAirFramework;
const TranscriptAirRelation = dependency_0.TranscriptAirRelation;
const TranscriptBindingFramework = dependency_0.TranscriptBindingFramework;
const TranscriptBindingRelation = dependency_0.TranscriptBindingRelation;
const TranscriptPayloadFramework = dependency_0.TranscriptPayloadFramework;
const TranscriptPayloadRelation = dependency_0.TranscriptPayloadRelation;
const TranscriptStateFramework = dependency_0.TranscriptStateFramework;
const TranscriptStateRelation = dependency_0.TranscriptStateRelation;
const TranscriptWordFramework = dependency_0.TranscriptWordFramework;
const TranscriptWordRelation = dependency_0.TranscriptWordRelation;
const VerifierRandomnessFramework = dependency_0.VerifierRandomnessFramework;
const VerifierRandomnessRelation = dependency_0.VerifierRandomnessRelation;
const WORKSPACE_DOMAIN = dependency_0.WORKSPACE_DOMAIN;
const checkedAdd = dependency_1.checkedAdd;
const checkedMul = dependency_1.checkedMul;
const control_air = dependency_0.control_air;
const control_witness = dependency_0.control_witness;
const hashInt = dependency_1.hashInt;
const hashNativeDigest = dependency_1.hashNativeDigest;
const hashRows = dependency_1.hashRows;
const interactionColumnCount = dependency_1.interactionColumnCount;
const logSizesEqual = dependency_1.logSizesEqual;
const manifest_mod = dependency_0.manifest_mod;
const payloadLogicalRow = dependency_1.payloadLogicalRow;
const powCheckLogicalRow = dependency_1.powCheckLogicalRow;
const powFrameLogicalRow = dependency_1.powFrameLogicalRow;
const pow_check_air = dependency_0.pow_check_air;
const pow_frame_air = dependency_0.pow_frame_air;
const relation_challenge_air = dependency_0.relation_challenge_air;
const relation_challenge_witness = dependency_0.relation_challenge_witness;
const rowIndex = dependency_0.rowIndex;
const source_v2 = dependency_0.source_v2;
const std = dependency_0.std;
const traceSize = dependency_1.traceSize;
const transcript_air = dependency_0.transcript_air;
const transcript_air_witness = dependency_0.transcript_air_witness;
const transcript_binding_air = dependency_0.transcript_binding_air;
const transcript_binding_witness = dependency_0.transcript_binding_witness;
const transcript_payload_air = dependency_0.transcript_payload_air;
const transcript_state_air = dependency_0.transcript_state_air;
const transcript_state_witness = dependency_0.transcript_state_witness;
const transcript_word_air = dependency_0.transcript_word_air;
const transcript_word_witness = dependency_0.transcript_word_witness;
const validateDirect = dependency_1.validateDirect;
const validateEventsFor = dependency_1.validateEventsFor;
const verifier_randomness_air = dependency_0.verifier_randomness_air;
const verifier_randomness_witness = dependency_0.verifier_randomness_witness;

/// One reusable worker cache. All allocations occur in `init`; preparation,
/// tree publication, claim generation, and provider publication allocate
/// nothing. A cache is intentionally single-worker and non-reentrant.
pub const Workspace = struct {
    allocator: std.mem.Allocator,
    source_id: source_v2.Digest,
    transcript_manifest_id: source_v2.Digest,
    log_sizes: [ROW_COUNT]u32,

    control_source: []source_v2.ControlRowV2,
    transcript_air_source: []source_v2.TranscriptAirRowV2,
    transcript_binding_source: []source_v2.TranscriptBindingRowV2,
    transcript_state_source: []source_v2.TranscriptStateRowV2,
    transcript_word_source: []source_v2.TranscriptWordRowV2,
    transcript_payload_source: []source_v2.TranscriptPayloadRowV2,
    pow_check_source: []source_v2.PowCheckRowV2,
    pow_frame_source: []source_v2.PowFrameRowV2,
    relation_challenge_source: []source_v2.RelationChallengeRowV2,
    verifier_randomness_source: []source_v2.VerifierRandomnessRowV2,
    relation_events: []source_v2.RelationEventV2,
    provider_calls: []source_v2.ProviderCall,

    control_rows: []ControlRelation.Row,
    transcript_air_rows: []TranscriptAirRelation.Row,
    transcript_binding_rows: []TranscriptBindingRelation.Row,
    transcript_state_rows: []TranscriptStateRelation.Row,
    transcript_word_rows: []TranscriptWordRelation.Row,
    transcript_payload_rows: []TranscriptPayloadRelation.Row,
    pow_check_rows: []PowCheckRelation.Row,
    pow_frame_rows: []PowFrameRelation.Row,
    relation_challenge_rows: []RelationChallengeRelation.Row,
    verifier_randomness_rows: []VerifierRandomnessRelation.Row,

    control_interaction: ControlFramework.Workspace,
    transcript_air_interaction: TranscriptAirFramework.Workspace,
    transcript_binding_interaction: TranscriptBindingFramework.Workspace,
    transcript_state_interaction: TranscriptStateFramework.Workspace,
    transcript_word_interaction: TranscriptWordFramework.Workspace,
    transcript_payload_interaction: TranscriptPayloadFramework.Workspace,
    pow_check_interaction: PowCheckFramework.Workspace,
    pow_frame_interaction: PowFrameFramework.Workspace,
    relation_challenge_interaction: RelationChallengeFramework.Workspace,
    verifier_randomness_interaction: VerifierRandomnessFramework.Workspace,

    interaction_offsets: [ROW_COUNT]usize,
    interaction_stage: []M31,
    seal: [32]u8,
    ready: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        prepared: *const source_v2.PreparedV2,
    ) !Workspace {
        try prepared.manifest.validate();
        const counts = prepared.counts();

        const control_source = try allocator.alloc(source_v2.ControlRowV2, counts.control);
        errdefer allocator.free(control_source);
        const transcript_air_source = try allocator.alloc(
            source_v2.TranscriptAirRowV2,
            counts.transcript_air,
        );
        errdefer allocator.free(transcript_air_source);
        const transcript_binding_source = try allocator.alloc(
            source_v2.TranscriptBindingRowV2,
            counts.transcript_binding,
        );
        errdefer allocator.free(transcript_binding_source);
        const transcript_state_source = try allocator.alloc(
            source_v2.TranscriptStateRowV2,
            counts.transcript_state,
        );
        errdefer allocator.free(transcript_state_source);
        const transcript_word_source = try allocator.alloc(
            source_v2.TranscriptWordRowV2,
            counts.transcript_word,
        );
        errdefer allocator.free(transcript_word_source);
        const transcript_payload_source = try allocator.alloc(
            source_v2.TranscriptPayloadRowV2,
            counts.transcript_payload,
        );
        errdefer allocator.free(transcript_payload_source);
        const pow_check_source = try allocator.alloc(
            source_v2.PowCheckRowV2,
            counts.pow_check,
        );
        errdefer allocator.free(pow_check_source);
        const pow_frame_source = try allocator.alloc(
            source_v2.PowFrameRowV2,
            counts.pow_frame,
        );
        errdefer allocator.free(pow_frame_source);
        const relation_challenge_source = try allocator.alloc(
            source_v2.RelationChallengeRowV2,
            counts.relation_challenge,
        );
        errdefer allocator.free(relation_challenge_source);
        const verifier_randomness_source = try allocator.alloc(
            source_v2.VerifierRandomnessRowV2,
            counts.verifier_randomness,
        );
        errdefer allocator.free(verifier_randomness_source);
        const relation_events = try allocator.alloc(
            source_v2.RelationEventV2,
            counts.relation_events,
        );
        errdefer allocator.free(relation_events);
        const provider_calls = try allocator.alloc(
            source_v2.ProviderCall,
            counts.poseidon_requests,
        );
        errdefer allocator.free(provider_calls);

        const control_rows = try allocator.alloc(ControlRelation.Row, counts.control);
        errdefer allocator.free(control_rows);
        const transcript_air_rows = try allocator.alloc(
            TranscriptAirRelation.Row,
            counts.transcript_air,
        );
        errdefer allocator.free(transcript_air_rows);
        const transcript_binding_rows = try allocator.alloc(
            TranscriptBindingRelation.Row,
            counts.transcript_binding,
        );
        errdefer allocator.free(transcript_binding_rows);
        const transcript_state_rows = try allocator.alloc(
            TranscriptStateRelation.Row,
            counts.transcript_state,
        );
        errdefer allocator.free(transcript_state_rows);
        const transcript_word_rows = try allocator.alloc(
            TranscriptWordRelation.Row,
            counts.transcript_word,
        );
        errdefer allocator.free(transcript_word_rows);
        const transcript_payload_rows = try allocator.alloc(
            TranscriptPayloadRelation.Row,
            counts.transcript_payload,
        );
        errdefer allocator.free(transcript_payload_rows);
        const pow_check_rows = try allocator.alloc(
            PowCheckRelation.Row,
            counts.pow_check,
        );
        errdefer allocator.free(pow_check_rows);
        const pow_frame_rows = try allocator.alloc(
            PowFrameRelation.Row,
            counts.pow_frame,
        );
        errdefer allocator.free(pow_frame_rows);
        const relation_challenge_rows = try allocator.alloc(
            RelationChallengeRelation.Row,
            counts.relation_challenge,
        );
        errdefer allocator.free(relation_challenge_rows);
        const verifier_randomness_rows = try allocator.alloc(
            VerifierRandomnessRelation.Row,
            counts.verifier_randomness,
        );
        errdefer allocator.free(verifier_randomness_rows);

        var logs: [ROW_COUNT]u32 = undefined;
        for (&logs, prepared.manifest.log_sizes) |*target, value| target.* = value;
        var control_interaction = try ControlFramework.Workspace.init(
            allocator,
            logs[rowIndex(.control)],
        );
        errdefer control_interaction.deinit();
        var transcript_air_interaction = try TranscriptAirFramework.Workspace.init(
            allocator,
            logs[rowIndex(.transcript_air)],
        );
        errdefer transcript_air_interaction.deinit();
        var transcript_binding_interaction =
            try TranscriptBindingFramework.Workspace.init(
                allocator,
                logs[rowIndex(.transcript_binding)],
            );
        errdefer transcript_binding_interaction.deinit();
        var transcript_state_interaction = try TranscriptStateFramework.Workspace.init(
            allocator,
            logs[rowIndex(.transcript_state)],
        );
        errdefer transcript_state_interaction.deinit();
        var transcript_word_interaction = try TranscriptWordFramework.Workspace.init(
            allocator,
            logs[rowIndex(.transcript_word)],
        );
        errdefer transcript_word_interaction.deinit();
        var transcript_payload_interaction =
            try TranscriptPayloadFramework.Workspace.init(
                allocator,
                logs[rowIndex(.transcript_payload)],
            );
        errdefer transcript_payload_interaction.deinit();
        var pow_check_interaction = try PowCheckFramework.Workspace.init(
            allocator,
            logs[rowIndex(.pow_check)],
        );
        errdefer pow_check_interaction.deinit();
        var pow_frame_interaction = try PowFrameFramework.Workspace.init(
            allocator,
            logs[rowIndex(.pow_frame)],
        );
        errdefer pow_frame_interaction.deinit();
        var relation_challenge_interaction =
            try RelationChallengeFramework.Workspace.init(
                allocator,
                logs[rowIndex(.relation_challenge)],
            );
        errdefer relation_challenge_interaction.deinit();
        var verifier_randomness_interaction =
            try VerifierRandomnessFramework.Workspace.init(
                allocator,
                logs[rowIndex(.verifier_randomness)],
            );
        errdefer verifier_randomness_interaction.deinit();

        var interaction_offsets: [ROW_COUNT]usize = undefined;
        var interaction_count: usize = 0;
        inline for (0..ROW_COUNT) |index| {
            interaction_offsets[index] = interaction_count;
            interaction_count = try checkedAdd(
                interaction_count,
                try checkedMul(
                    interactionColumnCount(index),
                    try traceSize(logs[index]),
                ),
            );
        }
        const interaction_stage = try allocator.alloc(M31, interaction_count);
        errdefer allocator.free(interaction_stage);

        return .{
            .allocator = allocator,
            .source_id = prepared.source_id,
            .transcript_manifest_id = prepared.manifest.identity,
            .log_sizes = logs,
            .control_source = control_source,
            .transcript_air_source = transcript_air_source,
            .transcript_binding_source = transcript_binding_source,
            .transcript_state_source = transcript_state_source,
            .transcript_word_source = transcript_word_source,
            .transcript_payload_source = transcript_payload_source,
            .pow_check_source = pow_check_source,
            .pow_frame_source = pow_frame_source,
            .relation_challenge_source = relation_challenge_source,
            .verifier_randomness_source = verifier_randomness_source,
            .relation_events = relation_events,
            .provider_calls = provider_calls,
            .control_rows = control_rows,
            .transcript_air_rows = transcript_air_rows,
            .transcript_binding_rows = transcript_binding_rows,
            .transcript_state_rows = transcript_state_rows,
            .transcript_word_rows = transcript_word_rows,
            .transcript_payload_rows = transcript_payload_rows,
            .pow_check_rows = pow_check_rows,
            .pow_frame_rows = pow_frame_rows,
            .relation_challenge_rows = relation_challenge_rows,
            .verifier_randomness_rows = verifier_randomness_rows,
            .control_interaction = control_interaction,
            .transcript_air_interaction = transcript_air_interaction,
            .transcript_binding_interaction = transcript_binding_interaction,
            .transcript_state_interaction = transcript_state_interaction,
            .transcript_word_interaction = transcript_word_interaction,
            .transcript_payload_interaction = transcript_payload_interaction,
            .pow_check_interaction = pow_check_interaction,
            .pow_frame_interaction = pow_frame_interaction,
            .relation_challenge_interaction = relation_challenge_interaction,
            .verifier_randomness_interaction = verifier_randomness_interaction,
            .interaction_offsets = interaction_offsets,
            .interaction_stage = interaction_stage,
            .seal = .{0} ** 32,
            .ready = false,
        };
    }

    pub fn deinit(self: *Workspace) void {
        self.allocator.free(self.interaction_stage);
        self.verifier_randomness_interaction.deinit();
        self.relation_challenge_interaction.deinit();
        self.pow_frame_interaction.deinit();
        self.pow_check_interaction.deinit();
        self.transcript_payload_interaction.deinit();
        self.transcript_word_interaction.deinit();
        self.transcript_state_interaction.deinit();
        self.transcript_binding_interaction.deinit();
        self.transcript_air_interaction.deinit();
        self.control_interaction.deinit();
        self.allocator.free(self.verifier_randomness_rows);
        self.allocator.free(self.relation_challenge_rows);
        self.allocator.free(self.pow_frame_rows);
        self.allocator.free(self.pow_check_rows);
        self.allocator.free(self.transcript_payload_rows);
        self.allocator.free(self.transcript_word_rows);
        self.allocator.free(self.transcript_state_rows);
        self.allocator.free(self.transcript_binding_rows);
        self.allocator.free(self.transcript_air_rows);
        self.allocator.free(self.control_rows);
        self.allocator.free(self.provider_calls);
        self.allocator.free(self.relation_events);
        self.allocator.free(self.verifier_randomness_source);
        self.allocator.free(self.relation_challenge_source);
        self.allocator.free(self.pow_frame_source);
        self.allocator.free(self.pow_check_source);
        self.allocator.free(self.transcript_payload_source);
        self.allocator.free(self.transcript_word_source);
        self.allocator.free(self.transcript_state_source);
        self.allocator.free(self.transcript_binding_source);
        self.allocator.free(self.transcript_air_source);
        self.allocator.free(self.control_source);
        self.* = undefined;
    }

    /// Replays the frozen native source into private storage, derives all ten
    /// logical AIR rows, validates every direct constraint and exact relation
    /// event, then seals the reusable cache. No committed tree is reachable
    /// from this operation.
    pub fn prepare(
        self: *Workspace,
        owner: *const Source,
        prepared: *const source_v2.PreparedV2,
        manifest: *const manifest_mod.Manifest,
        inputs: NativeInputs,
    ) !void {
        self.ready = false;
        self.seal = .{0} ** 32;
        try owner.validateAgainst(prepared, manifest);
        try self.validateGeometry(prepared);
        try source_v2.writeInto(
            prepared,
            self.sourceDestinations(),
            inputs.program,
            inputs.execution,
            inputs.evidence,
            inputs.plan,
            inputs.pcs_config,
            inputs.data,
            inputs.component_descs,
            inputs.infra_descs,
        );
        try self.deriveLogicalRows();
        try validateDirectRows(owner, self);
        try validateEventProjection(owner, self);
        self.seal = workspaceDigest(self, prepared);
        self.ready = true;
    }

    pub fn validateAgainst(
        self: *const Workspace,
        prepared: *const source_v2.PreparedV2,
    ) !void {
        if (!self.ready) return error.CacheNotPrepared;
        try self.validateGeometry(prepared);
        const actual = workspaceDigest(self, prepared);
        if (!std.mem.eql(u8, &actual, &self.seal))
            return error.WorkspaceSealMismatch;
    }

    fn validateGeometry(
        self: *const Workspace,
        prepared: *const source_v2.PreparedV2,
    ) !void {
        try prepared.manifest.validate();
        const counts = prepared.counts();
        if (!std.meta.eql(self.source_id, prepared.source_id) or
            !std.meta.eql(
                self.transcript_manifest_id,
                prepared.manifest.identity,
            ) or
            !logSizesEqual(self.log_sizes, prepared.manifest.log_sizes) or
            self.control_source.len != counts.control or
            self.transcript_air_source.len != counts.transcript_air or
            self.transcript_binding_source.len != counts.transcript_binding or
            self.transcript_state_source.len != counts.transcript_state or
            self.transcript_word_source.len != counts.transcript_word or
            self.transcript_payload_source.len != counts.transcript_payload or
            self.pow_check_source.len != counts.pow_check or
            self.pow_frame_source.len != counts.pow_frame or
            self.relation_challenge_source.len != counts.relation_challenge or
            self.verifier_randomness_source.len != counts.verifier_randomness or
            self.relation_events.len != counts.relation_events or
            self.provider_calls.len != counts.poseidon_requests or
            self.control_rows.len != counts.control or
            self.transcript_air_rows.len != counts.transcript_air or
            self.transcript_binding_rows.len != counts.transcript_binding or
            self.transcript_state_rows.len != counts.transcript_state or
            self.transcript_word_rows.len != counts.transcript_word or
            self.transcript_payload_rows.len != counts.transcript_payload or
            self.pow_check_rows.len != counts.pow_check or
            self.pow_frame_rows.len != counts.pow_frame or
            self.relation_challenge_rows.len != counts.relation_challenge or
            self.verifier_randomness_rows.len != counts.verifier_randomness)
        {
            return error.WorkspaceGeometryMismatch;
        }
        var expected_stage: usize = 0;
        inline for (0..ROW_COUNT) |index| {
            if (self.interaction_offsets[index] != expected_stage)
                return error.WorkspaceGeometryMismatch;
            expected_stage = try checkedAdd(
                expected_stage,
                try checkedMul(
                    interactionColumnCount(index),
                    try traceSize(self.log_sizes[index]),
                ),
            );
        }
        if (self.interaction_stage.len != expected_stage)
            return error.WorkspaceGeometryMismatch;
    }

    fn sourceDestinations(self: *Workspace) source_v2.DestinationsV2 {
        return .{
            .control = self.control_source,
            .transcript_air = self.transcript_air_source,
            .transcript_binding = self.transcript_binding_source,
            .transcript_state = self.transcript_state_source,
            .transcript_word = self.transcript_word_source,
            .transcript_payload = self.transcript_payload_source,
            .pow_check = self.pow_check_source,
            .pow_frame = self.pow_frame_source,
            .relation_challenge = self.relation_challenge_source,
            .verifier_randomness = self.verifier_randomness_source,
            .relation_events = self.relation_events,
            .poseidon_requests = self.provider_calls,
        };
    }

    fn deriveLogicalRows(self: *Workspace) !void {
        for (self.control_rows, self.control_source) |*target, row|
            target.* = control_witness.logicalRow(row, .segment_leaf);
        for (self.transcript_air_rows, self.transcript_air_source) |*target, row|
            target.* = try transcript_air_witness.logicalRow(row);
        for (
            self.transcript_binding_rows,
            self.transcript_binding_source,
        ) |*target, row| target.* = transcript_binding_witness.logicalInputs(
            row.main,
            row.preprocessing,
            .segment_leaf,
        );
        for (
            self.transcript_state_rows,
            self.transcript_state_source,
        ) |*target, row| target.* = transcript_state_witness.logicalInputs(
            row.main,
            row.preprocessing,
            .segment_leaf,
        );
        for (self.transcript_word_rows, self.transcript_word_source) |*target, row|
            target.* = try transcript_word_witness.logicalRow(
                row.preprocessing,
                row.value,
                .segment_leaf,
            );
        for (
            self.transcript_payload_rows,
            self.transcript_payload_source,
        ) |*target, row| target.* = payloadLogicalRow(row);
        for (self.pow_check_rows, self.pow_check_source) |*target, row|
            target.* = powCheckLogicalRow(row);
        for (self.pow_frame_rows, self.pow_frame_source) |*target, row|
            target.* = powFrameLogicalRow(row);
        for (
            self.relation_challenge_rows,
            self.relation_challenge_source,
        ) |*target, row| target.* = relation_challenge_witness.logicalInputs(
            row.main,
            row.preprocessing,
            .segment_leaf,
        );
        for (
            self.verifier_randomness_rows,
            self.verifier_randomness_source,
        ) |*target, row| target.* = verifier_randomness_witness.logicalInputs(
            row.main,
            row.preprocessing,
            .segment_leaf,
        );
    }
};

pub fn validateDirectRows(owner: *const Source, workspace: *const Workspace) !void {
    try validateDirect(
        control_air,
        &owner.owners.control.direct,
        workspace.control_rows,
    );
    try validateDirect(
        transcript_air,
        &owner.owners.transcript_air.direct,
        workspace.transcript_air_rows,
    );
    try validateDirect(
        transcript_binding_air,
        &owner.owners.transcript_binding.direct,
        workspace.transcript_binding_rows,
    );
    try validateDirect(
        transcript_state_air,
        &owner.owners.transcript_state.direct,
        workspace.transcript_state_rows,
    );
    try validateDirect(
        transcript_word_air,
        &owner.owners.transcript_word.direct,
        workspace.transcript_word_rows,
    );
    try validateDirect(
        transcript_payload_air,
        &owner.owners.transcript_payload.direct,
        workspace.transcript_payload_rows,
    );
    try validateDirect(
        pow_check_air,
        &owner.owners.pow_check.direct,
        workspace.pow_check_rows,
    );
    try validateDirect(
        pow_frame_air,
        &owner.owners.pow_frame.direct,
        workspace.pow_frame_rows,
    );
    try validateDirect(
        relation_challenge_air,
        &owner.owners.relation_challenge.direct,
        workspace.relation_challenge_rows,
    );
    try validateDirect(
        verifier_randomness_air,
        &owner.owners.verifier_randomness.direct,
        workspace.verifier_randomness_rows,
    );
}

pub fn validateEventProjection(
    owner: *const Source,
    workspace: *const Workspace,
) !void {
    var cursor: usize = 0;
    try validateEventsFor(
        ControlRelation.Runtime,
        &owner.owners.control.relation,
        workspace.control_rows,
        workspace.relation_events,
        &cursor,
        .control,
    );
    try validateEventsFor(
        TranscriptAirRelation.Runtime,
        &owner.owners.transcript_air.relation,
        workspace.transcript_air_rows,
        workspace.relation_events,
        &cursor,
        .transcript_air,
    );
    try validateEventsFor(
        TranscriptBindingRelation.Runtime,
        &owner.owners.transcript_binding.relation,
        workspace.transcript_binding_rows,
        workspace.relation_events,
        &cursor,
        .transcript_binding,
    );
    try validateEventsFor(
        TranscriptStateRelation.Runtime,
        &owner.owners.transcript_state.relation,
        workspace.transcript_state_rows,
        workspace.relation_events,
        &cursor,
        .transcript_state,
    );
    try validateEventsFor(
        TranscriptWordRelation.Runtime,
        &owner.owners.transcript_word.relation,
        workspace.transcript_word_rows,
        workspace.relation_events,
        &cursor,
        .transcript_word,
    );
    try validateEventsFor(
        TranscriptPayloadRelation.Runtime,
        &owner.owners.transcript_payload.relation,
        workspace.transcript_payload_rows,
        workspace.relation_events,
        &cursor,
        .transcript_payload,
    );
    try validateEventsFor(
        PowCheckRelation.Runtime,
        &owner.owners.pow_check.relation,
        workspace.pow_check_rows,
        workspace.relation_events,
        &cursor,
        .pow_check,
    );
    try validateEventsFor(
        PowFrameRelation.Runtime,
        &owner.owners.pow_frame.relation,
        workspace.pow_frame_rows,
        workspace.relation_events,
        &cursor,
        .pow_frame,
    );
    try validateEventsFor(
        RelationChallengeRelation.Runtime,
        &owner.owners.relation_challenge.relation,
        workspace.relation_challenge_rows,
        workspace.relation_events,
        &cursor,
        .relation_challenge,
    );
    try validateEventsFor(
        VerifierRandomnessRelation.Runtime,
        &owner.owners.verifier_randomness.relation,
        workspace.verifier_randomness_rows,
        workspace.relation_events,
        &cursor,
        .verifier_randomness,
    );
    if (cursor != workspace.relation_events.len)
        return error.EventProjectionMismatch;
}

pub fn workspaceDigest(
    workspace: *const Workspace,
    prepared: *const source_v2.PreparedV2,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(WORKSPACE_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashNativeDigest(&hash, workspace.source_id);
    hashNativeDigest(&hash, workspace.transcript_manifest_id);
    hashNativeDigest(&hash, prepared.source_id);
    hashNativeDigest(&hash, prepared.manifest.identity);
    for (workspace.log_sizes) |log_size| hashInt(&hash, u32, log_size);

    hashRows(&hash, workspace.control_rows);
    hashRows(&hash, workspace.transcript_air_rows);
    hashRows(&hash, workspace.transcript_binding_rows);
    hashRows(&hash, workspace.transcript_state_rows);
    hashRows(&hash, workspace.transcript_word_rows);
    hashRows(&hash, workspace.transcript_payload_rows);
    hashRows(&hash, workspace.pow_check_rows);
    hashRows(&hash, workspace.pow_frame_rows);
    hashRows(&hash, workspace.relation_challenge_rows);
    hashRows(&hash, workspace.verifier_randomness_rows);

    // These two V2 custody coordinates deliberately do not become AIR
    // columns. They still belong to the prepared-cache seal because they bind
    // each dynamic geometry word back to its authenticated source frame.
    for (workspace.transcript_payload_source) |row| {
        hashInt(&hash, u32, row.source_hash_id);
        hashInt(&hash, u32, row.source_word_index);
    }
    for (workspace.relation_events) |event| {
        hashInt(&hash, u8, event.roster_row);
        hashInt(&hash, u32, event.logical_row);
        hashInt(&hash, u8, event.event_ordinal);
        hashInt(&hash, u8, @intFromEnum(event.domain));
        hashInt(&hash, u8, @intFromEnum(event.role));
        hashInt(&hash, u32, event.multiplicity);
        hashInt(&hash, u8, event.arity);
        for (event.tuple) |value| hashInt(&hash, u32, value.toU32());
    }
    for (workspace.provider_calls) |call| {
        for (call.input) |value| hashInt(&hash, u32, value);
        hashInt(&hash, u8, @intFromBool(call.wide));
        hashInt(&hash, u8, @intFromBool(call.io));
        if (call.narrow_output) |value| {
            hashInt(&hash, u8, 1);
            hashInt(&hash, u32, value);
        } else {
            hashInt(&hash, u8, 0);
        }
    }
    return hash.finalResult();
}
