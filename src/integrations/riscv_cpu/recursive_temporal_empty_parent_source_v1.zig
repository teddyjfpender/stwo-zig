//! Specialized suffix authority for an empty/empty height-one parent.
//!
//! The two children are canonical proofless height-zero leaves.  Each owns a
//! statement-specific canonical-empty V3 recording and a transcript authority,
//! but no PCS/FRI proof or Merkle authentication path.  Rows 18--19 reuse the
//! universal composition-input/control source, rows 30--32 reuse the arithmetic
//! lowering source, and the intervening verifier/path rows are authenticated as
//! absent.  This is an append-only source; the existing real/real source and
//! every byte it publishes remain untouched.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const empty_transcript =
    @import("recursive_temporal_empty_parent_transcript_v1.zig");
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const composition = recursion.air.composition_circuit;
const lowering = recursion.air.verifier_arithmetic_lowering;
const schedule = recursion.air.verifier_schedule;
const canonical_empty = recursion.canonical_empty_cohort_v3;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const rows_source = recursion.binary_fri_outer_source;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const POLICY_SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const FIRST_SUFFIX_ROW: usize = 18;
pub const LAST_SUFFIX_ROW: usize = 34;
pub const SUFFIX_ROW_COUNT: usize = LAST_SUFFIX_ROW - FIRST_SUFFIX_ROW + 1;
pub const LEFT_CIRCUIT_ID: u32 = 551;
pub const RIGHT_CIRCUIT_ID: u32 = 552;
pub const CHILD_PROOF_BYTES_ACCEPTED = false;
pub const CHILD_FRI_AUTHORITY_PRESENT = false;
pub const CHILD_MERKLE_PATH_AUTHORITY_PRESENT = false;
pub const OUTPUT_STANDARD_TEMPORAL_NODE = true;
pub const PRESERVES_REAL_REAL_SOURCE_BYTES = true;

const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-empty-parent-source/v1\x00";
const POLICY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-empty-parent-policy/v1\x00";

pub const RowModeV1 = enum(u8) {
    composition,
    inactive_child_verifier,
    arithmetic,
    inactive_merkle_path,
    transcript_provider,
};

/// Exact 17-row suffix selection.  Absence is protocol data, not an implicit
/// zero convention: rows 20--29 and 33 cannot be populated from a fabricated
/// capture, and row 34 receives only the authenticated empty-lane transcript
/// calls plus the ordinary parent prefix calls supplied by the cohort.
pub const SuffixPolicyV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = POLICY_SCHEMA_VERSION,
    child_count: u8 = CHILD_COUNT,
    proofless_child_mask: u8 = 0b11,
    child_fri_mask: u8 = 0,
    child_merkle_path_mask: u8 = 0,
    output_is_standard_temporal_node: bool = true,
    padding: [1]u8 = .{0},
    modes: [SUFFIX_ROW_COUNT]RowModeV1,
    identity: [32]u8,

    pub fn canonical() SuffixPolicyV1 {
        var result = SuffixPolicyV1{
            .modes = .{
                .composition,
                .composition,
                .inactive_child_verifier,
                .inactive_child_verifier,
                .inactive_child_verifier,
                .inactive_child_verifier,
                .inactive_child_verifier,
                .inactive_child_verifier,
                .inactive_child_verifier,
                .inactive_child_verifier,
                .inactive_child_verifier,
                .inactive_child_verifier,
                .arithmetic,
                .arithmetic,
                .arithmetic,
                .inactive_merkle_path,
                .transcript_provider,
            },
            .identity = undefined,
        };
        result.identity = policyIdentity(&result);
        return result;
    }

    pub fn validate(self: SuffixPolicyV1) !void {
        const expected = SuffixPolicyV1.canonical();
        if (!std.meta.eql(self, expected))
            return error.InvalidEmptyParentPolicy;
    }

    pub fn mode(self: SuffixPolicyV1, roster_row: usize) !RowModeV1 {
        try self.validate();
        if (roster_row < FIRST_SUFFIX_ROW or roster_row > LAST_SUFFIX_ROW)
            return error.InvalidEmptyParentPolicy;
        return self.modes[roster_row - FIRST_SUFFIX_ROW];
    }
};

pub const RecordingInputV1 = struct {
    recording: *const composition_v3.RecordedHeterogeneousCircuitV3,
    manifests: composition_v3.TrustedManifestsV3,
    air_program_ids: composition_v3.AirProgramIdsV3,
    binary_layout: *const composition_v3.capture_layout_v3.CaptureLayoutV3,
    empty_layout: *const composition_v3.capture_layout_v3
        .CanonicalEmptyCaptureLayoutV3,
    program: composition_v3.CanonicalEmptyProgramV3,

    pub fn validateAgainst(
        self: RecordingInputV1,
        leaf: *const leaf_mod.LeafOrEmptyV1,
    ) !composition_v3.ConfigurationV3 {
        try leaf.validate();
        if (leaf.kind() != .empty)
            return error.InvalidEmptyParentChild;
        try self.program.validateAgainst(
            self.manifests.universal,
            self.binary_layout,
            self.empty_layout,
        );
        if (!std.meta.eql(self.program.statement_words, leaf.child().statement_words) or
            !std.meta.eql(self.program.statement_id, try leaf.child().statementId()) or
            !std.meta.eql(self.program.publication_id, try leaf.child().id()) or
            !std.mem.eql(
                u8,
                &self.program.parameter_authority_identity,
                &canonical_empty.parameterAuthorityIdentity(),
            ) or !std.meta.eql(
            self.air_program_ids.empty_leaf,
            self.program.air_program_id,
        )) return error.InvalidEmptyParentChild;

        try self.recording.validate(self.manifests, self.air_program_ids);
        const configuration = try self.recording.configurationSnapshot(
            self.manifests,
            self.air_program_ids,
        );
        const descriptor = configuration.program_roster.forKind(.empty_leaf);
        if (descriptor.claim_policy != .canonical_empty_provider or
            !std.mem.eql(
                u8,
                &descriptor.catalog_identity,
                &self.program.identity,
            ) or !std.meta.eql(
            descriptor.air_program_id,
            self.program.air_program_id,
        )) return error.InvalidEmptyParentChild;
        return configuration;
    }
};

pub const InputsV1 = struct {
    pair: *const leaf_mod.PreparedLeafPairV1,
    children: [CHILD_COUNT]*const leaf_mod.LeafOrEmptyV1,
    recordings: [CHILD_COUNT]RecordingInputV1,

    pub fn validate(
        self: InputsV1,
    ) ![CHILD_COUNT]composition_v3.ConfigurationV3 {
        try self.pair.validateAgainst(self.children[0], self.children[1]);
        var configurations: [CHILD_COUNT]composition_v3.ConfigurationV3 =
            undefined;
        inline for (0..CHILD_COUNT) |lane| configurations[lane] =
            try self.recordings[lane].validateAgainst(self.children[lane]);
        if (configurations[0].sampled_value_count !=
            configurations[1].sampled_value_count or
            !std.mem.eql(
                u8,
                &self.recordings[0].manifests.universal.seal,
                &self.recordings[1].manifests.universal.seal,
            ))
        {
            return error.InvalidEmptyParentChild;
        }
        return configurations;
    }
};

pub const SourceV1 = opaque {
    pub fn init(
        allocator: std.mem.Allocator,
        inputs: InputsV1,
    ) !*SourceV1 {
        const configurations = try inputs.validate();
        const programs = [CHILD_COUNT]empty_transcript.ProgramBindingV1{
            try .fromValidatedProgram(inputs.recordings[0].program),
            try .fromValidatedProgram(inputs.recordings[1].program),
        };
        var prepared_transcript = try empty_transcript.PreparedTranscriptV1.init(
            allocator,
            inputs.pair,
            inputs.children,
            programs,
        );
        errdefer prepared_transcript.deinit();

        var input_scratch: [CHILD_COUNT][]QM31 = undefined;
        var shared_samples: [CHILD_COUNT][]QM31 = undefined;
        var node_values: [CHILD_COUNT][]QM31 = undefined;
        var validation_values: [CHILD_COUNT][]QM31 = undefined;
        var initialized: usize = 0;
        errdefer deinitLaneStorage(
            allocator,
            &input_scratch,
            &shared_samples,
            &node_values,
            &validation_values,
            initialized,
        );
        var claim_inputs: [CHILD_COUNT][
            composition_v3
                .COMPOSITION_CLAIM_INPUT_COUNT
        ]QM31 = undefined;
        var evaluations: [CHILD_COUNT]lowering.Evaluation = undefined;
        var lanes: [CHILD_COUNT]composition.RecursionLane = undefined;
        var circuit_authority_sha_ids: [CHILD_COUNT][32]u8 = undefined;

        inline for (0..CHILD_COUNT) |lane| {
            const recording_input = inputs.recordings[lane];
            const graph = recording_input.recording.graph();
            {
                input_scratch[lane] = try allocator.alloc(
                    QM31,
                    try composition.recursionInputCount(
                        configurations[lane].graphInputProfile(),
                    ),
                );
                errdefer allocator.free(input_scratch[lane]);
                shared_samples[lane] = try allocator.alloc(
                    QM31,
                    configurations[lane].sampled_value_count,
                );
                errdefer allocator.free(shared_samples[lane]);
                node_values[lane] = try allocator.alloc(QM31, graph.nodes.len);
                errdefer allocator.free(node_values[lane]);
                validation_values[lane] = try allocator.alloc(
                    QM31,
                    graph.nodes.len,
                );
                errdefer allocator.free(validation_values[lane]);
            }
            initialized += 1;

            const sample_authority =
                try canonical_empty.CanonicalEmptySampleAuthorityV3.seal(
                    recording_input.empty_layout,
                    configurations[lane].sampled_value_count,
                );
            try sample_authority.writeSharedSamples(shared_samples[lane]);
            const relations = prepared_transcript.lanes[lane].relations();
            const claim_authority =
                try canonical_empty.CanonicalEmptyClaimAuthorityV3.seal(
                    recording_input.program,
                    &relations,
                );
            try claim_authority.writeClaimInputs(&claim_inputs[lane]);
            try recording_input.recording.evaluateInto(
                recording_input.manifests,
                recording_input.air_program_ids,
                .{
                    .parent_binary_selector = true,
                    .proof_kind = .empty_leaf,
                    .statement_words = &recording_input.program.statement_words,
                    .sampled_values = shared_samples[lane],
                    .claim_inputs = &claim_inputs[lane],
                    .public_wire_boundary = QM31.zero(),
                    .relations = &relations,
                    .composition_randomness = prepared_transcript.lanes[lane].composition_randomness,
                    .oods_seed = prepared_transcript.lanes[lane].oods_seed,
                },
                input_scratch[lane],
                node_values[lane],
            );
            evaluations[lane] = .{
                .circuit_identity = graph.identity_digest,
                .values = node_values[lane],
            };
            const view = try recording_input.recording.validatedView(
                recording_input.manifests,
                recording_input.air_program_ids,
            );
            lanes[lane] = try view.validatedLane(
                recording_input.manifests,
                recording_input.air_program_ids,
                verifierId(lane),
                circuitId(lane),
                statementScope(lane),
            );
            circuit_authority_sha_ids[lane] =
                (try recording_input.recording.validatedAuthority(
                    recording_input.manifests,
                    recording_input.air_program_ids,
                )).identity();
        }

        const owner = try allocator.create(Storage);
        errdefer allocator.destroy(owner);
        owner.* = .{
            .allocator = allocator,
            .inputs = inputs,
            .configurations = configurations,
            .programs = programs,
            .transcript = prepared_transcript,
            .input_scratch = input_scratch,
            .shared_samples = shared_samples,
            .claim_inputs = claim_inputs,
            .node_values = node_values,
            .validation_values = validation_values,
            .evaluations = evaluations,
            .lanes = lanes,
            .circuit_authority_sha_ids = circuit_authority_sha_ids,
            .policy = .canonical(),
            .authority_sha_id = undefined,
        };
        owner.authority_sha_id = sourceIdentity(owner);
        try owner.validate();
        return handle(owner);
    }

    pub fn deinit(self: *SourceV1) void {
        const owner = storage(self);
        const allocator = owner.allocator;
        owner.transcript.deinit();
        deinitLaneStorage(
            allocator,
            &owner.input_scratch,
            &owner.shared_samples,
            &owner.node_values,
            &owner.validation_values,
            CHILD_COUNT,
        );
        owner.* = undefined;
        allocator.destroy(owner);
    }

    pub fn validate(self: *SourceV1) !void {
        return storage(self).validate();
    }

    pub fn authorityIdentity(self: *const SourceV1) [32]u8 {
        return storageConst(self).authority_sha_id;
    }

    pub fn policy(self: *const SourceV1) SuffixPolicyV1 {
        return storageConst(self).policy;
    }

    pub fn preparedPair(
        self: *const SourceV1,
    ) *const leaf_mod.PreparedLeafPairV1 {
        return storageConst(self).inputs.pair;
    }

    pub fn children(
        self: *const SourceV1,
    ) [CHILD_COUNT]*const leaf_mod.LeafOrEmptyV1 {
        return storageConst(self).inputs.children;
    }

    pub fn transcript(
        self: *const SourceV1,
    ) *const empty_transcript.PreparedTranscriptV1 {
        return &storageConst(self).transcript;
    }

    pub fn transcriptRows(
        self: *const SourceV1,
    ) *const @import("recursive_temporal_nonfri_source_v2.zig").PreparedTranscriptRowsV2 {
        return storageConst(self).transcript.transcriptRows();
    }

    pub fn arithmeticLanes(
        self: *const SourceV1,
    ) [CHILD_COUNT]rows_source.AuthenticatedCompositionLane {
        const owner = storageConst(self);
        return .{
            authenticatedLane(owner, 0),
            authenticatedLane(owner, 1),
        };
    }

    pub fn cloneCompositionRows(
        self: *SourceV1,
        allocator: std.mem.Allocator,
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) !rows_source.CompositionRowsAuthority {
        try self.validate();
        const owner = storageConst(self);
        var result = try rows_source.CompositionRowsAuthority
            .initFromAuthenticatedRecorderLanes(
            allocator,
            vm_plan,
            recursion_plan,
            owner.configurations[0].sampled_value_count,
            owner.lanes,
            owner.evaluations,
        );
        errdefer result.deinit();
        try result.validateAuthenticatedRecorderLanes(owner.evaluations);
        return result;
    }

    pub fn cloneArithmeticRows(
        self: *SourceV1,
        allocator: std.mem.Allocator,
        shared: ?rows_source.SharedArithmeticInput,
    ) !rows_source.ArithmeticRowsAuthority {
        try self.validate();
        const lanes = self.arithmeticLanes();
        var result = try rows_source.ArithmeticRowsAuthority
            .initFromAuthenticatedCompositionLanes(
            allocator,
            lanes,
            shared,
        );
        errdefer result.deinit();
        try result.validateAuthenticatedCompositionLanes(lanes, shared);
        return result;
    }
};

const Storage = struct {
    allocator: std.mem.Allocator,
    inputs: InputsV1,
    configurations: [CHILD_COUNT]composition_v3.ConfigurationV3,
    programs: [CHILD_COUNT]empty_transcript.ProgramBindingV1,
    transcript: empty_transcript.PreparedTranscriptV1,
    input_scratch: [CHILD_COUNT][]QM31,
    shared_samples: [CHILD_COUNT][]QM31,
    claim_inputs: [CHILD_COUNT][
        composition_v3
            .COMPOSITION_CLAIM_INPUT_COUNT
    ]QM31,
    node_values: [CHILD_COUNT][]QM31,
    validation_values: [CHILD_COUNT][]QM31,
    evaluations: [CHILD_COUNT]lowering.Evaluation,
    lanes: [CHILD_COUNT]composition.RecursionLane,
    circuit_authority_sha_ids: [CHILD_COUNT][32]u8,
    policy: SuffixPolicyV1,
    authority_sha_id: [32]u8,

    fn validate(self: *Storage) !void {
        const configurations = try self.inputs.validate();
        if (!std.meta.eql(configurations, self.configurations))
            return error.InvalidEmptyParentSource;
        try self.policy.validate();
        try self.transcript.validateAgainst(
            self.inputs.pair,
            self.inputs.children,
            self.programs,
        );
        inline for (0..CHILD_COUNT) |lane| {
            const input = self.inputs.recordings[lane];
            const graph = input.recording.graph();
            const current_authority = (try input.recording.validatedAuthority(
                input.manifests,
                input.air_program_ids,
            )).identity();
            if (!std.mem.eql(
                u8,
                &current_authority,
                &self.circuit_authority_sha_ids[lane],
            ) or self.input_scratch[lane].len !=
                try composition.recursionInputCount(
                    configurations[lane].graphInputProfile(),
                ) or self.shared_samples[lane].len !=
                configurations[lane].sampled_value_count or
                self.node_values[lane].len != graph.nodes.len or
                self.validation_values[lane].len != graph.nodes.len)
            {
                return error.InvalidEmptyParentSource;
            }
            const relations = self.transcript.lanes[lane].relations();
            const claims = try canonical_empty.CanonicalEmptyClaimAuthorityV3
                .seal(input.program, &relations);
            var expected_claim_inputs: [
                composition_v3
                    .COMPOSITION_CLAIM_INPUT_COUNT
            ]QM31 = undefined;
            try claims.writeClaimInputs(&expected_claim_inputs);
            if (!qm31SliceEql(
                &self.claim_inputs[lane],
                &expected_claim_inputs,
            )) return error.InvalidEmptyParentSource;
            const samples = try canonical_empty.CanonicalEmptySampleAuthorityV3
                .seal(
                input.empty_layout,
                configurations[lane].sampled_value_count,
            );
            try samples.validateSharedSamples(self.shared_samples[lane]);
            try input.recording.evaluateInto(
                input.manifests,
                input.air_program_ids,
                .{
                    .parent_binary_selector = true,
                    .proof_kind = .empty_leaf,
                    .statement_words = &input.program.statement_words,
                    .sampled_values = self.shared_samples[lane],
                    .claim_inputs = &self.claim_inputs[lane],
                    .public_wire_boundary = QM31.zero(),
                    .relations = &relations,
                    .composition_randomness = self.transcript.lanes[lane].composition_randomness,
                    .oods_seed = self.transcript.lanes[lane].oods_seed,
                },
                self.input_scratch[lane],
                self.validation_values[lane],
            );
            if (!qm31SliceEql(
                self.evaluations[lane].values,
                self.validation_values[lane],
            )) return error.InvalidEmptyParentSource;
            try self.lanes[lane].graph.validate();
            if (self.lanes[lane].verifier_id != verifierId(lane) or
                self.lanes[lane].circuit_id != circuitId(lane) or
                self.lanes[lane].statement_scope != statementScope(lane) or
                !std.mem.eql(
                    u8,
                    &self.lanes[lane].graph.identity_digest,
                    &graph.identity_digest,
                )) return error.InvalidEmptyParentSource;
        }
        if (!std.mem.eql(
            u8,
            &self.authority_sha_id,
            &sourceIdentity(self),
        )) return error.InvalidEmptyParentSource;
    }
};

fn authenticatedLane(
    owner: *const Storage,
    comptime lane: usize,
) rows_source.AuthenticatedCompositionLane {
    const graph = owner.inputs.recordings[lane].recording.graph();
    return .{
        .circuit_id = circuitId(lane),
        .circuit_identity = graph.identity_digest,
        .graph = graph,
        .evaluation = owner.evaluations[lane],
    };
}

fn verifierId(lane: usize) u32 {
    return if (lane == 0)
        rows_source.LEFT_RECURSION_VERIFIER_ID
    else
        rows_source.RIGHT_RECURSION_VERIFIER_ID;
}

fn circuitId(lane: usize) u32 {
    return if (lane == 0) LEFT_CIRCUIT_ID else RIGHT_CIRCUIT_ID;
}

fn statementScope(lane: usize) u32 {
    return if (lane == 0)
        rows_source.LEFT_COMPOSITION_STATEMENT_SCOPE
    else
        rows_source.RIGHT_COMPOSITION_STATEMENT_SCOPE;
}

fn handle(value: *Storage) *SourceV1 {
    return @ptrCast(value);
}

fn storage(value: *SourceV1) *Storage {
    return @ptrCast(@alignCast(value));
}

fn storageConst(value: *const SourceV1) *const Storage {
    return @ptrCast(@alignCast(value));
}

fn deinitLaneStorage(
    allocator: std.mem.Allocator,
    input_scratch: *[CHILD_COUNT][]QM31,
    shared_samples: *[CHILD_COUNT][]QM31,
    node_values: *[CHILD_COUNT][]QM31,
    validation_values: *[CHILD_COUNT][]QM31,
    initialized: usize,
) void {
    for (0..initialized) |lane| {
        allocator.free(validation_values.*[lane]);
        allocator.free(node_values.*[lane]);
        allocator.free(shared_samples.*[lane]);
        allocator.free(input_scratch.*[lane]);
    }
}

fn sourceIdentity(value: *const Storage) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.inputs.pair.authority_sha_id);
    hash.update(&value.policy.identity);
    hash.update(&value.transcript.authority_sha_id);
    inline for (0..CHILD_COUNT) |lane| {
        hash.update(&value.inputs.children[lane].authority_sha_id);
        hash.update(&value.inputs.recordings[lane].program.identity);
        hash.update(&value.configurations[lane].identity);
        hash.update(&value.circuit_authority_sha_ids[lane]);
        hash.update(&value.lanes[lane].graph.identity_digest);
        for (value.evaluations[lane].values) |word| hashQm31(&hash, word);
    }
    return hash.finalResult();
}

fn policyIdentity(value: *const SuffixPolicyV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(POLICY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, value.child_count);
    hashInt(&hash, u8, value.proofless_child_mask);
    hashInt(&hash, u8, value.child_fri_mask);
    hashInt(&hash, u8, value.child_merkle_path_mask);
    hashInt(&hash, u8, @intFromBool(value.output_is_standard_temporal_node));
    for (value.modes) |mode| hashInt(&hash, u8, @intFromEnum(mode));
    return hash.finalResult();
}

fn qm31SliceEql(left: []const QM31, right: []const QM31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (SUFFIX_ROW_COUNT != 17 or CHILD_COUNT != 2 or
        LEFT_CIRCUIT_ID == RIGHT_CIRCUIT_ID or CHILD_PROOF_BYTES_ACCEPTED or
        CHILD_FRI_AUTHORITY_PRESENT or CHILD_MERKLE_PATH_AUTHORITY_PRESENT or
        !OUTPUT_STANDARD_TEMPORAL_NODE or !PRESERVES_REAL_REAL_SOURCE_BYTES)
    {
        @compileError("empty-parent suffix source contract drifted");
    }
    switch (@typeInfo(SourceV1)) {
        .@"opaque" => {},
        else => @compileError("empty-parent source must remain opaque"),
    }
}
