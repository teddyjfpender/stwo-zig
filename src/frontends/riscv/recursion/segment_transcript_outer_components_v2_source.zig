//! Internal segment transcript outer components v2 authority shard; use segment_transcript_outer_components_v2.zig publicly.

const dependency_0 = @import("segment_transcript_outer_components_v2_contract.zig");

const Claims = dependency_0.Claims;
const Components = dependency_0.Components;
const ControlAdapter = dependency_0.ControlAdapter;
const ControlFramework = dependency_0.ControlFramework;
const FIRST_ROW = dependency_0.FIRST_ROW;
const M31 = dependency_0.M31;
const Owners = dependency_0.Owners;
const PRODUCTION_ACTIVATION = dependency_0.PRODUCTION_ACTIVATION;
const Parameters = dependency_0.Parameters;
const PowCheckAdapter = dependency_0.PowCheckAdapter;
const PowCheckFramework = dependency_0.PowCheckFramework;
const PowCheckRelation = dependency_0.PowCheckRelation;
const PowFrameAdapter = dependency_0.PowFrameAdapter;
const PowFrameFramework = dependency_0.PowFrameFramework;
const PowFrameRelation = dependency_0.PowFrameRelation;
const ROW_COUNT = dependency_0.ROW_COUNT;
const RelationChallengeAdapter = dependency_0.RelationChallengeAdapter;
const RelationChallengeFramework = dependency_0.RelationChallengeFramework;
const TranscriptAirAdapter = dependency_0.TranscriptAirAdapter;
const TranscriptAirFramework = dependency_0.TranscriptAirFramework;
const TranscriptBindingAdapter = dependency_0.TranscriptBindingAdapter;
const TranscriptBindingFramework = dependency_0.TranscriptBindingFramework;
const TranscriptPayloadAdapter = dependency_0.TranscriptPayloadAdapter;
const TranscriptPayloadFramework = dependency_0.TranscriptPayloadFramework;
const TranscriptPayloadRelation = dependency_0.TranscriptPayloadRelation;
const TranscriptStateAdapter = dependency_0.TranscriptStateAdapter;
const TranscriptStateFramework = dependency_0.TranscriptStateFramework;
const TranscriptWordAdapter = dependency_0.TranscriptWordAdapter;
const TranscriptWordFramework = dependency_0.TranscriptWordFramework;
const VerifierRandomnessAdapter = dependency_0.VerifierRandomnessAdapter;
const VerifierRandomnessFramework = dependency_0.VerifierRandomnessFramework;
const direct_program = dependency_0.direct_program;
const expectedGeometry = dependency_0.expectedGeometry;
const manifest_mod = dependency_0.manifest_mod;
const pow_check_air = dependency_0.pow_check_air;
const relation_interaction = dependency_0.relation_interaction;
const rowIndex = dependency_0.rowIndex;
const source_v2 = dependency_0.source_v2;
const std = dependency_0.std;
const transcript_air = dependency_0.transcript_air;
const universal = dependency_0.universal;

pub const Source = struct {
    allocator: std.mem.Allocator,
    source_id: source_v2.Digest,
    transcript_manifest_id: source_v2.Digest,
    log_sizes: [ROW_COUNT]u32,
    parameters: Parameters,
    owners: Owners,

    pub fn init(
        allocator: std.mem.Allocator,
        prepared: *const source_v2.PreparedV2,
        manifest: *const manifest_mod.Manifest,
    ) !Source {
        try prepared.manifest.validate();
        var owners = try Owners.init(allocator);
        errdefer owners.deinit();
        var result = Source{
            .allocator = allocator,
            .source_id = prepared.source_id,
            .transcript_manifest_id = prepared.manifest.identity,
            .log_sizes = undefined,
            .parameters = Parameters.segmentV2(),
            .owners = owners,
        };
        for (&result.log_sizes, prepared.manifest.log_sizes) |*target, value|
            target.* = value;
        try result.validateAgainst(prepared, manifest);
        return result;
    }

    pub fn deinit(self: *Source) void {
        self.owners.deinit();
        self.* = undefined;
    }

    pub fn productionReady(_: *const Source) bool {
        return PRODUCTION_ACTIVATION;
    }

    pub fn validateAgainst(
        self: *const Source,
        prepared: *const source_v2.PreparedV2,
        manifest: *const manifest_mod.Manifest,
    ) !void {
        try prepared.manifest.validate();
        try manifest.validate();
        if (!std.meta.eql(self.source_id, prepared.source_id) or
            !std.meta.eql(
                self.transcript_manifest_id,
                prepared.manifest.identity,
            ) or
            !std.meta.eql(
                manifest.transcript_manifest_id,
                prepared.manifest.identity,
            ) or
            !std.meta.eql(self.parameters, Parameters.segmentV2()))
        {
            return error.PreparedAuthorityMismatch;
        }
        for (self.log_sizes, prepared.manifest.log_sizes, 0..) |
            actual,
            expected,
            index,
        | {
            if (actual != expected) return error.PreparedAuthorityMismatch;
            const key: manifest_mod.ComponentKey = @enumFromInt(FIRST_ROW + index);
            const placement = manifest.placements[FIRST_ROW + index] orelse
                return error.ManifestGeometryMismatch;
            if (placement.geometry.log_size != actual or
                !std.meta.eql(placement.geometry, expectedGeometry(key, actual)))
            {
                return error.ManifestGeometryMismatch;
            }
        }
        try self.owners.validate();
    }

    pub fn initComponents(
        self: *const Source,
        prepared: *const source_v2.PreparedV2,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        claims: Claims,
    ) !Components {
        try self.validateAgainst(prepared, manifest);
        try relations.validate();
        return .{
            .control = try ControlAdapter.init(
                &self.owners.control.definition,
                self.owners.control.relation,
                manifest,
                .control,
                self.log_sizes[rowIndex(.control)],
                self.parameters.control,
                relations,
                claims.control,
            ),
            .transcript_air = try TranscriptAirAdapter.init(
                &self.owners.transcript_air.definition,
                self.owners.transcript_air.relation,
                manifest,
                .transcript_air,
                self.log_sizes[rowIndex(.transcript_air)],
                self.parameters.transcript_air,
                relations,
                claims.transcript_air,
            ),
            .transcript_binding = try TranscriptBindingAdapter.init(
                &self.owners.transcript_binding.definition,
                self.owners.transcript_binding.relation,
                manifest,
                .transcript_binding,
                self.log_sizes[rowIndex(.transcript_binding)],
                self.parameters.transcript_binding,
                relations,
                claims.transcript_binding,
            ),
            .transcript_state = try TranscriptStateAdapter.init(
                &self.owners.transcript_state.definition,
                self.owners.transcript_state.relation,
                manifest,
                .transcript_state,
                self.log_sizes[rowIndex(.transcript_state)],
                self.parameters.transcript_state,
                relations,
                claims.transcript_state,
            ),
            .transcript_word = try TranscriptWordAdapter.init(
                &self.owners.transcript_word.definition,
                self.owners.transcript_word.relation,
                manifest,
                .transcript_word,
                self.log_sizes[rowIndex(.transcript_word)],
                self.parameters.transcript_word,
                relations,
                claims.transcript_word,
            ),
            .transcript_payload = try TranscriptPayloadAdapter.init(
                &self.owners.transcript_payload.definition,
                self.owners.transcript_payload.relation,
                manifest,
                .transcript_payload,
                self.log_sizes[rowIndex(.transcript_payload)],
                self.parameters.transcript_payload,
                relations,
                claims.transcript_payload,
            ),
            .pow_check = try PowCheckAdapter.init(
                &self.owners.pow_check.definition,
                self.owners.pow_check.relation,
                manifest,
                .pow_check,
                self.log_sizes[rowIndex(.pow_check)],
                self.parameters.pow_check,
                relations,
                claims.pow_check,
            ),
            .pow_frame = try PowFrameAdapter.init(
                &self.owners.pow_frame.definition,
                self.owners.pow_frame.relation,
                manifest,
                .pow_frame,
                self.log_sizes[rowIndex(.pow_frame)],
                self.parameters.pow_frame,
                relations,
                claims.pow_frame,
            ),
            .relation_challenge = try RelationChallengeAdapter.init(
                &self.owners.relation_challenge.definition,
                self.owners.relation_challenge.relation,
                manifest,
                .relation_challenge,
                self.log_sizes[rowIndex(.relation_challenge)],
                self.parameters.relation_challenge,
                relations,
                claims.relation_challenge,
            ),
            .verifier_randomness = try VerifierRandomnessAdapter.init(
                &self.owners.verifier_randomness.definition,
                self.owners.verifier_randomness.relation,
                manifest,
                .verifier_randomness,
                self.log_sizes[rowIndex(.verifier_randomness)],
                self.parameters.verifier_randomness,
                relations,
                claims.verifier_randomness,
            ),
        };
    }
};

pub fn payloadLogicalRow(
    row: source_v2.TranscriptPayloadRowV2,
) TranscriptPayloadRelation.Row {
    const constant_value = if (row.constant_mask == 1)
        row.value
    else
        M31.zero();
    return .{
        M31.one(),
        row.value,
        M31.one(),
        M31.one(),
        M31.zero(),
        felt(row.verifier_id),
        felt(row.instruction_index),
        felt(row.tag),
        felt(row.args[0]),
        felt(row.args[1]),
        felt(row.args[2]),
        felt(row.args[3]),
        felt(row.payload_index),
        felt(@intFromEnum(row.source_kind)),
        felt(row.item_index),
        felt(row.limb_index),
        felt(row.constant_mask),
        felt(row.input_use_count),
        constant_value,
        M31.one(),
        M31.zero(),
    };
}

pub fn powCheckLogicalRow(row: source_v2.PowCheckRowV2) PowCheckRelation.Row {
    var result: PowCheckRelation.Row = undefined;
    result[0] = felt(row.enabler);
    result[1] = felt(row.verifier_id);
    result[2] = felt(@intFromEnum(row.pow_kind));
    result[3] = felt(row.call_id);
    result[4] = felt(row.bits);
    result[5] = row.word;
    for (row.word_bits, 0..) |value, index| result[6 + index] = felt(value);
    for (row.active_bits, 0..) |value, index|
        result[6 + pow_check_air.M31_BIT_COUNT + index] = felt(value);
    return result;
}

pub fn powFrameLogicalRow(row: source_v2.PowFrameRowV2) PowFrameRelation.Row {
    return .{
        felt(row.enabler),
        felt(row.verifier_id),
        felt(row.instruction_index),
        felt(@intFromEnum(row.pow_kind)),
        felt(row.hash_id),
        felt(row.call_id),
        felt(row.bits),
    } ++ row.words;
}

pub fn validateDirect(
    comptime Air: type,
    program: *const direct_program.Program,
    rows: []const [Air.LOGICAL_INPUT_COUNT]M31,
) !void {
    var scratch: [direct_program.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (rows) |row| {
        try program.evaluateBaseInto(&row, &scratch, &roots);
        for (roots) |root| if (!root.isZero())
            return error.ConstraintViolation;
    }
}

pub fn validateEventsFor(
    comptime Runtime: type,
    plan: *const Runtime.Plan,
    rows: []const Runtime.Row,
    events: []const source_v2.RelationEventV2,
    cursor: *usize,
    component: manifest_mod.ComponentKey,
) !void {
    const slot_count = Runtime.LOGICAL_INPUT_COUNT +
        relation_interaction.MAX_COMPILED_NODES;
    var slots: [slot_count]M31 = undefined;
    for (rows, 0..) |row, logical_row| {
        @memcpy(slots[0..Runtime.LOGICAL_INPUT_COUNT], &row);
        for (plan.compiled_nodes[0..plan.compiled_node_count]) |node| {
            slots[node.destination] = evaluateRelationOp(node.op, &slots);
        }
        for (plan.events, 0..) |expected, ordinal| {
            if (cursor.* >= events.len) return error.EventProjectionMismatch;
            const actual = events[cursor.*];
            actual.validate() catch return error.EventProjectionMismatch;
            const magnitude = slots[expected.numerator_slot];
            if (actual.roster_row != manifest_mod.keyIndex(component) or
                actual.logical_row != logical_row or
                actual.event_ordinal != ordinal or
                actual.event_ordinal != expected.ordinal or
                actual.domain != expected.domain or
                actual.role != expected.role or
                actual.arity != expected.arity or
                actual.multiplicity != magnitude.toU32())
            {
                return error.EventProjectionMismatch;
            }
            for (actual.tuple[0..actual.arity], expected.value_slots[0..expected.arity]) |
                got,
                slot,
            | if (!got.eql(slots[slot])) return error.EventProjectionMismatch;
            cursor.* += 1;
        }
    }
}

inline fn evaluateRelationOp(
    op: relation_interaction.EvalOp,
    values: anytype,
) M31 {
    return switch (op) {
        .constant => |value| M31.fromU64(value),
        .add => |binary| values[binary.lhs].add(values[binary.rhs]),
        .sub => |binary| values[binary.lhs].sub(values[binary.rhs]),
        .mul => |binary| values[binary.lhs].mul(values[binary.rhs]),
        .neg => |operand| values[operand].neg(),
        .select => |selection| values[selection.selector]
            .mul(values[selection.when_true])
            .add(M31.one().sub(values[selection.selector])
            .mul(values[selection.when_false])),
    };
}

pub fn interactionColumnCount(index: usize) usize {
    return switch (index) {
        0 => ControlFramework.INTERACTION_COLUMN_COUNT,
        1 => TranscriptAirFramework.INTERACTION_COLUMN_COUNT,
        2 => TranscriptBindingFramework.INTERACTION_COLUMN_COUNT,
        3 => TranscriptStateFramework.INTERACTION_COLUMN_COUNT,
        4 => TranscriptWordFramework.INTERACTION_COLUMN_COUNT,
        5 => TranscriptPayloadFramework.INTERACTION_COLUMN_COUNT,
        6 => PowCheckFramework.INTERACTION_COLUMN_COUNT,
        7 => PowFrameFramework.INTERACTION_COLUMN_COUNT,
        8 => RelationChallengeFramework.INTERACTION_COLUMN_COUNT,
        9 => VerifierRandomnessFramework.INTERACTION_COLUMN_COUNT,
        else => unreachable,
    };
}

pub fn logSizesEqual(actual: [ROW_COUNT]u32, expected: [ROW_COUNT]u8) bool {
    for (actual, expected) |lhs, rhs| if (lhs != rhs) return false;
    return true;
}

pub fn hashRows(hash: anytype, rows: anytype) void {
    hashInt(hash, u64, rows.len);
    for (rows) |row| for (row) |value|
        hashInt(hash, u32, value.toU32());
}

pub fn hashNativeDigest(hash: anytype, value: source_v2.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub fn felt(value: anytype) M31 {
    return M31.fromCanonical(@intCast(value));
}

pub fn checkedAdd(lhs: usize, rhs: usize) !usize {
    return std.math.add(usize, lhs, rhs) catch error.ArithmeticOverflow;
}

pub fn checkedMul(lhs: usize, rhs: usize) !usize {
    return std.math.mul(usize, lhs, rhs) catch error.ArithmeticOverflow;
}

pub fn traceSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize) or log_size >= 31)
        return error.DestinationLogSizeMismatch;
    return @as(usize, 1) << @intCast(log_size);
}
