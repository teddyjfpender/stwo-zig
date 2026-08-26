//! Versioned typed AIR for temporal recursion row 8.
//!
//! The native Poseidon channel returns eight M31 words per draw: the two QM31
//! parameters of one universal relation.  The authenticated transcript names
//! those packed parameters with consecutive secure-field indices, while the
//! shared verifier-input ABI names their owning relation and word 0--7.  This
//! V2 component preserves the atomic transcript tuple and derives that exact
//! relation ordinal from the even first-parameter index before emitting words.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");
const proof_kind_mod = @import("proof_kind.zig");

pub const STABLE_NAME = "recursion.temporal_packed_relation_challenge.v2";
pub const PACKING_FORMAT_VERSION: u32 = 2;
pub const CHALLENGES_PER_DRAW: usize = 2;
pub const LIMBS_PER_CHALLENGE: usize = 4;
pub const WORD_COUNT: usize = CHALLENGES_PER_DRAW * LIMBS_PER_CHALLENGE;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1 + WORD_COUNT;
// The V2 pair of public selectors replaces V1's single public selector and
// redundant relation column. args[0] is twice the universal-relation ordinal,
// so the physical preprocessing width stays at twelve columns.
pub const PREPROCESSED_COLUMN_COUNT: usize = 12;
pub const PARAMETER_COUNT: usize = 4;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 1 + WORD_COUNT;
pub const RELATION_EVENT_COUNT: usize = 1 + 2 * WORD_COUNT;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 9;
pub const INTERACTION_COLUMN_COUNT: usize = 36;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "8b15ed97f14b920ed792de6f45c6f0e18129b71d0e77c12c0900d55f24c95e16";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid temporal packed relation-challenge semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.temporal_relation_challenge.enabler",
    "recursion.temporal_relation_challenge.output_0",
    "recursion.temporal_relation_challenge.output_1",
    "recursion.temporal_relation_challenge.output_2",
    "recursion.temporal_relation_challenge.output_3",
    "recursion.temporal_relation_challenge.output_4",
    "recursion.temporal_relation_challenge.output_5",
    "recursion.temporal_relation_challenge.output_6",
    "recursion.temporal_relation_challenge.output_7",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_temporal_relation_challenge_row_mask",
    "recursion_temporal_relation_challenge_segment_mask",
    "recursion_temporal_relation_challenge_binary_mask",
    "recursion_temporal_relation_challenge_public_first_mask",
    "recursion_temporal_relation_challenge_public_second_mask",
    "recursion_temporal_relation_challenge_verifier_id",
    "recursion_temporal_relation_challenge_sequence",
    "recursion_temporal_relation_challenge_tag",
    "recursion_temporal_relation_challenge_arg_0",
    "recursion_temporal_relation_challenge_arg_1",
    "recursion_temporal_relation_challenge_arg_2",
    "recursion_temporal_relation_challenge_arg_3",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.temporal_relation_challenge.param.segment_active",
    "recursion.temporal_relation_challenge.param.binary_active",
    "recursion.temporal_relation_challenge.param.air_scope",
    "recursion.temporal_relation_challenge.param.public_scope",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    outputs: [WORD_COUNT]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.enabler} ++ self.outputs;
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    public_masks: [CHALLENGES_PER_DRAW]types.ValueId,
    verifier_id: types.ValueId,
    sequence: types.ValueId,
    tag: types.ValueId,
    args: [4]types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
        } ++ self.public_masks ++ .{
            self.verifier_id,
            self.sequence,
            self.tag,
        } ++ self.args;
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    air_scope: types.ValueId,
    public_scope: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.binary_active,
            self.air_scope,
            self.public_scope,
        };
    }
};

pub const MainRow = struct {
    enabler: u32 = 1,
    outputs: [WORD_COUNT]M31,

    pub fn values(self: MainRow) [PHYSICAL_MAIN_COLUMN_COUNT]M31 {
        return .{M31.fromU64(self.enabler)} ++ self.outputs;
    }
};

pub const PreprocessedRow = struct {
    row_mask: u32 = 1,
    segment_mask: u32,
    binary_mask: u32,
    public_masks: [CHALLENGES_PER_DRAW]u32,
    verifier_id: u32,
    sequence: u32,
    tag: u32,
    args: [4]u32,

    pub fn values(self: PreprocessedRow) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.fromU64(self.row_mask),
            M31.fromU64(self.segment_mask),
            M31.fromU64(self.binary_mask),
            M31.fromU64(self.public_masks[0]),
            M31.fromU64(self.public_masks[1]),
            M31.fromU64(self.verifier_id),
            M31.fromU64(self.sequence),
            M31.fromU64(self.tag),
            M31.fromU64(self.args[0]),
            M31.fromU64(self.args[1]),
            M31.fromU64(self.args[2]),
            M31.fromU64(self.args[3]),
        };
    }
};

pub const Row = struct {
    preprocessing: PreprocessedRow,
    main: MainRow,
};

pub const ProofKind = proof_kind_mod.ProofKind;
pub const AIR_EVALUATION_CHALLENGE_SCOPE: u32 = 1;
pub const VM_PUBLIC_LOGUP_CHALLENGE_SCOPE: u32 = 0;

pub fn logicalInputs(
    main: MainRow,
    preprocessing: PreprocessedRow,
    kind: ProofKind,
) [LOGICAL_INPUT_COUNT]M31 {
    const selectors = kind.selectors();
    return main.values() ++ preprocessing.values() ++ .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(AIR_EVALUATION_CHALLENGE_SCOPE),
        M31.fromCanonical(VM_PUBLIC_LOGUP_CHALLENGE_SCOPE),
    };
}

pub const RowError = error{InvalidPackedRelationChallengeRow};

/// Cold preflight for trusted preprocessing.  Callers perform this before any
/// destination write; the hot writer is then infallible and failure-atomic.
pub fn validateRow(row: Row) RowError!void {
    if (row.main.enabler != 1 or row.preprocessing.row_mask != 1 or
        row.preprocessing.segment_mask > 1 or
        row.preprocessing.binary_mask > 1 or
        row.preprocessing.segment_mask + row.preprocessing.binary_mask != 1 or
        row.preprocessing.public_masks[0] > 1 or
        row.preprocessing.public_masks[1] > 1 or
        row.preprocessing.tag != 7 or
        row.preprocessing.args[0] % CHALLENGES_PER_DRAW != 0 or
        row.preprocessing.args[1] != CHALLENGES_PER_DRAW or
        row.preprocessing.args[2] != PACKING_FORMAT_VERSION or
        row.preprocessing.args[3] != 0)
    {
        return error.InvalidPackedRelationChallengeRow;
    }
    if (row.preprocessing.binary_mask == 1 and
        (row.preprocessing.public_masks[0] != 0 or
            row.preprocessing.public_masks[1] != 0))
    {
        return error.InvalidPackedRelationChallengeRow;
    }
}

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidPackedRelationChallengeDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
    relation_index: types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    weights: [RELATION_EVENT_COUNT]types.ValueId,
    events: [RELATION_EVENT_COUNT]types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const actual = try digest.computeIdentity(&self.arena);
        if (actual.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &actual.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or
            self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or
            self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidPackedRelationChallengeDefinition;
        }
        try validateInputs(
            &self.arena,
            &self.main.physical(),
            &MAIN_COLUMN_NAMES,
            0,
            &.{0},
        );
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            &.{ 0, 1, 2, 3, 4 },
        );
        try validateInputs(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            &.{ 0, 1 },
        );
        var name_buffer: [112]u8 = undefined;
        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidPackedRelationChallengeDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidPackedRelationChallengeDefinition;
            const expected_name = constraintName(index, &name_buffer) catch
                return error.InvalidPackedRelationChallengeDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidPackedRelationChallengeDefinition;
            }
        }
        try validateEvents(self);
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildDefinition(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn identity(allocator: std.mem.Allocator) !digest.Identity {
    var result = try buildDefinition(allocator);
    defer result.deinit();
    return digest.computeIdentity(&result.arena);
}

fn buildDefinition(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();

    var main_values: [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId = undefined;
    for (&main_values, MAIN_COLUMN_NAMES, 0..) |*value, name, index|
        value.* = try arena.input(name, if (index == 0) .selector else .felt, span);
    const main = MainColumns{
        .enabler = main_values[0],
        .outputs = main_values[1..][0..WORD_COUNT].*,
    };

    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index|
        value.* = try arena.input(name, if (index <= 4) .selector else .felt, span);
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .segment_mask = preprocessed_values[1],
        .binary_mask = preprocessed_values[2],
        .public_masks = preprocessed_values[3..5].*,
        .verifier_id = preprocessed_values[5],
        .sequence = preprocessed_values[6],
        .tag = preprocessed_values[7],
        .args = preprocessed_values[8..12].*,
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .binary_active = try arena.input(PARAMETER_NAMES[1], .selector, span),
        .air_scope = try arena.input(PARAMETER_NAMES[2], .felt, span),
        .public_scope = try arena.input(PARAMETER_NAMES[3], .felt, span),
    };
    const one = try arena.constantField(1, span);
    const active = try arena.mul(
        preprocessed.row_mask,
        try arena.add(
            try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
            try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
            span,
        ),
        span,
    );
    // M31 has prime modulus 2^31 - 1, hence 2^-1 = 2^30. Source custody
    // independently requires args[0] == 2 * relation_ordinal for every row.
    const relation_index = try arena.mul(
        preprocessed.args[0],
        try arena.constantField(1 << 30, span),
        span,
    );
    const inactive = try arena.sub(one, main.enabler, span);
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    roots[0] = try arena.sub(main.enabler, active, span);
    for (main.outputs, 0..) |output, index|
        roots[1 + index] = try arena.mul(inactive, output, span);
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var name_buffer: [112]u8 = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index|
        constraint.* = try arena.assertZero(
            try constraintName(index, &name_buffer),
            root,
            null,
            .semantic,
            span,
        );

    var weights: [RELATION_EVENT_COUNT]types.ValueId = undefined;
    weights[0] = main.enabler;
    var event_specs: [RELATION_EVENT_COUNT]relation_effect.EventSpec = undefined;
    event_specs[0] = .{
        .domain = .recursion_transcript_draw_output,
        .role = .consume,
        .values = &(.{
            preprocessed.verifier_id,
            preprocessed.sequence,
            preprocessed.tag,
        } ++ preprocessed.args ++ main.outputs),
        .weight = weights[0],
    };
    var word_tuples: [2 * WORD_COUNT][5]types.ValueId = undefined;
    for (main.outputs, 0..) |output, output_index| {
        const challenge_slot = output_index / LIMBS_PER_CHALLENGE;
        const word_index = try arena.constantField(@intCast(output_index), span);
        const air_index = 1 + 2 * output_index;
        const public_index = air_index + 1;
        weights[air_index] = main.enabler;
        weights[public_index] = try arena.mul(
            main.enabler,
            preprocessed.public_masks[challenge_slot],
            span,
        );
        word_tuples[2 * output_index] = .{
            preprocessed.verifier_id,
            parameters.air_scope,
            relation_index,
            word_index,
            output,
        };
        word_tuples[2 * output_index + 1] = .{
            preprocessed.verifier_id,
            parameters.public_scope,
            relation_index,
            word_index,
            output,
        };
        event_specs[air_index] = .{
            .domain = .recursion_relation_challenge_word,
            .role = .emit,
            .values = &word_tuples[2 * output_index],
            .weight = weights[air_index],
        };
        event_specs[public_index] = .{
            .domain = .recursion_relation_challenge_word,
            .role = .emit,
            .values = &word_tuples[2 * output_index + 1],
            .weight = weights[public_index],
        };
    }
    const events = try relation_effect.appendGroup(
        RELATION_EVENT_COUNT,
        &arena,
        event_specs,
        span,
    );
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .active = active,
        .relation_index = relation_index,
        .roots = roots,
        .constraints = constraints,
        .weights = weights,
        .events = events,
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) error{InvalidPackedRelationChallengeDefinition}!void {
    if (values.len != names.len)
        return error.InvalidPackedRelationChallengeDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidPackedRelationChallengeDefinition;
        var selector = false;
        for (selector_indices) |index| selector = selector or index == local_index;
        const node = arena.node(value) orelse
            return error.InvalidPackedRelationChallengeDefinition;
        if (!std.meta.eql(node.key.ty, if (selector) types.Type.selector else .felt))
            return error.InvalidPackedRelationChallengeDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidPackedRelationChallengeDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidPackedRelationChallengeDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidPackedRelationChallengeDefinition;
    }
}

fn validateEvents(
    self: *const Definition,
) error{InvalidPackedRelationChallengeDefinition}!void {
    const draw_tuple = .{
        self.preprocessed.verifier_id,
        self.preprocessed.sequence,
        self.preprocessed.tag,
    } ++ self.preprocessed.args ++ self.main.outputs;
    try validateEvent(
        self,
        0,
        .recursion_transcript_draw_output,
        .consume,
        &draw_tuple,
    );
    for (self.main.outputs, 0..) |output, output_index| {
        const word_index = constantValue(&self.arena, output_index) orelse
            return error.InvalidPackedRelationChallengeDefinition;
        const air_tuple = [_]types.ValueId{
            self.preprocessed.verifier_id,
            self.parameters.air_scope,
            self.relation_index,
            word_index,
            output,
        };
        const public_tuple = [_]types.ValueId{
            self.preprocessed.verifier_id,
            self.parameters.public_scope,
            self.relation_index,
            word_index,
            output,
        };
        try validateEvent(
            self,
            1 + 2 * output_index,
            .recursion_relation_challenge_word,
            .emit,
            &air_tuple,
        );
        try validateEvent(
            self,
            2 + 2 * output_index,
            .recursion_relation_challenge_word,
            .emit,
            &public_tuple,
        );
    }
}

fn validateEvent(
    self: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    expected_values: []const types.ValueId,
) error{InvalidPackedRelationChallengeDefinition}!void {
    const effect_id = self.events[index];
    if (types.idIndex(effect_id) != index)
        return error.InvalidPackedRelationChallengeDefinition;
    const item = self.arena.effect(effect_id) orelse
        return error.InvalidPackedRelationChallengeDefinition;
    const binding = item.binding orelse
        return error.InvalidPackedRelationChallengeDefinition;
    const schema = relation.get(domain);
    const values = self.arena.effectValues(effect_id) orelse
        return error.InvalidPackedRelationChallengeDefinition;
    if (item.kind != .component_call or item.liveness != self.weights[index] or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        !std.mem.eql(types.ValueId, values, expected_values))
    {
        return error.InvalidPackedRelationChallengeDefinition;
    }
}

fn constraintName(index: usize, buffer: *[112]u8) ![]const u8 {
    return switch (index) {
        0 => "recursion.temporal_relation_challenge.enabler_matches_mode",
        1...WORD_COUNT => std.fmt.bufPrint(
            buffer,
            "recursion.temporal_relation_challenge.inactive_output_{d}_zero",
            .{index - 1},
        ),
        else => error.InvalidConstraintIndex,
    };
}

fn constantValue(arena: *const ir.Arena, expected: u64) ?types.ValueId {
    for (arena.nodesView(), 0..) |node, index| switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |value| if (value == expected) return @enumFromInt(index),
            .unsigned => {},
        },
        else => {},
    };
    return null;
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    // The versioned packing changes tuple coordinates, not row-8 cost class.
    if (PACKING_FORMAT_VERSION != 2 or CHALLENGES_PER_DRAW != 2 or
        LIMBS_PER_CHALLENGE != 4 or WORD_COUNT != 8 or
        PHYSICAL_MAIN_COLUMN_COUNT != 9 or PREPROCESSED_COLUMN_COUNT != 12 or
        PARAMETER_COUNT != 4 or DIRECT_CONSTRAINT_COUNT != 9 or
        RELATION_EVENT_COUNT != 17 or INTERACTION_BATCH_COUNT != 9 or
        INTERACTION_COLUMN_COUNT != 36 or MAXIMUM_CONSTRAINT_DEGREE != 3)
    {
        @compileError("temporal packed relation-challenge V2 geometry drifted");
    }
}

test "temporal packed relation-challenge V2 semantic identity is pinned" {
    const actual = try identity(std.testing.allocator);
    try std.testing.expectEqual(digest.typed_effect_format_version, actual.format_version);
    try std.testing.expectEqualSlices(u8, &SEMANTIC_DIGEST, &actual.bytes);
    var definition = try build(std.testing.allocator);
    defer definition.deinit();
    try definition.validate();
}
