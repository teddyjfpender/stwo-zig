//! Exact typed logical AIR for Stark-V universal relation-challenge row 8.
//!
//! One verifier-owned schedule row consumes an atomic eight-word transcript
//! draw. Every word is emitted into the AIR-evaluation scope; VM challenges
//! 0, 1, and 3 are additionally emitted into the public-LogUp scope. Trusted
//! preprocessing owns that fan-out, so proof bytes cannot duplicate, omit, or
//! exchange a challenge word between verifier lanes or consumer scopes.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.relation_challenge.v1";
pub const WORD_COUNT: usize = 8;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1 + WORD_COUNT;
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
    "1f021a967688a3236d790d51de34d6fb7453433ed0c7696815d3d39456cc5710";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion relation-challenge semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "47d53af8c215dcd108c44147a06e707fe58fd157bc2019a7868864f361593f23";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.relation_challenge.enabler",
    "recursion.relation_challenge.output_0",
    "recursion.relation_challenge.output_1",
    "recursion.relation_challenge.output_2",
    "recursion.relation_challenge.output_3",
    "recursion.relation_challenge.output_4",
    "recursion.relation_challenge.output_5",
    "recursion.relation_challenge.output_6",
    "recursion.relation_challenge.output_7",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_relation_challenge_row_mask",
    "recursion_relation_challenge_segment_mask",
    "recursion_relation_challenge_binary_mask",
    "recursion_relation_challenge_public_logup_mask",
    "recursion_relation_challenge_verifier_id",
    "recursion_relation_challenge_sequence",
    "recursion_relation_challenge_tag",
    "recursion_relation_challenge_arg_0",
    "recursion_relation_challenge_arg_1",
    "recursion_relation_challenge_arg_2",
    "recursion_relation_challenge_arg_3",
    "recursion_relation_challenge_index",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.relation_challenge.param.segment_active",
    "recursion.relation_challenge.param.binary_active",
    "recursion.relation_challenge.param.air_scope",
    "recursion.relation_challenge.param.public_scope",
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
    public_logup_mask: types.ValueId,
    verifier_id: types.ValueId,
    sequence: types.ValueId,
    tag: types.ValueId,
    args: [4]types.ValueId,
    challenge: types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.public_logup_mask,
            self.verifier_id,
            self.sequence,
            self.tag,
        } ++ self.args ++ .{self.challenge};
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

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidRelationChallengeDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
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
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidRelationChallengeDefinition;
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
            &.{ 0, 1, 2, 3 },
        );
        try validateInputs(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            &.{ 0, 1 },
        );
        var name_buffer: [96]u8 = undefined;
        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidRelationChallengeDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidRelationChallengeDefinition;
            const expected_name = constraintName(index, &name_buffer) catch
                return error.InvalidRelationChallengeDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidRelationChallengeDefinition;
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
        value.* = try arena.input(name, if (index <= 3) .selector else .felt, span);
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .segment_mask = preprocessed_values[1],
        .binary_mask = preprocessed_values[2],
        .public_logup_mask = preprocessed_values[3],
        .verifier_id = preprocessed_values[4],
        .sequence = preprocessed_values[5],
        .tag = preprocessed_values[6],
        .args = preprocessed_values[7..11].*,
        .challenge = preprocessed_values[11],
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
    const inactive = try arena.sub(one, main.enabler, span);
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    roots[0] = try arena.sub(main.enabler, active, span);
    for (main.outputs, 0..) |output, index|
        roots[1 + index] = try arena.mul(inactive, output, span);
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var name_buffer: [96]u8 = undefined;
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
    for (main.outputs, 0..) |output, word| {
        const word_index = try arena.constantField(@intCast(word), span);
        const air_index = 1 + 2 * word;
        const public_index = air_index + 1;
        weights[air_index] = main.enabler;
        weights[public_index] = try arena.mul(
            main.enabler,
            preprocessed.public_logup_mask,
            span,
        );
        word_tuples[2 * word] = .{
            preprocessed.verifier_id,
            parameters.air_scope,
            preprocessed.challenge,
            word_index,
            output,
        };
        word_tuples[2 * word + 1] = .{
            preprocessed.verifier_id,
            parameters.public_scope,
            preprocessed.challenge,
            word_index,
            output,
        };
        event_specs[air_index] = .{
            .domain = .recursion_relation_challenge_word,
            .role = .emit,
            .values = &word_tuples[2 * word],
            .weight = weights[air_index],
        };
        event_specs[public_index] = .{
            .domain = .recursion_relation_challenge_word,
            .role = .emit,
            .values = &word_tuples[2 * word + 1],
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
) error{InvalidRelationChallengeDefinition}!void {
    if (values.len != names.len) return error.InvalidRelationChallengeDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidRelationChallengeDefinition;
        var selector = false;
        for (selector_indices) |index| selector = selector or index == local_index;
        const node = arena.node(value) orelse return error.InvalidRelationChallengeDefinition;
        if (!std.meta.eql(node.key.ty, if (selector) types.Type.selector else .felt))
            return error.InvalidRelationChallengeDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidRelationChallengeDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidRelationChallengeDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidRelationChallengeDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidRelationChallengeDefinition}!void {
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
    for (self.main.outputs, 0..) |output, word| {
        const word_index = constantValue(&self.arena, word) orelse
            return error.InvalidRelationChallengeDefinition;
        const air_tuple = [_]types.ValueId{
            self.preprocessed.verifier_id,
            self.parameters.air_scope,
            self.preprocessed.challenge,
            word_index,
            output,
        };
        const public_tuple = [_]types.ValueId{
            self.preprocessed.verifier_id,
            self.parameters.public_scope,
            self.preprocessed.challenge,
            word_index,
            output,
        };
        try validateEvent(
            self,
            1 + 2 * word,
            .recursion_relation_challenge_word,
            .emit,
            &air_tuple,
        );
        try validateEvent(
            self,
            2 + 2 * word,
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
) error{InvalidRelationChallengeDefinition}!void {
    const effect_id = self.events[index];
    if (types.idIndex(effect_id) != index)
        return error.InvalidRelationChallengeDefinition;
    const item = self.arena.effect(effect_id) orelse
        return error.InvalidRelationChallengeDefinition;
    const binding = item.binding orelse return error.InvalidRelationChallengeDefinition;
    const schema = relation.get(domain);
    const values = self.arena.effectValues(effect_id) orelse
        return error.InvalidRelationChallengeDefinition;
    if (item.kind != .component_call or item.liveness != self.weights[index] or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        !std.mem.eql(types.ValueId, values, expected_values))
    {
        return error.InvalidRelationChallengeDefinition;
    }
}

fn constraintName(index: usize, buffer: *[96]u8) ![]const u8 {
    return switch (index) {
        0 => "recursion.relation_challenge.enabler_matches_mode",
        1...WORD_COUNT => std.fmt.bufPrint(
            buffer,
            "recursion.relation_challenge.inactive_output_{d}_zero",
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
