//! Exact typed logical AIR for Stark-V universal verifier-randomness row 9.
//!
//! One verifier-owned schedule row consumes an atomic eight-word transcript
//! draw. Trusted preprocessing assigns each used word a semantic kind, item,
//! limb, and exact use count. Secure-field draws expose their first four limbs;
//! query blocks expose each raw query as its own item. Unused draw words remain
//! authenticated by the atomic transcript tuple but cannot enter a consumer.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const expr = @import("../../air/lang/expr.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.verifier_randomness.v1";
pub const STARK_V_REVISION: [40]u8 =
    "59172a201bd01f2f4b699bc2f7d4442d8ee81597".*;
pub const STARK_V_SOURCE_PATH = "crates/recursion/src/verifier_randomness_air.rs";
pub const STARK_V_SOURCE_SHA256_HEX =
    "edc6ddb6858636253859ede01812f23ceca576177c0e8eeb855c2dcdab1e28c8";
pub const STARK_V_SOURCE_SHA256: digest.Digest = hexDigest(
    STARK_V_SOURCE_SHA256_HEX,
    "invalid pinned Stark-V verifier-randomness source digest",
);
pub const WORD_COUNT: usize = 8;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1 + WORD_COUNT;
pub const PREPROCESSED_COLUMN_COUNT: usize = 21;
pub const PARAMETER_COUNT: usize = 2;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 1 + WORD_COUNT;
pub const RELATION_EVENT_COUNT: usize = 1 + WORD_COUNT;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 5;
pub const INTERACTION_COLUMN_COUNT: usize = 20;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "8b5e7eb7889d555cf2c64ddeaff28e24f2ce219dd6380af80322af340646333d";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion verifier-randomness semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "4588c3aa58382f812addafdc307939959a93cf3dbb8309acf9180d79f22a775d";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.verifier_randomness.enabler",
    "recursion.verifier_randomness.output_0",
    "recursion.verifier_randomness.output_1",
    "recursion.verifier_randomness.output_2",
    "recursion.verifier_randomness.output_3",
    "recursion.verifier_randomness.output_4",
    "recursion.verifier_randomness.output_5",
    "recursion.verifier_randomness.output_6",
    "recursion.verifier_randomness.output_7",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_verifier_randomness_row_mask",
    "recursion_verifier_randomness_segment_mask",
    "recursion_verifier_randomness_binary_mask",
    "recursion_verifier_randomness_verifier_id",
    "recursion_verifier_randomness_sequence",
    "recursion_verifier_randomness_tag",
    "recursion_verifier_randomness_arg_0",
    "recursion_verifier_randomness_arg_1",
    "recursion_verifier_randomness_arg_2",
    "recursion_verifier_randomness_arg_3",
    "recursion_verifier_randomness_kind",
    "recursion_verifier_randomness_item_base",
    "recursion_verifier_randomness_query_items",
    "recursion_verifier_randomness_word_0_multiplicity",
    "recursion_verifier_randomness_word_1_multiplicity",
    "recursion_verifier_randomness_word_2_multiplicity",
    "recursion_verifier_randomness_word_3_multiplicity",
    "recursion_verifier_randomness_word_4_multiplicity",
    "recursion_verifier_randomness_word_5_multiplicity",
    "recursion_verifier_randomness_word_6_multiplicity",
    "recursion_verifier_randomness_word_7_multiplicity",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.verifier_randomness.param.segment_active",
    "recursion.verifier_randomness.param.binary_active",
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
    verifier_id: types.ValueId,
    sequence: types.ValueId,
    tag: types.ValueId,
    args: [4]types.ValueId,
    kind: types.ValueId,
    item_base: types.ValueId,
    query_items: types.ValueId,
    multiplicities: [WORD_COUNT]types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.verifier_id,
            self.sequence,
            self.tag,
        } ++ self.args ++ .{
            self.kind,
            self.item_base,
            self.query_items,
        } ++ self.multiplicities;
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.binary_active,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidVerifierRandomnessDefinition,
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
            return error.InvalidVerifierRandomnessDefinition;
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
            &.{ 0, 1, 2, 12 },
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
                return error.InvalidVerifierRandomnessDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidVerifierRandomnessDefinition;
            const expected_name = constraintName(index, &name_buffer) catch
                return error.InvalidVerifierRandomnessDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidVerifierRandomnessDefinition;
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
        value.* = try arena.input(
            name,
            if (index <= 2 or index == 12) .selector else .felt,
            span,
        );
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .segment_mask = preprocessed_values[1],
        .binary_mask = preprocessed_values[2],
        .verifier_id = preprocessed_values[3],
        .sequence = preprocessed_values[4],
        .tag = preprocessed_values[5],
        .args = preprocessed_values[6..10].*,
        .kind = preprocessed_values[10],
        .item_base = preprocessed_values[11],
        .query_items = preprocessed_values[12],
        .multiplicities = preprocessed_values[13..21].*,
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .binary_active = try arena.input(PARAMETER_NAMES[1], .selector, span),
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
    var word_tuples: [WORD_COUNT][5]types.ValueId = undefined;
    for (main.outputs, 0..) |output, word| {
        const word_constant = try arena.constantField(@intCast(word), span);
        const event_index = 1 + word;
        weights[event_index] = try arena.mul(
            main.enabler,
            preprocessed.multiplicities[word],
            span,
        );
        word_tuples[word] = .{
            preprocessed.verifier_id,
            preprocessed.kind,
            try arena.add(
                preprocessed.item_base,
                try arena.mul(preprocessed.query_items, word_constant, span),
                span,
            ),
            try arena.mul(
                try arena.sub(one, preprocessed.query_items, span),
                word_constant,
                span,
            ),
            output,
        };
        event_specs[event_index] = .{
            .domain = .recursion_verifier_randomness_word,
            .role = .emit,
            .values = &word_tuples[word],
            .weight = weights[event_index],
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
) error{InvalidVerifierRandomnessDefinition}!void {
    if (values.len != names.len) return error.InvalidVerifierRandomnessDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidVerifierRandomnessDefinition;
        var selector = false;
        for (selector_indices) |index| selector = selector or index == local_index;
        const node = arena.node(value) orelse return error.InvalidVerifierRandomnessDefinition;
        if (!std.meta.eql(node.key.ty, if (selector) types.Type.selector else .felt))
            return error.InvalidVerifierRandomnessDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidVerifierRandomnessDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidVerifierRandomnessDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidVerifierRandomnessDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidVerifierRandomnessDefinition}!void {
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
        const word_constant = constantValue(&self.arena, word) orelse
            return error.InvalidVerifierRandomnessDefinition;
        const one = constantValue(&self.arena, 1) orelse
            return error.InvalidVerifierRandomnessDefinition;
        const expected_tuple = [_]types.ValueId{
            self.preprocessed.verifier_id,
            self.preprocessed.kind,
            findBinary(
                &self.arena,
                .add,
                self.preprocessed.item_base,
                findBinary(
                    &self.arena,
                    .mul,
                    self.preprocessed.query_items,
                    word_constant,
                ) orelse return error.InvalidVerifierRandomnessDefinition,
            ) orelse return error.InvalidVerifierRandomnessDefinition,
            findBinary(
                &self.arena,
                .mul,
                findBinary(
                    &self.arena,
                    .sub,
                    one,
                    self.preprocessed.query_items,
                ) orelse return error.InvalidVerifierRandomnessDefinition,
                word_constant,
            ) orelse return error.InvalidVerifierRandomnessDefinition,
            output,
        };
        try validateEvent(
            self,
            1 + word,
            .recursion_verifier_randomness_word,
            .emit,
            &expected_tuple,
        );
    }
}

fn validateEvent(
    self: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    expected_values: []const types.ValueId,
) error{InvalidVerifierRandomnessDefinition}!void {
    const effect_id = self.events[index];
    if (types.idIndex(effect_id) != index)
        return error.InvalidVerifierRandomnessDefinition;
    const item = self.arena.effect(effect_id) orelse
        return error.InvalidVerifierRandomnessDefinition;
    const binding = item.binding orelse return error.InvalidVerifierRandomnessDefinition;
    const schema = relation.get(domain);
    const values = self.arena.effectValues(effect_id) orelse
        return error.InvalidVerifierRandomnessDefinition;
    if (item.kind != .component_call or item.liveness != self.weights[index] or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        !std.mem.eql(types.ValueId, values, expected_values))
    {
        return error.InvalidVerifierRandomnessDefinition;
    }
}

fn constraintName(index: usize, buffer: *[96]u8) ![]const u8 {
    return switch (index) {
        0 => "recursion.verifier_randomness.enabler_matches_mode",
        1...WORD_COUNT => std.fmt.bufPrint(
            buffer,
            "recursion.verifier_randomness.inactive_output_{d}_zero",
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

fn findBinary(
    arena: *const ir.Arena,
    comptime tag: std.meta.Tag(expr.Op),
    lhs: types.ValueId,
    rhs: types.ValueId,
) ?types.ValueId {
    for (arena.nodesView(), 0..) |node, index| {
        const binary = switch (node.key.op) {
            .add => |value| if (tag == .add) value else continue,
            .sub => |value| if (tag == .sub) value else continue,
            .mul => |value| if (tag == .mul) value else continue,
            else => continue,
        };
        const exact = binary.lhs == lhs and binary.rhs == rhs;
        const commuted = (tag == .add or tag == .mul) and
            binary.lhs == rhs and binary.rhs == lhs;
        if (exact or commuted) return @enumFromInt(index);
    }
    return null;
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
