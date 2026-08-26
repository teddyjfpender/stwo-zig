//! Internal segment leaf outer air v2 authority shard; use segment_leaf_outer_air_v2.zig publicly.

pub const std = @import("std");

pub const digest = @import("../air/lang/digest.zig");
pub const ir = @import("../air/lang/ir.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const source = @import("../air/lang/source.zig");
pub const types = @import("../air/lang/types.zig");
pub const validate_mod = @import("../air/lang/validate.zig");
pub const relation_effect = @import("air/relation_effect.zig");
pub const relation_interaction = @import("air/relation_interaction.zig");
pub const transcript_payload = @import("air/transcript_payload.zig");
pub const source_v2 = @import("segment_leaf_authority_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;

pub const Statement = struct {
    pub const STABLE_NAME = "recursion.segment_leaf_v2.statement_source.v1";
    pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1;
    pub const PREPROCESSED_COLUMN_COUNT: usize = 3;
    pub const PARAMETER_COUNT: usize = 0;
    pub const LOGICAL_INPUT_COUNT: usize =
        PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
    pub const DIRECT_CONSTRAINT_COUNT: usize = 4;
    pub const RELATION_EVENT_COUNT: usize = 1;
    pub const LOOKUP_BATCH_SIZE: u8 = 1;
    pub const INTERACTION_BATCH_COUNT: usize = 1;
    pub const INTERACTION_COLUMN_COUNT: usize = 4;
    pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
    pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

    pub const SEMANTIC_DIGEST_HEX =
        "24a80ec6dfa468d52a566c4fb094fa9b63b0c9168c7e91c237a9f411f07b6f69";
    pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
        SEMANTIC_DIGEST_HEX,
        "invalid segment-leaf V2 statement-source semantic digest",
    );

    pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
        "recursion.segment_leaf_v2.statement_source.value",
    };
    pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
        "recursion_segment_leaf_v2_statement_source_active",
        "recursion_segment_leaf_v2_statement_source_scope",
        "recursion_segment_leaf_v2_statement_source_index",
    };
    pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
        "recursion.segment_leaf_v2.statement_source.active_boolean",
        "recursion.segment_leaf_v2.statement_source.inactive_scope_zero",
        "recursion.segment_leaf_v2.statement_source.inactive_index_zero",
        "recursion.segment_leaf_v2.statement_source.inactive_value_zero",
    };

    pub const MainColumns = struct {
        value: types.ValueId,

        pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
            return .{self.value};
        }
    };

    pub const PreprocessedColumns = struct {
        active: types.ValueId,
        scope: types.ValueId,
        index: types.ValueId,

        pub fn physical(
            self: PreprocessedColumns,
        ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
            return .{ self.active, self.scope, self.index };
        }
    };

    pub const Definition = struct {
        arena: ir.Arena,
        main: MainColumns,
        preprocessed: PreprocessedColumns,
        roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
        constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
        event: types.EffectId,

        pub fn deinit(self: *Definition) void {
            self.arena.deinit();
            self.* = undefined;
        }

        pub fn validate(self: *const Definition) !void {
            try validateDefinition(
                self,
                SEMANTIC_DIGEST,
                MAIN_COLUMN_NAMES,
                PREPROCESSED_COLUMN_NAMES,
                CONSTRAINT_NAMES,
                .recursion_statement_word,
                .emit,
                &.{
                    self.preprocessed.scope,
                    self.preprocessed.index,
                    self.main.value,
                },
                self.preprocessed.active,
            );
        }
    };

    pub const Runtime = relation_interaction.Runtime(
        LOGICAL_INPUT_COUNT,
        RELATION_EVENT_COUNT,
        LOOKUP_BATCH_SIZE,
    );
    pub const Plan = Runtime.Plan;
    pub const Row = Runtime.Row;

    pub fn build(allocator: std.mem.Allocator) !Definition {
        var result = try buildRaw(allocator);
        errdefer result.deinit();
        try result.validate();
        return result;
    }

    pub fn computeSemanticDigest(allocator: std.mem.Allocator) !digest.Digest {
        var definition = try buildRaw(allocator);
        defer definition.deinit();
        return (try digest.computeIdentity(&definition.arena)).bytes;
    }

    pub fn authenticate(definition: *const Definition) !Plan {
        try definition.validate();
        return Runtime.authenticate(
            &definition.arena,
            SEMANTIC_DIGEST,
            .{definition.event},
        );
    }

    pub fn logicalRow(
        value: @import("stwo_core").fields.m31.M31,
        active: @import("stwo_core").fields.m31.M31,
        scope: @import("stwo_core").fields.m31.M31,
        index: @import("stwo_core").fields.m31.M31,
    ) Row {
        return .{ value, active, scope, index };
    }

    fn buildRaw(allocator: std.mem.Allocator) !Definition {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const span = source.SourceSpan.generated();
        const main = MainColumns{
            .value = try arena.input(MAIN_COLUMN_NAMES[0], .felt, span),
        };
        const preprocessed = PreprocessedColumns{
            .active = try arena.input(PREPROCESSED_COLUMN_NAMES[0], .selector, span),
            .scope = try arena.input(PREPROCESSED_COLUMN_NAMES[1], .felt, span),
            .index = try arena.input(PREPROCESSED_COLUMN_NAMES[2], .felt, span),
        };
        const one = try arena.constantField(1, span);
        const inactive = try arena.sub(one, preprocessed.active, span);
        const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
            try arena.mul(
                preprocessed.active,
                try arena.sub(preprocessed.active, one, span),
                span,
            ),
            try arena.mul(inactive, preprocessed.scope, span),
            try arena.mul(inactive, preprocessed.index, span),
            try arena.mul(inactive, main.value, span),
        };
        var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
        for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name|
            constraint.* = try arena.assertZero(name, root, null, .semantic, span);
        const tuple = [_]types.ValueId{
            preprocessed.scope,
            preprocessed.index,
            main.value,
        };
        const event = try relation_effect.append(&arena, .{
            .domain = .recursion_statement_word,
            .role = .emit,
            .values = &tuple,
            .weight = preprocessed.active,
        }, span);
        return .{
            .arena = arena,
            .main = main,
            .preprocessed = preprocessed,
            .roots = roots,
            .constraints = constraints,
            .event = event,
        };
    }
};

pub fn validateEffect(
    arena: *const ir.Arena,
    effect_id: types.EffectId,
    expected_index: usize,
    expected_domain: relation.Domain,
    expected_role: relation.Role,
    expected_weight: types.ValueId,
    expected_tuple: []const types.ValueId,
) !void {
    if (types.idIndex(effect_id) != expected_index)
        return error.InvalidDefinition;
    const item = arena.effect(effect_id) orelse return error.InvalidDefinition;
    const binding = item.binding orelse return error.InvalidDefinition;
    const schema = relation.get(expected_domain);
    const values = arena.effectValues(effect_id) orelse
        return error.InvalidDefinition;
    if (item.kind != .component_call or item.liveness != expected_weight or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or
        binding.role != expected_role or
        !std.mem.eql(types.ValueId, values, expected_tuple))
    {
        return error.InvalidDefinition;
    }
}

pub fn validateDefinition(
    definition: anytype,
    expected_digest: digest.Digest,
    comptime main_names: anytype,
    comptime preprocessed_names: anytype,
    comptime constraint_names: anytype,
    expected_domain: relation.Domain,
    expected_role: relation.Role,
    expected_tuple: []const types.ValueId,
    expected_weight: types.ValueId,
) !void {
    try validate_mod.validate(&definition.arena);
    const identity = try digest.computeIdentity(&definition.arena);
    if (identity.format_version != digest.typed_effect_format_version or
        !std.mem.eql(u8, &identity.bytes, &expected_digest) or
        definition.arena.constraintsView().len != constraint_names.len or
        definition.arena.effectsView().len != 1 or
        definition.arena.hints.items.len != 0 or
        definition.arena.functions.items.len != 0 or
        definition.arena.calls.items.len != 0 or
        definition.arena.range_refinements.items.len != 0 or
        definition.arena.fixed_table_requests.items.len != 0)
    {
        return error.InvalidDefinition;
    }
    try validateInputs(
        &definition.arena,
        &definition.main.physical(),
        &main_names,
        0,
        null,
    );
    try validateInputs(
        &definition.arena,
        &definition.preprocessed.physical(),
        &preprocessed_names,
        main_names.len,
        0,
    );
    for (definition.constraints, definition.roots, constraint_names, 0..) |
        constraint_id,
        root,
        expected_name,
        index,
    | {
        const item = definition.arena.constraint(constraint_id) orelse
            return error.InvalidDefinition;
        const actual_name = definition.arena.name(item.name) orelse
            return error.InvalidDefinition;
        if (types.idIndex(constraint_id) != index or item.root != root or
            item.gate != null or item.category != .semantic or
            !std.mem.eql(u8, actual_name, expected_name))
        {
            return error.InvalidDefinition;
        }
    }
    if (types.idIndex(definition.event) != 0)
        return error.InvalidDefinition;
    const item = definition.arena.effect(definition.event) orelse
        return error.InvalidDefinition;
    const binding = item.binding orelse return error.InvalidDefinition;
    const schema = relation.get(expected_domain);
    const actual_values = definition.arena.effectValues(definition.event) orelse
        return error.InvalidDefinition;
    if (item.kind != .component_call or item.liveness != expected_weight or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or
        binding.role != expected_role or
        !std.mem.eql(types.ValueId, actual_values, expected_tuple))
    {
        return error.InvalidDefinition;
    }
}

pub fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_index: ?usize,
) !void {
    if (values.len != names.len) return error.InvalidDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidDefinition;
        const node = arena.node(value) orelse return error.InvalidDefinition;
        const expected_type: types.Type = if (selector_index == local_index)
            .selector
        else
            .felt;
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidDefinition;
    }
}

pub fn constantValue(arena: *const ir.Arena, expected: u32) ?types.ValueId {
    for (arena.nodesView(), 0..) |node, index| switch (node.key.op) {
        .constant => |constant| {
            const value = switch (constant) {
                .field, .unsigned => |word| word,
            };
            if (value == expected)
                return types.idFromIndex(types.ValueId, index) catch null;
        },
        else => {},
    };
    return null;
}

pub fn hexDigest(
    comptime value: []const u8,
    comptime message: []const u8,
) digest.Digest {
    if (value.len != 2 * @sizeOf(digest.Digest)) @compileError(message);
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
