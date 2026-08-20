//! Exact typed logical AIR for Stark-V universal FRI-Merkle node row 26.
//!
//! The row hashes two authenticated children, owns the parent through either
//! the external Merkle-node relation or the FRI local-root relation, and emits
//! both children.  The expression graph below is the sole constraint and
//! relation-tuple authority.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.fri_merkle_node.v1";
pub const DIGEST_WORD_COUNT: usize = 8;
pub const STATE_WIDTH: usize = 16;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize =
    2 + DIGEST_WORD_COUNT * 4;
pub const PREPROCESSED_COLUMN_COUNT: usize = 6;
pub const PARAMETER_COUNT: usize = 2;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = PHYSICAL_MAIN_COLUMN_COUNT;
pub const RELATION_EVENT_COUNT: usize = 5;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 3;
pub const INTERACTION_COLUMN_COUNT: usize = 12;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "39f685d0fa1b39f0a005093b070ccba32b144afd036e6c72c41ad25471070881";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion FRI-Merkle-node semantic digest",
);

pub const MAIN_COLUMN_NAMES = blk: {
    var names: [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion.fri_merkle_node.enabler";
    names[1] = "recursion.fri_merkle_node.index";
    for (0..DIGEST_WORD_COUNT) |index| names[2 + index] = std.fmt.comptimePrint(
        "recursion.fri_merkle_node.left_{d}",
        .{index},
    );
    for (0..DIGEST_WORD_COUNT) |index| names[2 + DIGEST_WORD_COUNT + index] =
        std.fmt.comptimePrint("recursion.fri_merkle_node.right_{d}", .{index});
    for (0..DIGEST_WORD_COUNT) |index| names[2 + 2 * DIGEST_WORD_COUNT + index] =
        std.fmt.comptimePrint("recursion.fri_merkle_node.parent_{d}", .{index});
    for (0..DIGEST_WORD_COUNT) |index| names[2 + 3 * DIGEST_WORD_COUNT + index] =
        std.fmt.comptimePrint("recursion.fri_merkle_node.output_{d}", .{
            DIGEST_WORD_COUNT + index,
        });
    break :blk names;
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_fri_merkle_node_row_mask",
    "recursion_fri_merkle_node_segment_mask",
    "recursion_fri_merkle_node_binary_mask",
    "recursion_fri_merkle_node_tree_id",
    "recursion_fri_merkle_node_depth",
    "recursion_fri_merkle_node_local_root_mask",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.fri_merkle_node.param.segment_active",
    "recursion.fri_merkle_node.param.binary_active",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    index: types.ValueId,
    left: [DIGEST_WORD_COUNT]types.ValueId,
    right: [DIGEST_WORD_COUNT]types.ValueId,
    parent: [DIGEST_WORD_COUNT]types.ValueId,
    output_tail: [DIGEST_WORD_COUNT]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.index } ++ self.left ++ self.right ++
            self.parent ++ self.output_tail;
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    tree_id: types.ValueId,
    depth: types.ValueId,
    local_root_mask: types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.tree_id,
            self.depth,
            self.local_root_mask,
        };
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{ self.segment_active, self.binary_active };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidFriMerkleNodeDefinition,
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
        const identity_value = try digest.computeIdentity(&self.arena);
        if (identity_value.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &identity_value.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidFriMerkleNodeDefinition;
        }
        try validateInputGroup(&self.arena, &self.main.physical(), &MAIN_COLUMN_NAMES, 0, .main);
        try validateInputGroup(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            .preprocessed,
        );
        try validateInputGroup(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            .parameters,
        );
        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            if (types.idIndex(constraint_id) != index)
                return error.InvalidFriMerkleNodeDefinition;
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidFriMerkleNodeDefinition;
            if (item.root != root or item.gate != null or item.category != .semantic)
                return error.InvalidFriMerkleNodeDefinition;
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
        .index = main_values[1],
        .left = main_values[2..][0..DIGEST_WORD_COUNT].*,
        .right = main_values[2 + DIGEST_WORD_COUNT ..][0..DIGEST_WORD_COUNT].*,
        .parent = main_values[2 + 2 * DIGEST_WORD_COUNT ..][0..DIGEST_WORD_COUNT].*,
        .output_tail = main_values[2 + 3 * DIGEST_WORD_COUNT ..][0..DIGEST_WORD_COUNT].*,
    };
    var pp: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&pp, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (isPreprocessedSelector(index)) .selector else .felt, span);
    }
    const preprocessed = PreprocessedColumns{
        .row_mask = pp[0],
        .segment_mask = pp[1],
        .binary_mask = pp[2],
        .tree_id = pp[3],
        .depth = pp[4],
        .local_root_mask = pp[5],
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .binary_active = try arena.input(PARAMETER_NAMES[1], .selector, span),
    };
    const one = try arena.constantField(1, span);
    const two = try arena.constantField(2, span);
    const active = try arena.add(
        try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
        span,
    );
    const inactive = try arena.sub(one, active, span);
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    roots[0] = try arena.sub(main.enabler, active, span);
    for (main.physical()[1..], 1..) |value, index|
        roots[index] = try arena.mul(inactive, value, span);
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var name_buffer: [96]u8 = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index| {
        const name = try std.fmt.bufPrint(
            &name_buffer,
            "recursion.fri_merkle_node.constraint_{d}",
            .{index},
        );
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }

    const child_depth = try arena.add(preprocessed.depth, one, span);
    const left_index = try arena.mul(main.index, two, span);
    const right_index = try arena.add(left_index, one, span);
    const not_local_root = try arena.sub(one, preprocessed.local_root_mask, span);
    const weights = [RELATION_EVENT_COUNT]types.ValueId{
        active,
        try arena.mul(active, not_local_root, span),
        try arena.mul(active, preprocessed.local_root_mask, span),
        active,
        active,
    };
    const poseidon_tuple = main.left ++ main.right ++ main.parent ++ main.output_tail;
    const parent_tuple = .{ preprocessed.tree_id, preprocessed.depth, main.index } ++ main.parent;
    const left_tuple = .{ preprocessed.tree_id, child_depth, left_index } ++ main.left;
    const right_tuple = .{ preprocessed.tree_id, child_depth, right_index } ++ main.right;
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .poseidon2_io, .role = .request, .values = &poseidon_tuple, .weight = weights[0] },
        .{ .domain = .recursion_merkle_node, .role = .consume, .values = &parent_tuple, .weight = weights[1] },
        .{ .domain = .recursion_fri_merkle_local_root, .role = .consume, .values = &parent_tuple, .weight = weights[2] },
        .{ .domain = .recursion_merkle_node, .role = .emit, .values = &left_tuple, .weight = weights[3] },
        .{ .domain = .recursion_merkle_node, .role = .emit, .values = &right_tuple, .weight = weights[4] },
    }, span);
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

const InputGroup = enum { main, preprocessed, parameters };

fn validateInputGroup(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    group: InputGroup,
) error{InvalidFriMerkleNodeDefinition}!void {
    if (values.len != names.len) return error.InvalidFriMerkleNodeDefinition;
    for (values, names, 0..) |value, expected_name, index| {
        if (types.idIndex(value) != offset + index)
            return error.InvalidFriMerkleNodeDefinition;
        const node = arena.node(value) orelse return error.InvalidFriMerkleNodeDefinition;
        const expected_type: types.Type = switch (group) {
            .main => if (index == 0) .selector else .felt,
            .preprocessed => if (isPreprocessedSelector(index)) .selector else .felt,
            .parameters => .selector,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidFriMerkleNodeDefinition;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidFriMerkleNodeDefinition,
        };
        const actual = arena.name(name_id) orelse return error.InvalidFriMerkleNodeDefinition;
        if (!std.mem.eql(u8, actual, expected_name))
            return error.InvalidFriMerkleNodeDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidFriMerkleNodeDefinition}!void {
    const expected = [_]struct { domain: relation.Domain, role: relation.Role }{
        .{ .domain = .poseidon2_io, .role = .request },
        .{ .domain = .recursion_merkle_node, .role = .consume },
        .{ .domain = .recursion_fri_merkle_local_root, .role = .consume },
        .{ .domain = .recursion_merkle_node, .role = .emit },
        .{ .domain = .recursion_merkle_node, .role = .emit },
    };
    for (self.events, self.weights, expected, 0..) |effect_id, weight, want, index| {
        if (types.idIndex(effect_id) != index)
            return error.InvalidFriMerkleNodeDefinition;
        const item = self.arena.effect(effect_id) orelse
            return error.InvalidFriMerkleNodeDefinition;
        const binding = item.binding orelse return error.InvalidFriMerkleNodeDefinition;
        const schema = relation.get(want.domain);
        const values = self.arena.effectValues(effect_id) orelse
            return error.InvalidFriMerkleNodeDefinition;
        if (item.kind != .component_call or item.liveness != weight or
            binding.schema != schema.id or binding.schema_version != schema.version or
            binding.role != want.role or values.len != schema.fields.len)
        {
            return error.InvalidFriMerkleNodeDefinition;
        }
    }
}

fn isPreprocessedSelector(index: usize) bool {
    return index <= 2 or index == 5;
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
