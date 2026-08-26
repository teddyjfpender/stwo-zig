//! Exact typed logical AIR for Stark-V universal Merkle-path row 33.
//!
//! An enabled row authenticates one complete Poseidon2 permutation, consumes
//! ownership of its parent node, and transfers ownership to exactly the child
//! selected by `direction`. The terminal row must emit its selected leaf too:
//! the leaf table consumes that exact endpoint, so suppressing the terminal
//! transfer would leave the authenticated node multiset open. The physical
//! layout, quadratic roots, relation tuples, multiplicities, and batching are
//! kept in the typed arena as the single semantic authority.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.merkle_path.v1";
pub const DIGEST_WORD_COUNT: usize = 8;
pub const STATE_WIDTH: usize = 16;
pub const DECLARED_COMMITTED_COLUMN_COUNT: usize =
    5 + 5 * DIGEST_WORD_COUNT;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize =
    1 + DECLARED_COMMITTED_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT: usize = 0;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = PHYSICAL_MAIN_COLUMN_COUNT;
pub const AUTHORED_CONSTRAINT_COUNT: usize = 2 + DIGEST_WORD_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 1 + AUTHORED_CONSTRAINT_COUNT;
pub const RELATION_EVENT_COUNT: usize = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;

// Filled from `identity()` after the exact graph below is authored.  Keeping
// the seal here makes any later layout, root, tuple, role, or weight drift a
// construction failure rather than a silent protocol change.
pub const SEMANTIC_DIGEST_HEX =
    "733dfbe5b7ecf111c0ea2823e092bb6a2ea97bf1c770d9ba3c7beedc6d5dc067";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion Merkle-path semantic digest",
);

pub const MAIN_COLUMN_NAMES = blk: {
    var names: [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion.merkle_path.enabler";
    names[1] = "recursion.merkle_path.tree_id";
    names[2] = "recursion.merkle_path.depth";
    names[3] = "recursion.merkle_path.index";
    names[4] = "recursion.merkle_path.direction";
    names[5] = "recursion.merkle_path.is_leaf";
    for (0..DIGEST_WORD_COUNT) |index| {
        names[6 + index] = std.fmt.comptimePrint(
            "recursion.merkle_path.left_{d}",
            .{index},
        );
        names[6 + DIGEST_WORD_COUNT + index] = std.fmt.comptimePrint(
            "recursion.merkle_path.right_{d}",
            .{index},
        );
        names[6 + 2 * DIGEST_WORD_COUNT + index] = std.fmt.comptimePrint(
            "recursion.merkle_path.parent_{d}",
            .{index},
        );
        names[6 + 3 * DIGEST_WORD_COUNT + index] = std.fmt.comptimePrint(
            "recursion.merkle_path.output_{d}",
            .{DIGEST_WORD_COUNT + index},
        );
        names[6 + 4 * DIGEST_WORD_COUNT + index] = std.fmt.comptimePrint(
            "recursion.merkle_path.child_{d}",
            .{index},
        );
    }
    break :blk names;
};

pub const CONSTRAINT_NAMES = blk: {
    var names: [DIRECT_CONSTRAINT_COUNT][]const u8 = undefined;
    names[0] = "recursion.merkle_path.enabler_boolean";
    names[1] = "recursion.merkle_path.direction_boolean";
    names[2] = "recursion.merkle_path.is_leaf_boolean";
    for (0..DIGEST_WORD_COUNT) |index| names[3 + index] =
        std.fmt.comptimePrint("recursion.merkle_path.selected_child_{d}", .{index});
    break :blk names;
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    tree_id: types.ValueId,
    depth: types.ValueId,
    index: types.ValueId,
    direction: types.ValueId,
    is_leaf: types.ValueId,
    left: [DIGEST_WORD_COUNT]types.ValueId,
    right: [DIGEST_WORD_COUNT]types.ValueId,
    parent: [DIGEST_WORD_COUNT]types.ValueId,
    output_tail: [DIGEST_WORD_COUNT]types.ValueId,
    child: [DIGEST_WORD_COUNT]types.ValueId,

    pub fn declared(self: MainColumns) [DECLARED_COMMITTED_COLUMN_COUNT]types.ValueId {
        return .{
            self.tree_id,
            self.depth,
            self.index,
            self.direction,
            self.is_leaf,
        } ++ self.left ++ self.right ++ self.parent ++ self.output_tail ++ self.child;
    }

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.enabler} ++ self.declared();
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidMerklePathDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    one: types.ValueId,
    two: types.ValueId,
    child_depth: types.ValueId,
    doubled_index: types.ValueId,
    child_index: types.ValueId,
    child_weight: types.ValueId,
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
        const actual_identity = try digest.computeIdentity(&self.arena);
        if (actual_identity.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &actual_identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidMerklePathDefinition;
        }
        try validateInputs(&self.arena, self.main);
        try validateDerived(self);
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            if (types.idIndex(constraint_id) != index)
                return error.InvalidMerklePathDefinition;
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidMerklePathDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidMerklePathDefinition;
            if (item.root != root or item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidMerklePathDefinition;
            }
        }
        try validateRootShapes(self);
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

    var values: [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId = undefined;
    for (&values, MAIN_COLUMN_NAMES, 0..) |*value, name, index| {
        const ty: types.Type = switch (index) {
            0, 4, 5 => .selector,
            else => .felt,
        };
        value.* = try arena.input(name, ty, span);
    }
    const main = MainColumns{
        .enabler = values[0],
        .tree_id = values[1],
        .depth = values[2],
        .index = values[3],
        .direction = values[4],
        .is_leaf = values[5],
        .left = values[6..][0..DIGEST_WORD_COUNT].*,
        .right = values[6 + DIGEST_WORD_COUNT ..][0..DIGEST_WORD_COUNT].*,
        .parent = values[6 + 2 * DIGEST_WORD_COUNT ..][0..DIGEST_WORD_COUNT].*,
        .output_tail = values[6 + 3 * DIGEST_WORD_COUNT ..][0..DIGEST_WORD_COUNT].*,
        .child = values[6 + 4 * DIGEST_WORD_COUNT ..][0..DIGEST_WORD_COUNT].*,
    };

    const one = try arena.constantField(1, span);
    const two = try arena.constantField(2, span);
    const child_depth = try arena.add(main.depth, one, span);
    const doubled_index = try arena.mul(main.index, two, span);
    const child_index = try arena.add(doubled_index, main.direction, span);
    // Every path row transfers ownership to its selected child. In particular,
    // the terminal row publishes the leaf consumed by the typed leaf table.
    const child_weight = main.enabler;

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    roots[0] = try booleanRoot(&arena, main.enabler, one, span);
    roots[1] = try booleanRoot(&arena, main.direction, one, span);
    roots[2] = try booleanRoot(&arena, main.is_leaf, one, span);
    for (main.left, main.right, main.child, 0..) |left, right, child, index| {
        roots[3 + index] = try arena.sub(
            try arena.add(
                left,
                try arena.mul(
                    main.direction,
                    try arena.sub(right, left, span),
                    span,
                ),
                span,
            ),
            child,
            span,
        );
    }
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name| {
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }

    const weights = [RELATION_EVENT_COUNT]types.ValueId{
        main.enabler,
        main.enabler,
        child_weight,
    };
    const poseidon_tuple = main.left ++ main.right ++ main.parent ++ main.output_tail;
    const parent_tuple = .{ main.tree_id, main.depth, main.index } ++ main.parent;
    const child_tuple = .{ main.tree_id, child_depth, child_index } ++ main.child;
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .domain = .poseidon2_io,
            .role = .request,
            .values = &poseidon_tuple,
            .weight = weights[0],
        },
        .{
            .domain = .recursion_merkle_node,
            .role = .consume,
            .values = &parent_tuple,
            .weight = weights[1],
        },
        .{
            .domain = .recursion_merkle_node,
            .role = .emit,
            .values = &child_tuple,
            .weight = weights[2],
        },
    }, span);

    return .{
        .arena = arena,
        .main = main,
        .one = one,
        .two = two,
        .child_depth = child_depth,
        .doubled_index = doubled_index,
        .child_index = child_index,
        .child_weight = child_weight,
        .roots = roots,
        .constraints = constraints,
        .weights = weights,
        .events = events,
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    main: MainColumns,
) error{InvalidMerklePathDefinition}!void {
    for (main.physical(), MAIN_COLUMN_NAMES, 0..) |value, expected_name, index| {
        if (types.idIndex(value) != index)
            return error.InvalidMerklePathDefinition;
        const node = arena.node(value) orelse return error.InvalidMerklePathDefinition;
        const expected_type: types.Type = switch (index) {
            0, 4, 5 => .selector,
            else => .felt,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidMerklePathDefinition;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidMerklePathDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidMerklePathDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidMerklePathDefinition;
    }
}

fn validateDerived(self: *const Definition) error{InvalidMerklePathDefinition}!void {
    if (!constantIs(&self.arena, self.one, 1) or
        !constantIs(&self.arena, self.two, 2) or
        !commutativeBinaryIs(&self.arena, self.child_depth, .add, self.main.depth, self.one) or
        !commutativeBinaryIs(&self.arena, self.doubled_index, .mul, self.main.index, self.two) or
        !commutativeBinaryIs(
            &self.arena,
            self.child_index,
            .add,
            self.doubled_index,
            self.main.direction,
        ) or
        self.child_weight != self.main.enabler or
        self.weights[0] != self.main.enabler or
        self.weights[1] != self.main.enabler or
        self.weights[2] != self.child_weight)
    {
        return error.InvalidMerklePathDefinition;
    }
}

fn validateRootShapes(self: *const Definition) error{InvalidMerklePathDefinition}!void {
    const flags = [_]types.ValueId{
        self.main.enabler,
        self.main.direction,
        self.main.is_leaf,
    };
    for (self.roots[0..3], flags) |root, flag| {
        const product = binaryOperands(&self.arena, root, .mul) orelse
            return error.InvalidMerklePathDefinition;
        const complement = if (product.lhs == flag)
            product.rhs
        else if (product.rhs == flag)
            product.lhs
        else
            return error.InvalidMerklePathDefinition;
        if (!binaryIs(&self.arena, complement, .sub, self.one, flag)) {
            return error.InvalidMerklePathDefinition;
        }
    }
    for (
        self.roots[3..],
        self.main.left,
        self.main.right,
        self.main.child,
    ) |root, left, right, child| {
        const outer = binaryOperands(&self.arena, root, .sub) orelse
            return error.InvalidMerklePathDefinition;
        if (outer.rhs != child)
            return error.InvalidMerklePathDefinition;
        const sum = binaryOperands(&self.arena, outer.lhs, .add) orelse
            return error.InvalidMerklePathDefinition;
        if (sum.lhs != left)
            return error.InvalidMerklePathDefinition;
        const selection = binaryOperands(&self.arena, sum.rhs, .mul) orelse
            return error.InvalidMerklePathDefinition;
        if (selection.lhs != self.main.direction or
            !binaryIs(&self.arena, selection.rhs, .sub, right, left))
        {
            return error.InvalidMerklePathDefinition;
        }
    }
}

fn validateEvents(self: *const Definition) error{InvalidMerklePathDefinition}!void {
    const expected = [_]struct {
        domain: relation.Domain,
        role: relation.Role,
        weight: types.ValueId,
    }{
        .{ .domain = .poseidon2_io, .role = .request, .weight = self.main.enabler },
        .{ .domain = .recursion_merkle_node, .role = .consume, .weight = self.main.enabler },
        .{ .domain = .recursion_merkle_node, .role = .emit, .weight = self.child_weight },
    };
    const poseidon_tuple = self.main.left ++ self.main.right ++
        self.main.parent ++ self.main.output_tail;
    const parent_tuple = .{ self.main.tree_id, self.main.depth, self.main.index } ++
        self.main.parent;
    const child_tuple = .{ self.main.tree_id, self.child_depth, self.child_index } ++
        self.main.child;
    const tuples = .{ &poseidon_tuple, &parent_tuple, &child_tuple };
    inline for (self.events, expected, tuples, 0..) |effect_id, want, tuple, index| {
        if (types.idIndex(effect_id) != index)
            return error.InvalidMerklePathDefinition;
        const item = self.arena.effect(effect_id) orelse
            return error.InvalidMerklePathDefinition;
        const binding = item.binding orelse return error.InvalidMerklePathDefinition;
        const schema = relation.get(want.domain);
        const values = self.arena.effectValues(effect_id) orelse
            return error.InvalidMerklePathDefinition;
        if (item.kind != .component_call or item.liveness != want.weight or
            self.weights[index] != want.weight or binding.schema != schema.id or
            binding.schema_version != schema.version or binding.role != want.role or
            !std.mem.eql(types.ValueId, values, tuple))
        {
            return error.InvalidMerklePathDefinition;
        }
    }
}

fn booleanRoot(
    arena: *ir.Arena,
    value: types.ValueId,
    one: types.ValueId,
    span: source.SourceSpan,
) !types.ValueId {
    return arena.mul(value, try arena.sub(one, value, span), span);
}

const BinaryOperands = struct { lhs: types.ValueId, rhs: types.ValueId };
const BinaryTag = enum { add, sub, mul };

fn binaryOperands(
    arena: *const ir.Arena,
    value: types.ValueId,
    expected: BinaryTag,
) ?BinaryOperands {
    const node = arena.node(value) orelse return null;
    return switch (expected) {
        .add => switch (node.key.op) {
            .add => |binary| .{ .lhs = binary.lhs, .rhs = binary.rhs },
            else => null,
        },
        .sub => switch (node.key.op) {
            .sub => |binary| .{ .lhs = binary.lhs, .rhs = binary.rhs },
            else => null,
        },
        .mul => switch (node.key.op) {
            .mul => |binary| .{ .lhs = binary.lhs, .rhs = binary.rhs },
            else => null,
        },
    };
}

fn binaryIs(
    arena: *const ir.Arena,
    value: types.ValueId,
    expected: BinaryTag,
    lhs: types.ValueId,
    rhs: types.ValueId,
) bool {
    const operands = binaryOperands(arena, value, expected) orelse return false;
    return operands.lhs == lhs and operands.rhs == rhs;
}

fn commutativeBinaryIs(
    arena: *const ir.Arena,
    value: types.ValueId,
    expected: BinaryTag,
    lhs: types.ValueId,
    rhs: types.ValueId,
) bool {
    if (expected == .sub) return false;
    const operands = binaryOperands(arena, value, expected) orelse return false;
    return (operands.lhs == lhs and operands.rhs == rhs) or
        (operands.lhs == rhs and operands.rhs == lhs);
}

fn constantIs(arena: *const ir.Arena, value: types.ValueId, expected: u64) bool {
    const node = arena.node(value) orelse return false;
    return switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |actual| actual == expected,
            else => false,
        },
        else => false,
    };
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
