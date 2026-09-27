//! Exact typed logical AIR for Stark-V universal FRI-Merkle anchor row 27.
//!
//! One row binds query routing, the local-subtree root, the external Merkle
//! path endpoint, multiplicity for every packed leaf, and the exact verifier
//! control step. The authenticated graph is the sole tuple authority.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.fri_merkle_anchor.v1";
pub const DIGEST_WORD_COUNT: usize = 8;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2 + DIGEST_WORD_COUNT;
pub const PREPROCESSED_COLUMN_COUNT: usize = 15;
pub const PARAMETER_COUNT: usize = 3;
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
    "74ac6346920c358c25b4afa9aa3fb77579694deaf9d0013bdfab21328b807ea2";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion FRI-Merkle-anchor semantic digest",
);

pub const MAIN_COLUMN_NAMES = blk: {
    var names: [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion.fri_merkle_anchor.enabler";
    names[1] = "recursion.fri_merkle_anchor.position";
    for (0..DIGEST_WORD_COUNT) |index| names[2 + index] = std.fmt.comptimePrint(
        "recursion.fri_merkle_anchor.digest_{d}",
        .{index},
    );
    break :blk names;
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_fri_merkle_anchor_row_mask",
    "recursion_fri_merkle_anchor_segment_mask",
    "recursion_fri_merkle_anchor_binary_mask",
    "recursion_fri_merkle_anchor_verifier_id",
    "recursion_fri_merkle_anchor_layer",
    "recursion_fri_merkle_anchor_query",
    "recursion_fri_merkle_anchor_tree_id",
    "recursion_fri_merkle_anchor_path_depth",
    "recursion_fri_merkle_anchor_leaf_count",
    "recursion_fri_merkle_anchor_control_sequence",
    "recursion_fri_merkle_anchor_control_tag",
    "recursion_fri_merkle_anchor_control_arg_0",
    "recursion_fri_merkle_anchor_control_arg_1",
    "recursion_fri_merkle_anchor_control_arg_2",
    "recursion_fri_merkle_anchor_control_arg_3",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.fri_merkle_anchor.param.segment_active",
    "recursion.fri_merkle_anchor.param.binary_active",
    "recursion.fri_merkle_anchor.param.fri_merkle_kind",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    position: types.ValueId,
    digest_words: [DIGEST_WORD_COUNT]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.position } ++ self.digest_words;
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    verifier_id: types.ValueId,
    layer: types.ValueId,
    query: types.ValueId,
    tree_id: types.ValueId,
    path_depth: types.ValueId,
    leaf_count: types.ValueId,
    control_sequence: types.ValueId,
    control_tag: types.ValueId,
    control_args: [4]types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.verifier_id,
            self.layer,
            self.query,
            self.tree_id,
            self.path_depth,
            self.leaf_count,
            self.control_sequence,
            self.control_tag,
        } ++ self.control_args;
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    fri_merkle_kind: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{ self.segment_active, self.binary_active, self.fri_merkle_kind };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidFriMerkleAnchorDefinition,
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
            return error.InvalidFriMerkleAnchorDefinition;
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
                return error.InvalidFriMerkleAnchorDefinition;
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidFriMerkleAnchorDefinition;
            if (item.root != root or item.gate != null or item.category != .semantic)
                return error.InvalidFriMerkleAnchorDefinition;
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
        .position = main_values[1],
        .digest_words = main_values[2..][0..DIGEST_WORD_COUNT].*,
    };
    var pp: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&pp, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (index <= 2) .selector else .felt, span);
    }
    const preprocessed = PreprocessedColumns{
        .row_mask = pp[0],
        .segment_mask = pp[1],
        .binary_mask = pp[2],
        .verifier_id = pp[3],
        .layer = pp[4],
        .query = pp[5],
        .tree_id = pp[6],
        .path_depth = pp[7],
        .leaf_count = pp[8],
        .control_sequence = pp[9],
        .control_tag = pp[10],
        .control_args = pp[11..15].*,
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .binary_active = try arena.input(PARAMETER_NAMES[1], .selector, span),
        .fri_merkle_kind = try arena.input(PARAMETER_NAMES[2], .felt, span),
    };
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
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
            "recursion.fri_merkle_anchor.constraint_{d}",
            .{index},
        );
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }

    const weights = [RELATION_EVENT_COUNT]types.ValueId{
        active,
        active,
        active,
        try arena.mul(active, preprocessed.leaf_count, span),
        active,
    };
    const query_tuple = .{
        preprocessed.verifier_id,
        parameters.fri_merkle_kind,
        preprocessed.layer,
        preprocessed.query,
        main.position,
        zero,
    };
    // The terminal Merkle-path row transfers ownership of this exact local
    // coordinate from the committed global root. The anchor consumes it and
    // republishes it for the FRI-local node tree.
    const merkle_tuple = .{
        preprocessed.tree_id,
        preprocessed.path_depth,
        main.position,
    } ++ main.digest_words;
    const route_tuple = .{
        preprocessed.verifier_id,
        preprocessed.layer,
        preprocessed.query,
        main.position,
    };
    const control_tuple = .{
        preprocessed.verifier_id,
        preprocessed.control_sequence,
        preprocessed.control_tag,
    } ++ preprocessed.control_args;
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_query_position, .role = .consume, .values = &query_tuple, .weight = weights[0] },
        .{ .domain = .recursion_merkle_node, .role = .consume, .values = &merkle_tuple, .weight = weights[1] },
        .{ .domain = .recursion_fri_merkle_local_root, .role = .emit, .values = &merkle_tuple, .weight = weights[2] },
        .{ .domain = .recursion_fri_merkle_route, .role = .emit, .values = &route_tuple, .weight = weights[3] },
        .{ .domain = .recursion_step, .role = .consume, .values = &control_tuple, .weight = weights[4] },
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
) error{InvalidFriMerkleAnchorDefinition}!void {
    if (values.len != names.len) return error.InvalidFriMerkleAnchorDefinition;
    for (values, names, 0..) |value, expected_name, index| {
        if (types.idIndex(value) != offset + index)
            return error.InvalidFriMerkleAnchorDefinition;
        const node = arena.node(value) orelse return error.InvalidFriMerkleAnchorDefinition;
        const expected_type: types.Type = switch (group) {
            .main => if (index == 0) .selector else .felt,
            .preprocessed => if (index <= 2) .selector else .felt,
            .parameters => if (index <= 1) .selector else .felt,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidFriMerkleAnchorDefinition;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidFriMerkleAnchorDefinition,
        };
        const actual = arena.name(name_id) orelse return error.InvalidFriMerkleAnchorDefinition;
        if (!std.mem.eql(u8, actual, expected_name))
            return error.InvalidFriMerkleAnchorDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidFriMerkleAnchorDefinition}!void {
    const expected = [_]struct { domain: relation.Domain, role: relation.Role }{
        .{ .domain = .recursion_query_position, .role = .consume },
        .{ .domain = .recursion_merkle_node, .role = .consume },
        .{ .domain = .recursion_fri_merkle_local_root, .role = .emit },
        .{ .domain = .recursion_fri_merkle_route, .role = .emit },
        .{ .domain = .recursion_step, .role = .consume },
    };
    for (self.events, self.weights, expected, 0..) |effect_id, weight, want, index| {
        if (types.idIndex(effect_id) != index)
            return error.InvalidFriMerkleAnchorDefinition;
        const item = self.arena.effect(effect_id) orelse
            return error.InvalidFriMerkleAnchorDefinition;
        const binding = item.binding orelse return error.InvalidFriMerkleAnchorDefinition;
        const schema = relation.get(want.domain);
        const values = self.arena.effectValues(effect_id) orelse
            return error.InvalidFriMerkleAnchorDefinition;
        if (item.kind != .component_call or item.liveness != weight or
            binding.schema != schema.id or binding.schema_version != schema.version or
            binding.role != want.role or values.len != schema.fields.len)
        {
            return error.InvalidFriMerkleAnchorDefinition;
        }
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
