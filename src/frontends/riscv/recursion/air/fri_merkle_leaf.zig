//! Typed logical AIR for Stark-V universal FRI-Merkle leaf row 25.
//!
//! The row authenticates packed secure values, every chained Poseidon2 state,
//! the routed subset position, and the endpoint in either the external Merkle
//! path or the one-leaf local subtree. One compiler-owned leaf-index column
//! materializes the sole nonlinear relation field, preserving cubic LogUp
//! geometry without widening the interaction trace.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.fri_merkle_leaf.v2";
pub const STATE_WIDTH: usize = 16;
pub const RATE: usize = 8;
pub const DIGEST_WORD_COUNT: usize = 8;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 3 + STATE_WIDTH + RATE + STATE_WIDTH;
pub const PREPROCESSED_COLUMN_COUNT: usize = 14 + RATE * 4 + 2;
pub const PARAMETER_COUNT: usize = 3;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize =
    2 + STATE_WIDTH + RATE + STATE_WIDTH + 1 + STATE_WIDTH + RATE;
pub const RELATION_EVENT_COUNT: usize = 14;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 7;
pub const INTERACTION_COLUMN_COUNT: usize = 28;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 4;
/// Exact degree after leaf-index materialization. Relation tuple fields are
/// linear, while event weights are at most quadratic.
pub const LOWERED_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "c8a71800dd9577d5bc7165bfc12fb3babae6f610ec16193df1e08fbeaeae3224";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion FRI-Merkle-leaf semantic digest",
);

pub const MAIN_COLUMN_NAMES = blk: {
    var names: [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion.fri_merkle_leaf.enabler";
    names[1] = "recursion.fri_merkle_leaf.position";
    names[2] = "recursion.fri_merkle_leaf.leaf_index";
    for (0..STATE_WIDTH) |index| names[3 + index] = std.fmt.comptimePrint(
        "recursion.fri_merkle_leaf.previous_{d}",
        .{index},
    );
    for (0..RATE) |index| names[3 + STATE_WIDTH + index] = std.fmt.comptimePrint(
        "recursion.fri_merkle_leaf.chunk_{d}",
        .{index},
    );
    for (0..STATE_WIDTH) |index| names[3 + STATE_WIDTH + RATE + index] =
        std.fmt.comptimePrint("recursion.fri_merkle_leaf.output_{d}", .{index});
    break :blk names;
};

pub const PREPROCESSED_COLUMN_NAMES = blk: {
    var names: [PREPROCESSED_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion_fri_merkle_leaf_row_mask";
    names[1] = "recursion_fri_merkle_leaf_segment_mask";
    names[2] = "recursion_fri_merkle_leaf_binary_mask";
    names[3] = "recursion_fri_merkle_leaf_verifier_id";
    names[4] = "recursion_fri_merkle_leaf_layer";
    names[5] = "recursion_fri_merkle_leaf_query";
    names[6] = "recursion_fri_merkle_leaf_packed_index";
    names[7] = "recursion_fri_merkle_leaf_count";
    names[8] = "recursion_fri_merkle_leaf_local_root_mask";
    names[9] = "recursion_fri_merkle_leaf_tree_id";
    names[10] = "recursion_fri_merkle_leaf_tree_height";
    names[11] = "recursion_fri_merkle_leaf_step";
    names[12] = "recursion_fri_merkle_leaf_first_mask";
    names[13] = "recursion_fri_merkle_leaf_last_mask";
    for (0..RATE) |index| {
        names[14 + 4 * index] = std.fmt.comptimePrint(
            "recursion_fri_merkle_leaf_chunk_{d}_source_mask",
            .{index},
        );
        names[15 + 4 * index] = std.fmt.comptimePrint(
            "recursion_fri_merkle_leaf_chunk_{d}_offset",
            .{index},
        );
        names[16 + 4 * index] = std.fmt.comptimePrint(
            "recursion_fri_merkle_leaf_chunk_{d}_word",
            .{index},
        );
        names[17 + 4 * index] = std.fmt.comptimePrint(
            "recursion_fri_merkle_leaf_chunk_{d}_constant",
            .{index},
        );
    }
    names[46] = "recursion_fri_merkle_leaf_merkle_endpoint_mask";
    names[47] = "recursion_fri_merkle_leaf_local_root_endpoint_mask";
    break :blk names;
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.fri_merkle_leaf.param.segment_active",
    "recursion.fri_merkle_leaf.param.binary_active",
    "recursion.fri_merkle_leaf.param.leaf_tag",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    position: types.ValueId,
    leaf_index: types.ValueId,
    previous: [STATE_WIDTH]types.ValueId,
    chunks: [RATE]types.ValueId,
    output: [STATE_WIDTH]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.position, self.leaf_index } ++
            self.previous ++ self.chunks ++ self.output;
    }
};

pub const ChunkPreprocessed = struct {
    source_mask: types.ValueId,
    offset: types.ValueId,
    word: types.ValueId,
    constant: types.ValueId,
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    verifier_id: types.ValueId,
    layer: types.ValueId,
    query: types.ValueId,
    packed_index: types.ValueId,
    leaf_count: types.ValueId,
    local_root_mask: types.ValueId,
    tree_id: types.ValueId,
    tree_height: types.ValueId,
    step: types.ValueId,
    first: types.ValueId,
    last: types.ValueId,
    chunks: [RATE]ChunkPreprocessed,
    merkle_endpoint_mask: types.ValueId,
    local_root_endpoint_mask: types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        var result: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
        result[0..14].* = .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.verifier_id,
            self.layer,
            self.query,
            self.packed_index,
            self.leaf_count,
            self.local_root_mask,
            self.tree_id,
            self.tree_height,
            self.step,
            self.first,
            self.last,
        };
        for (self.chunks, 0..) |chunk, index| result[14 + 4 * index ..][0..4].* = .{
            chunk.source_mask,
            chunk.offset,
            chunk.word,
            chunk.constant,
        };
        result[46] = self.merkle_endpoint_mask;
        result[47] = self.local_root_endpoint_mask;
        return result;
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    leaf_tag: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{ self.segment_active, self.binary_active, self.leaf_tag };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidFriMerkleLeafDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
    final_active: types.ValueId,
    leaf_index: types.ValueId,
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
            return error.InvalidFriMerkleLeafDefinition;
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
                return error.InvalidFriMerkleLeafDefinition;
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidFriMerkleLeafDefinition;
            if (item.root != root or item.gate != null or item.category != .semantic)
                return error.InvalidFriMerkleLeafDefinition;
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
        .leaf_index = main_values[2],
        .previous = main_values[3..][0..STATE_WIDTH].*,
        .chunks = main_values[3 + STATE_WIDTH ..][0..RATE].*,
        .output = main_values[3 + STATE_WIDTH + RATE ..][0..STATE_WIDTH].*,
    };
    var pp: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&pp, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (isPreprocessedSelector(index)) .selector else .felt, span);
    }
    var chunks: [RATE]ChunkPreprocessed = undefined;
    for (&chunks, 0..) |*chunk, index| chunk.* = .{
        .source_mask = pp[14 + 4 * index],
        .offset = pp[15 + 4 * index],
        .word = pp[16 + 4 * index],
        .constant = pp[17 + 4 * index],
    };
    const preprocessed = PreprocessedColumns{
        .row_mask = pp[0],
        .segment_mask = pp[1],
        .binary_mask = pp[2],
        .verifier_id = pp[3],
        .layer = pp[4],
        .query = pp[5],
        .packed_index = pp[6],
        .leaf_count = pp[7],
        .local_root_mask = pp[8],
        .tree_id = pp[9],
        .tree_height = pp[10],
        .step = pp[11],
        .first = pp[12],
        .last = pp[13],
        .chunks = chunks,
        .merkle_endpoint_mask = pp[46],
        .local_root_endpoint_mask = pp[47],
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .binary_active = try arena.input(PARAMETER_NAMES[1], .selector, span),
        .leaf_tag = try arena.input(PARAMETER_NAMES[2], .felt, span),
    };
    const one = try arena.constantField(1, span);
    const active = try arena.add(
        try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
        span,
    );
    const inactive = try arena.sub(one, active, span);
    const final_active = try arena.mul(active, preprocessed.last, span);
    const derived_leaf_index = try arena.add(
        try arena.mul(main.position, preprocessed.leaf_count, span),
        preprocessed.packed_index,
        span,
    );
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var cursor: usize = 0;
    roots[cursor] = try arena.sub(main.enabler, active, span);
    cursor += 1;
    roots[cursor] = try arena.sub(main.leaf_index, derived_leaf_index, span);
    cursor += 1;
    for (main.previous) |value| {
        roots[cursor] = try arena.mul(inactive, value, span);
        cursor += 1;
    }
    for (main.chunks) |value| {
        roots[cursor] = try arena.mul(inactive, value, span);
        cursor += 1;
    }
    for (main.output) |value| {
        roots[cursor] = try arena.mul(inactive, value, span);
        cursor += 1;
    }
    roots[cursor] = try arena.mul(try arena.sub(one, final_active, span), main.position, span);
    cursor += 1;
    for (main.previous, 0..) |value, index| {
        const expected = if (index == STATE_WIDTH - 1)
            try arena.sub(value, parameters.leaf_tag, span)
        else
            value;
        roots[cursor] = try arena.mul(try arena.mul(active, preprocessed.first, span), expected, span);
        cursor += 1;
    }
    for (main.chunks, preprocessed.chunks) |value, metadata| {
        roots[cursor] = try arena.mul(
            try arena.mul(active, try arena.sub(one, metadata.source_mask, span), span),
            try arena.sub(value, metadata.constant, span),
            span,
        );
        cursor += 1;
    }
    std.debug.assert(cursor == roots.len);
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var name_buffer: [96]u8 = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index| {
        const name = try std.fmt.bufPrint(
            &name_buffer,
            "recursion.fri_merkle_leaf.constraint_{d}",
            .{index},
        );
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }
    const not_first = try arena.sub(one, preprocessed.first, span);
    const not_last = try arena.sub(one, preprocessed.last, span);
    var weights: [RELATION_EVENT_COUNT]types.ValueId = undefined;
    weights[0] = active;
    for (preprocessed.chunks, 0..) |metadata, index| weights[1 + index] =
        try arena.mul(active, metadata.source_mask, span);
    weights[9] = try arena.mul(active, not_first, span);
    weights[10] = try arena.mul(active, not_last, span);
    weights[11] = final_active;
    weights[12] = try arena.mul(active, preprocessed.merkle_endpoint_mask, span);
    weights[13] = try arena.mul(active, preprocessed.local_root_endpoint_mask, span);

    var permutation_input: [STATE_WIDTH]types.ValueId = undefined;
    for (main.previous, 0..) |value, index| permutation_input[index] = if (index < RATE)
        try arena.add(value, main.chunks[index], span)
    else
        value;
    const poseidon_tuple = permutation_input ++ main.output;
    var value_tuples: [RATE][6]types.ValueId = undefined;
    for (&value_tuples, preprocessed.chunks, main.chunks) |*tuple, metadata, value| tuple.* = .{
        preprocessed.verifier_id,
        preprocessed.layer,
        preprocessed.query,
        metadata.offset,
        metadata.word,
        value,
    };
    const current_state = .{
        preprocessed.verifier_id,
        preprocessed.layer,
        preprocessed.query,
        preprocessed.packed_index,
        preprocessed.step,
    } ++ main.previous;
    const next_state = .{
        preprocessed.verifier_id,
        preprocessed.layer,
        preprocessed.query,
        preprocessed.packed_index,
        try arena.add(preprocessed.step, one, span),
    } ++ main.output;
    const route_tuple = .{
        preprocessed.verifier_id,
        preprocessed.layer,
        preprocessed.query,
        main.position,
    };
    const endpoint_tuple = .{
        preprocessed.tree_id,
        preprocessed.tree_height,
        main.leaf_index,
    } ++ main.output[0..DIGEST_WORD_COUNT].*;
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .poseidon2_io, .role = .request, .values = &poseidon_tuple, .weight = weights[0] },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit, .values = &value_tuples[0], .weight = weights[1] },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit, .values = &value_tuples[1], .weight = weights[2] },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit, .values = &value_tuples[2], .weight = weights[3] },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit, .values = &value_tuples[3], .weight = weights[4] },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit, .values = &value_tuples[4], .weight = weights[5] },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit, .values = &value_tuples[5], .weight = weights[6] },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit, .values = &value_tuples[6], .weight = weights[7] },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit, .values = &value_tuples[7], .weight = weights[8] },
        .{ .domain = .recursion_fri_merkle_leaf_state, .role = .consume, .values = &current_state, .weight = weights[9] },
        .{ .domain = .recursion_fri_merkle_leaf_state, .role = .emit, .values = &next_state, .weight = weights[10] },
        .{ .domain = .recursion_fri_merkle_route, .role = .consume, .values = &route_tuple, .weight = weights[11] },
        .{ .domain = .recursion_merkle_node, .role = .consume, .values = &endpoint_tuple, .weight = weights[12] },
        .{ .domain = .recursion_fri_merkle_local_root, .role = .consume, .values = &endpoint_tuple, .weight = weights[13] },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .active = active,
        .final_active = final_active,
        .leaf_index = main.leaf_index,
        .roots = roots,
        .constraints = constraints,
        .weights = weights,
        .events = events,
    };
}

fn isPreprocessedSelector(index: usize) bool {
    return index <= 2 or index == 8 or index == 12 or index == 13 or
        (index >= 14 and index < 46 and (index - 14) % 4 == 0) or index >= 46;
}

const InputGroup = enum { main, preprocessed, parameters };

fn validateInputGroup(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    group: InputGroup,
) error{InvalidFriMerkleLeafDefinition}!void {
    if (values.len != names.len) return error.InvalidFriMerkleLeafDefinition;
    for (values, names, 0..) |value, expected_name, index| {
        if (types.idIndex(value) != offset + index)
            return error.InvalidFriMerkleLeafDefinition;
        const node = arena.node(value) orelse return error.InvalidFriMerkleLeafDefinition;
        const expected_type: types.Type = switch (group) {
            .main => if (index == 0) .selector else .felt,
            .preprocessed => if (isPreprocessedSelector(index)) .selector else .felt,
            .parameters => if (index <= 1) .selector else .felt,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidFriMerkleLeafDefinition;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidFriMerkleLeafDefinition,
        };
        const actual = arena.name(name_id) orelse return error.InvalidFriMerkleLeafDefinition;
        if (!std.mem.eql(u8, actual, expected_name))
            return error.InvalidFriMerkleLeafDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidFriMerkleLeafDefinition}!void {
    const expected = [_]struct { domain: relation.Domain, role: relation.Role }{
        .{ .domain = .poseidon2_io, .role = .request },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit },
        .{ .domain = .recursion_fri_merkle_value_word, .role = .emit },
        .{ .domain = .recursion_fri_merkle_leaf_state, .role = .consume },
        .{ .domain = .recursion_fri_merkle_leaf_state, .role = .emit },
        .{ .domain = .recursion_fri_merkle_route, .role = .consume },
        .{ .domain = .recursion_merkle_node, .role = .consume },
        .{ .domain = .recursion_fri_merkle_local_root, .role = .consume },
    };
    for (self.events, self.weights, expected, 0..) |effect_id, weight, want, index| {
        if (types.idIndex(effect_id) != index) return error.InvalidFriMerkleLeafDefinition;
        const item = self.arena.effect(effect_id) orelse return error.InvalidFriMerkleLeafDefinition;
        const binding = item.binding orelse return error.InvalidFriMerkleLeafDefinition;
        const schema = relation.get(want.domain);
        const values = self.arena.effectValues(effect_id) orelse
            return error.InvalidFriMerkleLeafDefinition;
        if (item.kind != .component_call or item.liveness != weight or
            binding.schema != schema.id or binding.schema_version != schema.version or
            binding.role != want.role or values.len != schema.fields.len)
        {
            return error.InvalidFriMerkleLeafDefinition;
        }
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
