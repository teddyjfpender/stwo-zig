//! Exact typed logical AIR for Stark-V universal trace-Merkle row 23.
//!
//! The component authenticates stable leaf ordering, every Poseidon2 sponge
//! transition, every exported query value, the routed endpoint, the Merkle
//! leaf, and the mandatory verifier-control step from one typed definition.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.trace_merkle.v1";
pub const STATE_WIDTH: usize = 16;
pub const RATE: usize = 8;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2 + STATE_WIDTH + RATE + STATE_WIDTH;
pub const PREPROCESSED_COLUMN_COUNT: usize = 17 + RATE * 3;
pub const PARAMETER_COUNT: usize = 4;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize =
    1 + STATE_WIDTH + RATE + STATE_WIDTH + 1 + STATE_WIDTH + RATE;
pub const RELATION_EVENT_COUNT: usize = 14;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 7;
pub const INTERACTION_COLUMN_COUNT: usize = 28;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
/// The local profiler conservatively counts preprocessed selectors as degree
/// one; Stark-V's framework treats them as verifier-owned constants.
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 4;

pub const SEMANTIC_DIGEST_HEX =
    "e55b69031c1d02cdbf40dc514df529ac46a9a64d601c51863a59cb96073f1a2a";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion trace-Merkle semantic digest",
);

pub const MAIN_COLUMN_NAMES = blk: {
    var names: [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion.trace_merkle.enabler";
    names[1] = "recursion.trace_merkle.position";
    for (0..STATE_WIDTH) |index| names[2 + index] = std.fmt.comptimePrint(
        "recursion.trace_merkle.previous_{d}",
        .{index},
    );
    for (0..RATE) |index| names[2 + STATE_WIDTH + index] = std.fmt.comptimePrint(
        "recursion.trace_merkle.chunk_{d}",
        .{index},
    );
    for (0..STATE_WIDTH) |index| names[2 + STATE_WIDTH + RATE + index] =
        std.fmt.comptimePrint("recursion.trace_merkle.output_{d}", .{index});
    break :blk names;
};

pub const PREPROCESSED_COLUMN_NAMES = blk: {
    var names: [PREPROCESSED_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion_trace_leaf_row_mask";
    names[1] = "recursion_trace_leaf_segment_mask";
    names[2] = "recursion_trace_leaf_binary_mask";
    names[3] = "recursion_trace_leaf_verifier_id";
    names[4] = "recursion_trace_leaf_tree";
    names[5] = "recursion_trace_leaf_query";
    names[6] = "recursion_trace_leaf_tree_id";
    names[7] = "recursion_trace_leaf_tree_height";
    names[8] = "recursion_trace_leaf_step";
    names[9] = "recursion_trace_leaf_first_mask";
    names[10] = "recursion_trace_leaf_last_mask";
    names[11] = "recursion_trace_leaf_control_sequence";
    names[12] = "recursion_trace_leaf_control_tag";
    for (0..4) |index| names[13 + index] = std.fmt.comptimePrint(
        "recursion_trace_leaf_control_arg_{d}",
        .{index},
    );
    for (0..RATE) |index| {
        names[17 + 3 * index] = std.fmt.comptimePrint(
            "recursion_trace_leaf_chunk_{d}_source_mask",
            .{index},
        );
        names[18 + 3 * index] = std.fmt.comptimePrint(
            "recursion_trace_leaf_chunk_{d}_column",
            .{index},
        );
        names[19 + 3 * index] = std.fmt.comptimePrint(
            "recursion_trace_leaf_chunk_{d}_constant",
            .{index},
        );
    }
    break :blk names;
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.trace_merkle.param.segment_active",
    "recursion.trace_merkle.param.binary_active",
    "recursion.trace_merkle.param.leaf_tag",
    "recursion.trace_merkle.param.trace_position_kind",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    position: types.ValueId,
    previous: [STATE_WIDTH]types.ValueId,
    chunks: [RATE]types.ValueId,
    output: [STATE_WIDTH]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.position } ++ self.previous ++ self.chunks ++ self.output;
    }
};

pub const ChunkPreprocessed = struct {
    source_mask: types.ValueId,
    column: types.ValueId,
    constant: types.ValueId,
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    verifier_id: types.ValueId,
    tree: types.ValueId,
    query: types.ValueId,
    tree_id: types.ValueId,
    tree_height: types.ValueId,
    step: types.ValueId,
    first: types.ValueId,
    last: types.ValueId,
    control_sequence: types.ValueId,
    control_tag: types.ValueId,
    control_args: [4]types.ValueId,
    chunks: [RATE]ChunkPreprocessed,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        var result: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
        result[0..17].* = .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.verifier_id,
            self.tree,
            self.query,
            self.tree_id,
            self.tree_height,
            self.step,
            self.first,
            self.last,
            self.control_sequence,
            self.control_tag,
            self.control_args[0],
            self.control_args[1],
            self.control_args[2],
            self.control_args[3],
        };
        for (self.chunks, 0..) |chunk, index| result[17 + 3 * index ..][0..3].* = .{
            chunk.source_mask,
            chunk.column,
            chunk.constant,
        };
        return result;
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    leaf_tag: types.ValueId,
    trace_position_kind: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.binary_active,
            self.leaf_tag,
            self.trace_position_kind,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidTraceMerkleDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
    final_active: types.ValueId,
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
            return error.InvalidTraceMerkleDefinition;
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
                return error.InvalidTraceMerkleDefinition;
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidTraceMerkleDefinition;
            if (item.root != root or item.gate != null or item.category != .semantic)
                return error.InvalidTraceMerkleDefinition;
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
        .previous = main_values[2..][0..STATE_WIDTH].*,
        .chunks = main_values[2 + STATE_WIDTH ..][0..RATE].*,
        .output = main_values[2 + STATE_WIDTH + RATE ..][0..STATE_WIDTH].*,
    };

    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        const is_selector = index <= 2 or index == 9 or index == 10 or
            (index >= 17 and (index - 17) % 3 == 0);
        value.* = try arena.input(name, if (is_selector) .selector else .felt, span);
    }
    var chunks: [RATE]ChunkPreprocessed = undefined;
    for (&chunks, 0..) |*chunk, index| chunk.* = .{
        .source_mask = preprocessed_values[17 + 3 * index],
        .column = preprocessed_values[18 + 3 * index],
        .constant = preprocessed_values[19 + 3 * index],
    };
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .segment_mask = preprocessed_values[1],
        .binary_mask = preprocessed_values[2],
        .verifier_id = preprocessed_values[3],
        .tree = preprocessed_values[4],
        .query = preprocessed_values[5],
        .tree_id = preprocessed_values[6],
        .tree_height = preprocessed_values[7],
        .step = preprocessed_values[8],
        .first = preprocessed_values[9],
        .last = preprocessed_values[10],
        .control_sequence = preprocessed_values[11],
        .control_tag = preprocessed_values[12],
        .control_args = preprocessed_values[13..17].*,
        .chunks = chunks,
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .binary_active = try arena.input(PARAMETER_NAMES[1], .selector, span),
        .leaf_tag = try arena.input(PARAMETER_NAMES[2], .felt, span),
        .trace_position_kind = try arena.input(PARAMETER_NAMES[3], .felt, span),
    };
    const one = try arena.constantField(1, span);
    const zero = try arena.constantField(0, span);
    const active = try arena.add(
        try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
        span,
    );
    const inactive = try arena.sub(one, active, span);
    const final_active = try arena.mul(active, preprocessed.last, span);
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var cursor: usize = 0;
    roots[cursor] = try arena.sub(main.enabler, active, span);
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
    var constraint_name_buffer: [96]u8 = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index| {
        const name = try std.fmt.bufPrint(
            &constraint_name_buffer,
            "recursion.trace_merkle.constraint_{d}",
            .{index},
        );
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }

    const not_first = try arena.sub(one, preprocessed.first, span);
    const not_last = try arena.sub(one, preprocessed.last, span);
    var weights: [RELATION_EVENT_COUNT]types.ValueId = undefined;
    weights[0] = active;
    for (preprocessed.chunks, 0..) |metadata, index|
        weights[1 + index] = try arena.mul(active, metadata.source_mask, span);
    weights[9] = try arena.mul(active, not_first, span);
    weights[10] = try arena.mul(active, not_last, span);
    weights[11] = final_active;
    weights[12] = final_active;
    weights[13] = final_active;

    var poseidon_tuple: [32]types.ValueId = undefined;
    for (0..RATE) |index| poseidon_tuple[index] = try arena.add(
        main.previous[index],
        main.chunks[index],
        span,
    );
    @memcpy(poseidon_tuple[RATE..STATE_WIDTH], main.previous[RATE..STATE_WIDTH]);
    @memcpy(poseidon_tuple[STATE_WIDTH..], &main.output);
    var value_tuples: [RATE][5]types.ValueId = undefined;
    var previous_state_tuple: [20]types.ValueId = undefined;
    var output_state_tuple: [20]types.ValueId = undefined;
    previous_state_tuple[0..4].* = .{
        preprocessed.verifier_id,
        preprocessed.tree,
        preprocessed.query,
        preprocessed.step,
    };
    @memcpy(previous_state_tuple[4..], &main.previous);
    output_state_tuple[0..4].* = .{
        preprocessed.verifier_id,
        preprocessed.tree,
        preprocessed.query,
        try arena.add(preprocessed.step, one, span),
    };
    @memcpy(output_state_tuple[4..], &main.output);
    const position_tuple = [_]types.ValueId{
        preprocessed.verifier_id,
        parameters.trace_position_kind,
        preprocessed.tree,
        preprocessed.query,
        main.position,
        zero,
    };
    const merkle_tuple = [_]types.ValueId{
        preprocessed.tree_id,
        preprocessed.tree_height,
        main.position,
    } ++ main.output[0..RATE].*;
    const control_tuple = [_]types.ValueId{
        preprocessed.verifier_id,
        preprocessed.control_sequence,
        preprocessed.control_tag,
    } ++ preprocessed.control_args;
    var event_specs: [RELATION_EVENT_COUNT]relation_effect.EventSpec = undefined;
    event_specs[0] = .{
        .domain = .poseidon2_io,
        .role = .request,
        .values = &poseidon_tuple,
        .weight = weights[0],
    };
    for (&value_tuples, main.chunks, preprocessed.chunks, 0..) |
        *tuple,
        chunk,
        metadata,
        index,
    | {
        tuple.* = .{
            preprocessed.verifier_id,
            preprocessed.tree,
            metadata.column,
            preprocessed.query,
            chunk,
        };
        event_specs[1 + index] = .{
            .domain = .recursion_trace_query_value,
            .role = .emit,
            .values = tuple,
            .weight = weights[1 + index],
        };
    }
    event_specs[9] = .{
        .domain = .recursion_trace_leaf_hash_state,
        .role = .consume,
        .values = &previous_state_tuple,
        .weight = weights[9],
    };
    event_specs[10] = .{
        .domain = .recursion_trace_leaf_hash_state,
        .role = .emit,
        .values = &output_state_tuple,
        .weight = weights[10],
    };
    event_specs[11] = .{
        .domain = .recursion_query_position,
        .role = .consume,
        .values = &position_tuple,
        .weight = weights[11],
    };
    event_specs[12] = .{
        .domain = .recursion_merkle_node,
        .role = .consume,
        .values = &merkle_tuple,
        .weight = weights[12],
    };
    event_specs[13] = .{
        .domain = .recursion_step,
        .role = .consume,
        .values = &control_tuple,
        .weight = weights[13],
    };
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
        .final_active = final_active,
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
) error{InvalidTraceMerkleDefinition}!void {
    if (values.len != names.len) return error.InvalidTraceMerkleDefinition;
    for (values, names, 0..) |value, expected_name, index| {
        if (types.idIndex(value) != offset + index)
            return error.InvalidTraceMerkleDefinition;
        const node = arena.node(value) orelse return error.InvalidTraceMerkleDefinition;
        const expected_type: types.Type = switch (group) {
            .main => if (index == 0) .selector else .felt,
            .preprocessed => if (index <= 2 or index == 9 or index == 10 or
                (index >= 17 and (index - 17) % 3 == 0)) .selector else .felt,
            .parameters => if (index <= 1) .selector else .felt,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidTraceMerkleDefinition;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidTraceMerkleDefinition,
        };
        const actual = arena.name(name_id) orelse return error.InvalidTraceMerkleDefinition;
        if (!std.mem.eql(u8, actual, expected_name))
            return error.InvalidTraceMerkleDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidTraceMerkleDefinition}!void {
    const expected = [_]struct { domain: relation.Domain, role: relation.Role }{
        .{ .domain = .poseidon2_io, .role = .request },
        .{ .domain = .recursion_trace_query_value, .role = .emit },
        .{ .domain = .recursion_trace_query_value, .role = .emit },
        .{ .domain = .recursion_trace_query_value, .role = .emit },
        .{ .domain = .recursion_trace_query_value, .role = .emit },
        .{ .domain = .recursion_trace_query_value, .role = .emit },
        .{ .domain = .recursion_trace_query_value, .role = .emit },
        .{ .domain = .recursion_trace_query_value, .role = .emit },
        .{ .domain = .recursion_trace_query_value, .role = .emit },
        .{ .domain = .recursion_trace_leaf_hash_state, .role = .consume },
        .{ .domain = .recursion_trace_leaf_hash_state, .role = .emit },
        .{ .domain = .recursion_query_position, .role = .consume },
        .{ .domain = .recursion_merkle_node, .role = .consume },
        .{ .domain = .recursion_step, .role = .consume },
    };
    for (self.events, self.weights, expected, 0..) |effect_id, weight, want, index| {
        if (types.idIndex(effect_id) != index) return error.InvalidTraceMerkleDefinition;
        const item = self.arena.effect(effect_id) orelse return error.InvalidTraceMerkleDefinition;
        const binding = item.binding orelse return error.InvalidTraceMerkleDefinition;
        const schema = relation.get(want.domain);
        const values = self.arena.effectValues(effect_id) orelse
            return error.InvalidTraceMerkleDefinition;
        if (item.kind != .component_call or item.liveness != weight or
            binding.schema != schema.id or binding.schema_version != schema.version or
            binding.role != want.role or values.len != schema.fields.len)
        {
            return error.InvalidTraceMerkleDefinition;
        }
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
