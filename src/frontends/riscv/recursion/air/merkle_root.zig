//! Exact typed logical AIR for Stark-V universal Merkle-root row 22.
//!
//! Every active transcript commitment word is consumed exactly once and the
//! resulting digest is emitted as a namespaced root node once per authenticated
//! query path. Tree identifiers and path multiplicities are verifier-owned.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.merkle_root.v1";
pub const DIGEST_WORD_COUNT: usize = 8;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1 + DIGEST_WORD_COUNT;
pub const PREPROCESSED_COLUMN_COUNT: usize = 8;
pub const PARAMETER_COUNT: usize = 2;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 1 + DIGEST_WORD_COUNT;
pub const RELATION_EVENT_COUNT: usize = DIGEST_WORD_COUNT + 1;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 5;
pub const INTERACTION_COLUMN_COUNT: usize = 20;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "f298939576ee772c146c1bb1d61ab6e0478cc80926272d80fd37a28b2b91aa6e";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion Merkle-root semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.merkle_root.enabler",
    "recursion.merkle_root.digest_0",
    "recursion.merkle_root.digest_1",
    "recursion.merkle_root.digest_2",
    "recursion.merkle_root.digest_3",
    "recursion.merkle_root.digest_4",
    "recursion.merkle_root.digest_5",
    "recursion.merkle_root.digest_6",
    "recursion.merkle_root.digest_7",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_merkle_root_row_mask",
    "recursion_merkle_root_segment_mask",
    "recursion_merkle_root_binary_mask",
    "recursion_merkle_root_verifier_id",
    "recursion_merkle_root_input_kind",
    "recursion_merkle_root_item",
    "recursion_merkle_root_tree_id",
    "recursion_merkle_root_path_count",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.merkle_root.param.segment_active",
    "recursion.merkle_root.param.binary_active",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    digest_words: [DIGEST_WORD_COUNT]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.enabler} ++ self.digest_words;
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    verifier_id: types.ValueId,
    input_kind: types.ValueId,
    item: types.ValueId,
    tree_id: types.ValueId,
    path_count: types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.verifier_id,
            self.input_kind,
            self.item,
            self.tree_id,
            self.path_count,
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
    InvalidMerkleRootDefinition,
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
        const actual_identity = try digest.computeIdentity(&self.arena);
        if (actual_identity.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &actual_identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidMerkleRootDefinition;
        }
        try validateInputs(
            &self.arena,
            &self.main.physical(),
            &MAIN_COLUMN_NAMES,
            0,
            .main,
        );
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            .preprocessed,
        );
        try validateInputs(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            .parameters,
        );
        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidMerkleRootDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidMerkleRootDefinition;
            const expected_name = if (index == 0)
                "recursion.merkle_root.enabler_matches_active"
            else
                MAIN_COLUMN_NAMES[index];
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidMerkleRootDefinition;
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
        .digest_words = main_values[1..][0..DIGEST_WORD_COUNT].*,
    };

    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index|
        value.* = try arena.input(name, if (index <= 2) .selector else .felt, span);
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .segment_mask = preprocessed_values[1],
        .binary_mask = preprocessed_values[2],
        .verifier_id = preprocessed_values[3],
        .input_kind = preprocessed_values[4],
        .item = preprocessed_values[5],
        .tree_id = preprocessed_values[6],
        .path_count = preprocessed_values[7],
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .binary_active = try arena.input(PARAMETER_NAMES[1], .selector, span),
    };

    const one = try arena.constantField(1, span);
    const zero = try arena.constantField(0, span);
    const active = try arena.add(
        try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
        span,
    );
    const inactive = try arena.sub(one, active, span);
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    roots[0] = try arena.sub(main.enabler, active, span);
    for (main.digest_words, 0..) |word, index|
        roots[1 + index] = try arena.mul(inactive, word, span);
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index| {
        const name = if (index == 0)
            "recursion.merkle_root.enabler_matches_active"
        else
            MAIN_COLUMN_NAMES[index];
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }

    var weights: [RELATION_EVENT_COUNT]types.ValueId = undefined;
    for (weights[0..DIGEST_WORD_COUNT]) |*weight| weight.* = active;
    weights[DIGEST_WORD_COUNT] = try arena.mul(active, preprocessed.path_count, span);
    var input_tuples: [DIGEST_WORD_COUNT][5]types.ValueId = undefined;
    var event_specs: [RELATION_EVENT_COUNT]relation_effect.EventSpec = undefined;
    for (&input_tuples, main.digest_words, 0..) |*tuple, word, index| {
        tuple.* = .{
            preprocessed.verifier_id,
            preprocessed.input_kind,
            preprocessed.item,
            try arena.constantField(@intCast(index), span),
            word,
        };
        event_specs[index] = .{
            .domain = .recursion_verifier_input_word,
            .role = .consume,
            .values = tuple,
            .weight = weights[index],
        };
    }
    const merkle_tuple = [_]types.ValueId{
        preprocessed.tree_id,
        zero,
        zero,
    } ++ main.digest_words;
    event_specs[DIGEST_WORD_COUNT] = .{
        .domain = .recursion_merkle_node,
        .role = .emit,
        .values = &merkle_tuple,
        .weight = weights[DIGEST_WORD_COUNT],
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
        .roots = roots,
        .constraints = constraints,
        .weights = weights,
        .events = events,
    };
}

const InputGroup = enum { main, preprocessed, parameters };

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    group: InputGroup,
) error{InvalidMerkleRootDefinition}!void {
    if (values.len != names.len) return error.InvalidMerkleRootDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidMerkleRootDefinition;
        const node = arena.node(value) orelse return error.InvalidMerkleRootDefinition;
        const expected_type: types.Type = switch (group) {
            .main => if (local_index == 0) .selector else .felt,
            .preprocessed => if (local_index <= 2) .selector else .felt,
            .parameters => .selector,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidMerkleRootDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidMerkleRootDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidMerkleRootDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidMerkleRootDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidMerkleRootDefinition}!void {
    for (self.main.digest_words, 0..) |word, index| {
        const limb = constantValue(&self.arena, index) orelse
            return error.InvalidMerkleRootDefinition;
        const tuple = [_]types.ValueId{
            self.preprocessed.verifier_id,
            self.preprocessed.input_kind,
            self.preprocessed.item,
            limb,
            word,
        };
        try validateEvent(
            self,
            index,
            .recursion_verifier_input_word,
            .consume,
            &tuple,
        );
    }
    const zero = constantValue(&self.arena, 0) orelse
        return error.InvalidMerkleRootDefinition;
    const tuple = [_]types.ValueId{
        self.preprocessed.tree_id,
        zero,
        zero,
    } ++ self.main.digest_words;
    try validateEvent(
        self,
        DIGEST_WORD_COUNT,
        .recursion_merkle_node,
        .emit,
        &tuple,
    );
}

fn validateEvent(
    self: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    expected_values: []const types.ValueId,
) error{InvalidMerkleRootDefinition}!void {
    const effect_id = self.events[index];
    if (types.idIndex(effect_id) != index) return error.InvalidMerkleRootDefinition;
    const item = self.arena.effect(effect_id) orelse return error.InvalidMerkleRootDefinition;
    const binding = item.binding orelse return error.InvalidMerkleRootDefinition;
    const schema = relation.get(domain);
    const values = self.arena.effectValues(effect_id) orelse
        return error.InvalidMerkleRootDefinition;
    if (item.kind != .component_call or item.liveness != self.weights[index] or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        !std.mem.eql(types.ValueId, values, expected_values))
    {
        return error.InvalidMerkleRootDefinition;
    }
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
