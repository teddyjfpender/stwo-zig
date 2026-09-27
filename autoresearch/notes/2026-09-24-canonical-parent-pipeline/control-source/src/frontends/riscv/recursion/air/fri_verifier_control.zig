//! Exact typed logical AIR for Stark-V universal FRI verifier-control row 28.
//!
//! The row adapts verifier-owned DEEP/fold/last-layer control steps to atomic
//! query positions and scalar route words without permitting committed values
//! to choose schedule or route geometry.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.fri_verifier_control.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 3;
pub const PREPROCESSED_COLUMN_COUNT: usize = 15;
pub const PARAMETER_COUNT: usize = 4;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 6;
pub const RELATION_EVENT_COUNT: usize = 4;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "44c87ee65d3d2eeb82fd3a3beb846e404e90e98820e96b16027459620b9cac86";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion FRI-verifier-control semantic digest",
);

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.fri_verifier_control.enabler",
    "recursion.fri_verifier_control.position",
    "recursion.fri_verifier_control.offset",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_fri_control_row_mask",
    "recursion_fri_control_segment_mask",
    "recursion_fri_control_binary_mask",
    "recursion_fri_control_route_mask",
    "recursion_fri_control_offset_output_mask",
    "recursion_fri_control_verifier_id",
    "recursion_fri_control_route_kind",
    "recursion_fri_control_item",
    "recursion_fri_control_query",
    "recursion_fri_control_sequence",
    "recursion_fri_control_tag",
    "recursion_fri_control_arg_0",
    "recursion_fri_control_arg_1",
    "recursion_fri_control_arg_2",
    "recursion_fri_control_arg_3",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.fri_verifier_control.param.segment_active",
    "recursion.fri_verifier_control.param.binary_active",
    "recursion.fri_verifier_control.param.position_field",
    "recursion.fri_verifier_control.param.offset_field",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    position: types.ValueId,
    offset: types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.position, self.offset };
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    route_mask: types.ValueId,
    offset_output_mask: types.ValueId,
    verifier_id: types.ValueId,
    route_kind: types.ValueId,
    item: types.ValueId,
    query: types.ValueId,
    sequence: types.ValueId,
    tag: types.ValueId,
    args: [4]types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.route_mask,
            self.offset_output_mask,
            self.verifier_id,
            self.route_kind,
            self.item,
            self.query,
            self.sequence,
            self.tag,
        } ++ self.args;
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    position_field: types.ValueId,
    offset_field: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.binary_active,
            self.position_field,
            self.offset_field,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidFriVerifierControlDefinition,
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
            return error.InvalidFriVerifierControlDefinition;
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
                return error.InvalidFriVerifierControlDefinition;
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidFriVerifierControlDefinition;
            if (item.root != root or item.gate != null or item.category != .semantic)
                return error.InvalidFriVerifierControlDefinition;
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
        .offset = main_values[2],
    };
    var pp: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&pp, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (index <= 4) .selector else .felt, span);
    }
    const preprocessed = PreprocessedColumns{
        .row_mask = pp[0],
        .segment_mask = pp[1],
        .binary_mask = pp[2],
        .route_mask = pp[3],
        .offset_output_mask = pp[4],
        .verifier_id = pp[5],
        .route_kind = pp[6],
        .item = pp[7],
        .query = pp[8],
        .sequence = pp[9],
        .tag = pp[10],
        .args = pp[11..15].*,
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .binary_active = try arena.input(PARAMETER_NAMES[1], .selector, span),
        .position_field = try arena.input(PARAMETER_NAMES[2], .felt, span),
        .offset_field = try arena.input(PARAMETER_NAMES[3], .felt, span),
    };
    const one = try arena.constantField(1, span);
    const active = try arena.add(
        try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
        span,
    );
    const inactive = try arena.sub(one, active, span);
    const non_route = try arena.sub(preprocessed.row_mask, preprocessed.route_mask, span);
    const non_offset_output = try arena.sub(
        preprocessed.route_mask,
        preprocessed.offset_output_mask,
        span,
    );
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.sub(main.enabler, preprocessed.row_mask, span),
        try arena.mul(inactive, main.position, span),
        try arena.mul(inactive, main.offset, span),
        try arena.mul(non_route, main.position, span),
        try arena.mul(non_route, main.offset, span),
        try arena.mul(non_offset_output, main.offset, span),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var name_buffer: [96]u8 = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index| {
        const name = try std.fmt.bufPrint(
            &name_buffer,
            "recursion.fri_verifier_control.constraint_{d}",
            .{index},
        );
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }

    const weights = [RELATION_EVENT_COUNT]types.ValueId{
        try arena.mul(active, preprocessed.row_mask, span),
        try arena.mul(active, preprocessed.route_mask, span),
        try arena.mul(active, preprocessed.route_mask, span),
        try arena.mul(active, preprocessed.offset_output_mask, span),
    };
    const control_tuple = .{
        preprocessed.verifier_id,
        preprocessed.sequence,
        preprocessed.tag,
    } ++ preprocessed.args;
    const position_tuple = .{
        preprocessed.verifier_id,
        preprocessed.route_kind,
        preprocessed.item,
        preprocessed.query,
        main.position,
        main.offset,
    };
    const position_word_tuple = .{
        preprocessed.verifier_id,
        preprocessed.route_kind,
        preprocessed.item,
        preprocessed.query,
        parameters.position_field,
        main.position,
    };
    const offset_word_tuple = .{
        preprocessed.verifier_id,
        preprocessed.route_kind,
        preprocessed.item,
        preprocessed.query,
        parameters.offset_field,
        main.offset,
    };
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_step, .role = .consume, .values = &control_tuple, .weight = weights[0] },
        .{ .domain = .recursion_query_position, .role = .consume, .values = &position_tuple, .weight = weights[1] },
        .{ .domain = .recursion_fri_verifier_route_word, .role = .emit, .values = &position_word_tuple, .weight = weights[2] },
        .{ .domain = .recursion_fri_verifier_route_word, .role = .emit, .values = &offset_word_tuple, .weight = weights[3] },
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
) error{InvalidFriVerifierControlDefinition}!void {
    if (values.len != names.len) return error.InvalidFriVerifierControlDefinition;
    for (values, names, 0..) |value, expected_name, index| {
        if (types.idIndex(value) != offset + index)
            return error.InvalidFriVerifierControlDefinition;
        const node = arena.node(value) orelse return error.InvalidFriVerifierControlDefinition;
        const expected_type: types.Type = switch (group) {
            .main => if (index == 0) .selector else .felt,
            .preprocessed => if (index <= 4) .selector else .felt,
            .parameters => if (index <= 1) .selector else .felt,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidFriVerifierControlDefinition;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidFriVerifierControlDefinition,
        };
        const actual = arena.name(name_id) orelse return error.InvalidFriVerifierControlDefinition;
        if (!std.mem.eql(u8, actual, expected_name))
            return error.InvalidFriVerifierControlDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidFriVerifierControlDefinition}!void {
    const expected = [_]struct { domain: relation.Domain, role: relation.Role }{
        .{ .domain = .recursion_step, .role = .consume },
        .{ .domain = .recursion_query_position, .role = .consume },
        .{ .domain = .recursion_fri_verifier_route_word, .role = .emit },
        .{ .domain = .recursion_fri_verifier_route_word, .role = .emit },
    };
    for (self.events, self.weights, expected, 0..) |effect_id, weight, want, index| {
        if (types.idIndex(effect_id) != index)
            return error.InvalidFriVerifierControlDefinition;
        const item = self.arena.effect(effect_id) orelse
            return error.InvalidFriVerifierControlDefinition;
        const binding = item.binding orelse return error.InvalidFriVerifierControlDefinition;
        const schema = relation.get(want.domain);
        const values = self.arena.effectValues(effect_id) orelse
            return error.InvalidFriVerifierControlDefinition;
        if (item.kind != .component_call or item.liveness != weight or
            binding.schema != schema.id or binding.schema_version != schema.version or
            binding.role != want.role or values.len != schema.fields.len)
        {
            return error.InvalidFriVerifierControlDefinition;
        }
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
