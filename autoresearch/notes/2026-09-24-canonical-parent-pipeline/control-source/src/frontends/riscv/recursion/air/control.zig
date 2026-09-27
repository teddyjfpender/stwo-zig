//! Exact typed logical AIR for Stark-V universal control row 0.
//!
//! There are no committed columns. Ten verifier-owned preprocessing columns
//! and two public proof-kind parameters select one VM lane or both recursion
//! lanes. Every active step is emitted; terminal close/complete rows consume
//! the same tuple so downstream gadgets must discharge the full schedule.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.control.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 0;
pub const PREPROCESSED_COLUMN_COUNT: usize = 10;
pub const PROOF_KIND_PARAMETER_COUNT: usize = 2;
pub const LOGICAL_INPUT_COUNT: usize = 12;
pub const DIRECT_CONSTRAINT_COUNT: usize = 1;
pub const RELATION_EVENT_COUNT: usize = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 0;

pub const SEMANTIC_DIGEST_HEX =
    "e3fb48a410d9fbce3a189925f04c2f2a4c18bd783ad317c1bda15c62435f18f5";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion control semantic digest",
);

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_control_segment_mask",
    "recursion_control_binary_mask",
    "recursion_control_verifier_id",
    "recursion_control_sequence",
    "recursion_control_tag",
    "recursion_control_arg_0",
    "recursion_control_arg_1",
    "recursion_control_arg_2",
    "recursion_control_arg_3",
    "recursion_control_terminal_mask",
};

pub const PARAMETER_NAMES = [PROOF_KIND_PARAMETER_COUNT][]const u8{
    "recursion.control.param.segment_active",
    "recursion.control.param.binary_active",
};

pub const PreprocessedColumns = struct {
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    verifier_id: types.ValueId,
    sequence: types.ValueId,
    tag: types.ValueId,
    args: [4]types.ValueId,
    terminal_mask: types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.segment_mask,
            self.binary_mask,
            self.verifier_id,
            self.sequence,
            self.tag,
        } ++ self.args ++ .{self.terminal_mask};
    }

    pub fn stepTuple(self: PreprocessedColumns) [7]types.ValueId {
        return .{ self.verifier_id, self.sequence, self.tag } ++ self.args;
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,

    pub fn physical(self: Parameters) [PROOF_KIND_PARAMETER_COUNT]types.ValueId {
        return .{ self.segment_active, self.binary_active };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidControlDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    generated_enabler_root: types.ValueId,
    generated_enabler_constraint: types.ConstraintId,
    active: types.ValueId,
    terminal_active: types.ValueId,
    events: [RELATION_EVENT_COUNT]types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const identity = try digest.computeIdentity(&self.arena);
        if (identity.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidControlDefinition;
        }

        try validateInputBlock(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            0,
            &.{ 0, 1, 9 },
        );
        try validateInputBlock(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PREPROCESSED_COLUMN_COUNT,
            &.{ 0, 1 },
        );
        const constraint = self.arena.constraint(self.generated_enabler_constraint) orelse
            return error.InvalidControlDefinition;
        if (types.idIndex(self.generated_enabler_constraint) != 0 or
            constraint.root != self.generated_enabler_root or constraint.gate != null or
            constraint.category != .semantic)
        {
            return error.InvalidControlDefinition;
        }
        const constraint_name = self.arena.name(constraint.name) orelse
            return error.InvalidControlDefinition;
        if (!std.mem.eql(
            u8,
            constraint_name,
            "recursion.control.enabler_boolean",
        )) return error.InvalidControlDefinition;

        const schema = relation.get(.recursion_step);
        const tuple = self.preprocessed.stepTuple();
        for (self.events, [_]relation.Role{ .emit, .consume }, [_]types.ValueId{
            self.active,
            self.terminal_active,
        }, 0..) |event_id, role, weight, index| {
            if (types.idIndex(event_id) != index)
                return error.InvalidControlDefinition;
            const effect = self.arena.effect(event_id) orelse
                return error.InvalidControlDefinition;
            const binding = effect.binding orelse
                return error.InvalidControlDefinition;
            const values = self.arena.effectValues(event_id) orelse
                return error.InvalidControlDefinition;
            if (effect.kind != .component_call or binding.schema != schema.id or
                binding.schema_version != schema.version or binding.role != role or
                effect.liveness != weight or effect.access_ordinal != null or
                !std.mem.eql(types.ValueId, values, &tuple))
            {
                return error.InvalidControlDefinition;
            }
        }
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildDefinition(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

fn buildDefinition(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();

    var preprocessing: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessing, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(
            name,
            if (index == 0 or index == 1 or index == 9) .selector else .felt,
            span,
        );
    }
    const preprocessed = PreprocessedColumns{
        .segment_mask = preprocessing[0],
        .binary_mask = preprocessing[1],
        .verifier_id = preprocessing[2],
        .sequence = preprocessing[3],
        .tag = preprocessing[4],
        .args = preprocessing[5..9].*,
        .terminal_mask = preprocessing[9],
    };

    var parameter_values: [PROOF_KIND_PARAMETER_COUNT]types.ValueId = undefined;
    for (&parameter_values, PARAMETER_NAMES) |*value, name| {
        value.* = try arena.input(name, .selector, span);
    }
    const parameters = Parameters{
        .segment_active = parameter_values[0],
        .binary_active = parameter_values[1],
    };

    // An embedded component with no committed columns receives the constant
    // framework enabler one. Preserve its generated boolean root explicitly.
    const one = try arena.constantField(1, span);
    const generated_enabler_root = try arena.mul(
        one,
        try arena.sub(one, one, span),
        span,
    );
    const generated_enabler_constraint = try arena.assertZero(
        "recursion.control.enabler_boolean",
        generated_enabler_root,
        null,
        .semantic,
        span,
    );

    const active = try arena.add(
        try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
        span,
    );
    const terminal_active = try arena.mul(active, preprocessed.terminal_mask, span);
    const tuple = preprocessed.stepTuple();
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_step, .role = .emit, .values = &tuple, .weight = active },
        .{ .domain = .recursion_step, .role = .consume, .values = &tuple, .weight = terminal_active },
    }, span);

    return .{
        .arena = arena,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .generated_enabler_root = generated_enabler_root,
        .generated_enabler_constraint = generated_enabler_constraint,
        .active = active,
        .terminal_active = terminal_active,
        .events = events,
    };
}

fn validateInputBlock(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) error{InvalidControlDefinition}!void {
    if (values.len != names.len) return error.InvalidControlDefinition;
    for (values, names, 0..) |value, name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidControlDefinition;
        const node = arena.node(value) orelse return error.InvalidControlDefinition;
        var selector = false;
        for (selector_indices) |index| selector = selector or index == local_index;
        if (!std.meta.eql(node.key.ty, if (selector) types.Type.selector else .felt))
            return error.InvalidControlDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidControlDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidControlDefinition;
        if (!std.mem.eql(u8, actual_name, name))
            return error.InvalidControlDefinition;
    }
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
