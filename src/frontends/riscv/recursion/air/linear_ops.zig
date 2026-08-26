//! Exact typed logical AIR for Stark-V recursion QM31 add/sub/neg rows.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const program = @import("../../air/lang/program.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const arithmetic = @import("qm31_mul.zig");
const component_support = @import("component_support.zig");
const wire = @import("wire_relation.zig");

pub const DECLARED_COMMITTED_COLUMN_COUNT: usize = 20;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 21;
pub const PREPROCESSED_COLUMN_COUNT: usize = 27;
pub const PROOF_KIND_PARAMETER_COUNT: usize = 3;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT +
    PROOF_KIND_PARAMETER_COUNT;
pub const AUTHORED_CONSTRAINT_COUNT: usize = 17;
pub const DIRECT_CONSTRAINT_COUNT: usize = 18;
pub const RELATION_EVENT_COUNT: usize = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "dc09207710459ccac149a37cf105d82ed34f11492eaaa66374aa94b2b32a73e3";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion linear-ops semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "d7062cef2216a8fbd34e857462f74315af63dc00fb9fe67df1ff7e7297dc48dd";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.linear_ops.enabler",
    "recursion.linear_ops.circuit_id",
    "recursion.linear_ops.node_id",
    "recursion.linear_ops.is_add",
    "recursion.linear_ops.is_sub",
    "recursion.linear_ops.is_neg",
    "recursion.linear_ops.lhs_id",
    "recursion.linear_ops.rhs_id",
    "recursion.linear_ops.lhs.0",
    "recursion.linear_ops.lhs.1",
    "recursion.linear_ops.lhs.2",
    "recursion.linear_ops.lhs.3",
    "recursion.linear_ops.rhs.0",
    "recursion.linear_ops.rhs.1",
    "recursion.linear_ops.rhs.2",
    "recursion.linear_ops.rhs.3",
    "recursion.linear_ops.out.0",
    "recursion.linear_ops.out.1",
    "recursion.linear_ops.out.2",
    "recursion.linear_ops.out.3",
    "recursion.linear_ops.uses",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_linear_ops_segment_mask",
    "recursion_linear_ops_segment_circuit_id",
    "recursion_linear_ops_segment_node_id",
    "recursion_linear_ops_segment_is_add",
    "recursion_linear_ops_segment_is_sub",
    "recursion_linear_ops_segment_is_neg",
    "recursion_linear_ops_segment_lhs_id",
    "recursion_linear_ops_segment_rhs_id",
    "recursion_linear_ops_segment_uses",
    "recursion_linear_ops_binary_mask",
    "recursion_linear_ops_binary_circuit_id",
    "recursion_linear_ops_binary_node_id",
    "recursion_linear_ops_binary_is_add",
    "recursion_linear_ops_binary_is_sub",
    "recursion_linear_ops_binary_is_neg",
    "recursion_linear_ops_binary_lhs_id",
    "recursion_linear_ops_binary_rhs_id",
    "recursion_linear_ops_binary_uses",
    "recursion_linear_ops_empty_mask",
    "recursion_linear_ops_empty_circuit_id",
    "recursion_linear_ops_empty_node_id",
    "recursion_linear_ops_empty_is_add",
    "recursion_linear_ops_empty_is_sub",
    "recursion_linear_ops_empty_is_neg",
    "recursion_linear_ops_empty_lhs_id",
    "recursion_linear_ops_empty_rhs_id",
    "recursion_linear_ops_empty_uses",
};

pub const PARAMETER_NAMES = [PROOF_KIND_PARAMETER_COUNT][]const u8{
    "recursion.linear_ops.param.segment_active",
    "recursion.linear_ops.param.binary_active",
    "recursion.linear_ops.param.empty_active",
};

pub const Location = arithmetic.Location;

pub const MainColumns = struct {
    enabler: types.ValueId,
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    is_add: types.ValueId,
    is_sub: types.ValueId,
    is_neg: types.ValueId,
    lhs_id: types.ValueId,
    rhs_id: types.ValueId,
    lhs: [4]types.ValueId,
    rhs: [4]types.ValueId,
    out: [4]types.ValueId,
    uses: types.ValueId,

    pub fn declared(self: MainColumns) [DECLARED_COMMITTED_COLUMN_COUNT]types.ValueId {
        return .{
            self.circuit_id,
            self.node_id,
            self.is_add,
            self.is_sub,
            self.is_neg,
            self.lhs_id,
            self.rhs_id,
        } ++ self.lhs ++ self.rhs ++ self.out ++ .{self.uses};
    }

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.enabler} ++ self.declared();
    }

    pub fn operationFlags(self: MainColumns) [3]types.ValueId {
        return .{ self.is_add, self.is_sub, self.is_neg };
    }
};

pub const ScheduleColumns = struct {
    mask: types.ValueId,
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    is_add: types.ValueId,
    is_sub: types.ValueId,
    is_neg: types.ValueId,
    lhs_id: types.ValueId,
    rhs_id: types.ValueId,
    uses: types.ValueId,

    pub fn physical(self: ScheduleColumns) [9]types.ValueId {
        return .{
            self.mask,
            self.circuit_id,
            self.node_id,
            self.is_add,
            self.is_sub,
            self.is_neg,
            self.lhs_id,
            self.rhs_id,
            self.uses,
        };
    }
};

pub const PreprocessedColumns = struct {
    segment: ScheduleColumns,
    binary: ScheduleColumns,
    empty: ScheduleColumns,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return self.segment.physical() ++ self.binary.physical() ++
            self.empty.physical();
    }
};

pub const ProofKindParameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,
    empty_active: types.ValueId,

    pub fn physical(self: ProofKindParameters) [PROOF_KIND_PARAMETER_COUNT]types.ValueId {
        return .{ self.segment_active, self.binary_active, self.empty_active };
    }
};

pub const Events = struct {
    lhs_consume: types.EffectId,
    rhs_consume: types.EffectId,
    output_emit: types.EffectId,
    rhs_weight: types.ValueId,

    pub fn ordered(self: Events) [RELATION_EVENT_COUNT]types.EffectId {
        return .{ self.lhs_consume, self.rhs_consume, self.output_emit };
    }
};

pub const ValidationError = validate_mod.Error || wire.Error || error{
    InvalidLinearOpsDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: ProofKindParameters,
    selected: ScheduleColumns,
    expected: [4]types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    events: Events,

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
            return error.InvalidLinearOpsDefinition;
        }
        const main = self.main.physical();
        const preprocessed = self.preprocessed.physical();
        const parameters = self.parameters.physical();
        try validateInputs(&self.arena, &main, &MAIN_COLUMN_NAMES, 0, .main);
        try validateInputs(
            &self.arena,
            &preprocessed,
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            .preprocessed,
        );
        try validateInputs(
            &self.arena,
            &parameters,
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            .parameters,
        );
        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            if (types.idIndex(constraint_id) != index)
                return error.InvalidLinearOpsDefinition;
            const constraint = self.arena.constraint(constraint_id) orelse
                return error.InvalidLinearOpsDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidLinearOpsDefinition;
            }
            const name = self.arena.name(constraint.name) orelse
                return error.InvalidLinearOpsDefinition;
            if (!std.mem.eql(u8, name, CONSTRAINT_NAMES[index]))
                return error.InvalidLinearOpsDefinition;
        }
        if (!std.meta.eql(self.roots[14..18].*, self.expected))
            return error.InvalidLinearOpsDefinition;
        try validateEvents(self);
    }
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.linear_ops.enabler_boolean",
    "recursion.linear_ops.is_add_boolean",
    "recursion.linear_ops.is_sub_boolean",
    "recursion.linear_ops.is_neg_boolean",
    "recursion.linear_ops.operation_one_hot",
    "recursion.linear_ops.schedule.mask",
    "recursion.linear_ops.schedule.circuit_id",
    "recursion.linear_ops.schedule.node_id",
    "recursion.linear_ops.schedule.is_add",
    "recursion.linear_ops.schedule.is_sub",
    "recursion.linear_ops.schedule.is_neg",
    "recursion.linear_ops.schedule.lhs_id",
    "recursion.linear_ops.schedule.rhs_id",
    "recursion.linear_ops.schedule.uses",
    "recursion.linear_ops.result.0",
    "recursion.linear_ops.result.1",
    "recursion.linear_ops.result.2",
    "recursion.linear_ops.result.3",
};

pub fn build(allocator: std.mem.Allocator, location: Location) !Definition {
    var result = try buildDefinition(allocator, location);
    errdefer result.deinit();
    try result.validate();
    return result;
}

fn buildDefinition(allocator: std.mem.Allocator, location: Location) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = try location.install(&arena);
    var main_values: [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId = undefined;
    for (&main_values, MAIN_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, mainType(index), span);
    }
    const main = MainColumns{
        .enabler = main_values[0],
        .circuit_id = main_values[1],
        .node_id = main_values[2],
        .is_add = main_values[3],
        .is_sub = main_values[4],
        .is_neg = main_values[5],
        .lhs_id = main_values[6],
        .rhs_id = main_values[7],
        .lhs = main_values[8..12].*,
        .rhs = main_values[12..16].*,
        .out = main_values[16..20].*,
        .uses = main_values[20],
    };
    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, scheduleType(index % 9), span);
    }
    const preprocessed = PreprocessedColumns{
        .segment = scheduleFrom(preprocessed_values[0..9].*),
        .binary = scheduleFrom(preprocessed_values[9..18].*),
        .empty = scheduleFrom(preprocessed_values[18..27].*),
    };
    var parameter_values: [PROOF_KIND_PARAMETER_COUNT]types.ValueId = undefined;
    for (&parameter_values, PARAMETER_NAMES) |*value, name| {
        value.* = try arena.input(name, .selector, span);
    }
    const parameters = ProofKindParameters{
        .segment_active = parameter_values[0],
        .binary_active = parameter_values[1],
        .empty_active = parameter_values[2],
    };
    const selected = scheduleFrom(try component_support.selectSchedule(
        9,
        &arena,
        .{
            preprocessed.segment.physical(),
            preprocessed.binary.physical(),
            preprocessed.empty.physical(),
        },
        parameters.physical(),
        span,
    ));

    const one = try arena.constantField(1, span);
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    roots[0] = try component_support.booleanRoot(&arena, main.enabler, one, span);
    roots[1] = try component_support.booleanRoot(&arena, main.is_add, one, span);
    roots[2] = try component_support.booleanRoot(&arena, main.is_sub, one, span);
    roots[3] = try component_support.booleanRoot(&arena, main.is_neg, one, span);
    roots[4] = try arena.sub(
        try arena.add(try arena.add(main.is_add, main.is_sub, span), main.is_neg, span),
        main.enabler,
        span,
    );
    roots[5] = try arena.sub(main.enabler, selected.mask, span);
    const committed_schedule = [_]types.ValueId{
        main.circuit_id, main.node_id, main.is_add, main.is_sub,
        main.is_neg,     main.lhs_id,  main.rhs_id, main.uses,
    };
    const selected_schedule = [_]types.ValueId{
        selected.circuit_id, selected.node_id, selected.is_add, selected.is_sub,
        selected.is_neg,     selected.lhs_id,  selected.rhs_id, selected.uses,
    };
    for (committed_schedule, selected_schedule, 6..) |committed, scheduled, index| {
        roots[index] = try arena.mul(
            main.enabler,
            try arena.sub(committed, scheduled, span),
            span,
        );
    }
    var expected: [4]types.ValueId = undefined;
    for (&expected, main.lhs, main.rhs, main.out) |*root, lhs, rhs, out| {
        const add_term = try arena.mul(main.is_add, try arena.add(lhs, rhs, span), span);
        const sub_term = try arena.mul(main.is_sub, try arena.sub(lhs, rhs, span), span);
        const neg_term = try arena.mul(main.is_neg, lhs, span);
        root.* = try arena.sub(
            try arena.sub(try arena.add(add_term, sub_term, span), neg_term, span),
            out,
            span,
        );
    }
    @memcpy(roots[14..18], &expected);
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name| {
        constraint.* = try arena.assertZero(
            name,
            root,
            null,
            program.ConstraintCategory.semantic,
            span,
        );
    }

    const node_checkpoint = arena.nodeCheckpoint();
    errdefer arena.rollbackToNodeCheckpoint(node_checkpoint);
    const rhs_weight = try arena.add(main.is_add, main.is_sub, span);
    const event_ids = try wire.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .role = .consume,
            .tuple = .{
                .circuit_id = main.circuit_id,
                .node_id = main.lhs_id,
                .value = main.lhs,
            },
            .weight = main.enabler,
        },
        .{
            .role = .consume,
            .tuple = .{
                .circuit_id = main.circuit_id,
                .node_id = main.rhs_id,
                .value = main.rhs,
            },
            .weight = rhs_weight,
        },
        .{
            .role = .emit,
            .tuple = .{
                .circuit_id = main.circuit_id,
                .node_id = main.node_id,
                .value = main.out,
            },
            .weight = main.uses,
        },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .selected = selected,
        .expected = expected,
        .roots = roots,
        .constraints = constraints,
        .events = .{
            .lhs_consume = event_ids[0],
            .rhs_consume = event_ids[1],
            .output_emit = event_ids[2],
            .rhs_weight = rhs_weight,
        },
    };
}

const InputClass = enum { main, preprocessed, parameters };

fn scheduleFrom(values: [9]types.ValueId) ScheduleColumns {
    return .{
        .mask = values[0],
        .circuit_id = values[1],
        .node_id = values[2],
        .is_add = values[3],
        .is_sub = values[4],
        .is_neg = values[5],
        .lhs_id = values[6],
        .rhs_id = values[7],
        .uses = values[8],
    };
}

fn mainType(index: usize) types.Type {
    return switch (index) {
        0, 3, 4, 5 => .selector,
        else => .felt,
    };
}

fn scheduleType(index: usize) types.Type {
    return switch (index) {
        0, 3, 4, 5 => .selector,
        else => .felt,
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    class: InputClass,
) error{InvalidLinearOpsDefinition}!void {
    if (values.len != names.len) return error.InvalidLinearOpsDefinition;
    for (values, names, 0..) |value, name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidLinearOpsDefinition;
        const node = arena.node(value) orelse return error.InvalidLinearOpsDefinition;
        const expected_type: types.Type = switch (class) {
            .main => mainType(local_index),
            .preprocessed => scheduleType(local_index % 9),
            .parameters => .selector,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidLinearOpsDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidLinearOpsDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidLinearOpsDefinition;
        if (!std.mem.eql(u8, actual_name, name))
            return error.InvalidLinearOpsDefinition;
    }
}

fn validateEvents(self: *const Definition) ValidationError!void {
    const ids = self.events.ordered();
    const expected_values = [RELATION_EVENT_COUNT][wire.ARITY]types.ValueId{
        (wire.Tuple{
            .circuit_id = self.main.circuit_id,
            .node_id = self.main.lhs_id,
            .value = self.main.lhs,
        }).values(),
        (wire.Tuple{
            .circuit_id = self.main.circuit_id,
            .node_id = self.main.rhs_id,
            .value = self.main.rhs,
        }).values(),
        (wire.Tuple{
            .circuit_id = self.main.circuit_id,
            .node_id = self.main.node_id,
            .value = self.main.out,
        }).values(),
    };
    const expected_roles = [_]relation.Role{ .consume, .consume, .emit };
    const expected_liveness = [_]types.ValueId{
        self.main.enabler,
        self.events.rhs_weight,
        self.main.uses,
    };
    const schema = relation.get(.recursion_wire);
    for (ids, expected_values, expected_roles, expected_liveness, 0..) |
        id,
        values,
        role,
        liveness,
        index,
    | {
        if (types.idIndex(id) != index) return error.InvalidLinearOpsDefinition;
        const effect = self.arena.effect(id) orelse
            return error.InvalidLinearOpsDefinition;
        const binding = effect.binding orelse return error.InvalidLinearOpsDefinition;
        const actual_values = self.arena.effectValues(id) orelse
            return error.InvalidLinearOpsDefinition;
        if (effect.kind != .component_call or binding.schema != schema.id or
            binding.schema_version != schema.version or binding.role != role or
            effect.liveness != liveness or effect.access_ordinal != null or
            !std.mem.eql(types.ValueId, actual_values, &values))
        {
            return error.InvalidLinearOpsDefinition;
        }
    }
    const weight = binaryAdd(&self.arena, self.events.rhs_weight) orelse
        return error.InvalidLinearOpsDefinition;
    if (!unorderedPairEquals(weight, self.main.is_add, self.main.is_sub))
        return error.InvalidLinearOpsDefinition;
}

fn binaryAdd(
    arena: *const ir.Arena,
    value: types.ValueId,
) ?@import("../../air/lang/expr.zig").Binary {
    const node = arena.node(value) orelse return null;
    return switch (node.key.op) {
        .add => |binary| binary,
        else => null,
    };
}

fn unorderedPairEquals(
    actual: @import("../../air/lang/expr.zig").Binary,
    lhs: types.ValueId,
    rhs: types.ValueId,
) bool {
    return (actual.lhs == lhs and actual.rhs == rhs) or
        (actual.lhs == rhs and actual.rhs == lhs);
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
