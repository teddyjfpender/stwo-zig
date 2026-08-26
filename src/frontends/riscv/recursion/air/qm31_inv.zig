//! Exact typed logical AIR for Stark-V's recursion QM31 inversion row.

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

pub const DECLARED_COMMITTED_COLUMN_COUNT: usize = 13;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 14;
pub const PREPROCESSED_COLUMN_COUNT: usize = 15;
pub const PROOF_KIND_PARAMETER_COUNT: usize = 3;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT +
    PROOF_KIND_PARAMETER_COUNT;
pub const AUTHORED_CONSTRAINT_COUNT: usize = 11;
pub const DIRECT_CONSTRAINT_COUNT: usize = 12;
pub const RELATION_EVENT_COUNT: usize = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "0940fc4d65bece4f9837cae7e03240dee490121661772d616b58df1509e08a40";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion QM31 inversion semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "241be3d67e580dae0a427249516b8f95ed09dab87265ab42e8a9fea7a7d264c3";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.qm31_inv.enabler",
    "recursion.qm31_inv.a.0",
    "recursion.qm31_inv.a.1",
    "recursion.qm31_inv.a.2",
    "recursion.qm31_inv.a.3",
    "recursion.qm31_inv.inv.0",
    "recursion.qm31_inv.inv.1",
    "recursion.qm31_inv.inv.2",
    "recursion.qm31_inv.inv.3",
    "recursion.qm31_inv.circuit_id",
    "recursion.qm31_inv.node_id",
    "recursion.qm31_inv.lhs_id",
    "recursion.qm31_inv.uses",
    "recursion.qm31_inv.in_circuit",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_qm31_inv_segment_mask",
    "recursion_qm31_inv_segment_circuit_id",
    "recursion_qm31_inv_segment_node_id",
    "recursion_qm31_inv_segment_lhs_id",
    "recursion_qm31_inv_segment_uses",
    "recursion_qm31_inv_binary_mask",
    "recursion_qm31_inv_binary_circuit_id",
    "recursion_qm31_inv_binary_node_id",
    "recursion_qm31_inv_binary_lhs_id",
    "recursion_qm31_inv_binary_uses",
    "recursion_qm31_inv_empty_mask",
    "recursion_qm31_inv_empty_circuit_id",
    "recursion_qm31_inv_empty_node_id",
    "recursion_qm31_inv_empty_lhs_id",
    "recursion_qm31_inv_empty_uses",
};

pub const PARAMETER_NAMES = [PROOF_KIND_PARAMETER_COUNT][]const u8{
    "recursion.qm31_inv.param.segment_active",
    "recursion.qm31_inv.param.binary_active",
    "recursion.qm31_inv.param.empty_active",
};

pub const Location = arithmetic.Location;

pub const MainColumns = struct {
    enabler: types.ValueId,
    a: [4]types.ValueId,
    inv: [4]types.ValueId,
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    lhs_id: types.ValueId,
    uses: types.ValueId,
    in_circuit: types.ValueId,

    pub fn declared(self: MainColumns) [DECLARED_COMMITTED_COLUMN_COUNT]types.ValueId {
        return self.a ++ self.inv ++ .{
            self.circuit_id,
            self.node_id,
            self.lhs_id,
            self.uses,
            self.in_circuit,
        };
    }

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.enabler} ++ self.declared();
    }
};

pub const ScheduleColumns = struct {
    mask: types.ValueId,
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    lhs_id: types.ValueId,
    uses: types.ValueId,

    pub fn physical(self: ScheduleColumns) [5]types.ValueId {
        return .{ self.mask, self.circuit_id, self.node_id, self.lhs_id, self.uses };
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
    input_consume: types.EffectId,
    output_emit: types.EffectId,
    output_weight: types.ValueId,

    pub fn ordered(self: Events) [RELATION_EVENT_COUNT]types.EffectId {
        return .{ self.input_consume, self.output_emit };
    }
};

pub const ValidationError = validate_mod.Error || wire.Error || error{
    InvalidQm31InvDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: ProofKindParameters,
    selected: ScheduleColumns,
    product: [4]types.ValueId,
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
            return error.InvalidQm31InvDefinition;
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
                return error.InvalidQm31InvDefinition;
            const constraint = self.arena.constraint(constraint_id) orelse
                return error.InvalidQm31InvDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidQm31InvDefinition;
            }
            const name = self.arena.name(constraint.name) orelse
                return error.InvalidQm31InvDefinition;
            if (!std.mem.eql(u8, name, CONSTRAINT_NAMES[index]))
                return error.InvalidQm31InvDefinition;
        }
        const first_product = binaryOp(&self.arena, self.roots[8], .sub) orelse
            return error.InvalidQm31InvDefinition;
        if (first_product.lhs != self.product[0] or
            first_product.rhs != self.main.enabler or
            !std.meta.eql(self.roots[9..12].*, self.product[1..4].*))
        {
            return error.InvalidQm31InvDefinition;
        }
        try validateEvents(self);
    }
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.qm31_inv.enabler_boolean",
    "recursion.qm31_inv.in_circuit_boolean",
    "recursion.qm31_inv.in_circuit_requires_enabler",
    "recursion.qm31_inv.schedule.mask",
    "recursion.qm31_inv.schedule.circuit_id",
    "recursion.qm31_inv.schedule.node_id",
    "recursion.qm31_inv.schedule.lhs_id",
    "recursion.qm31_inv.schedule.uses",
    "recursion.qm31_inv.product.0",
    "recursion.qm31_inv.product.1",
    "recursion.qm31_inv.product.2",
    "recursion.qm31_inv.product.3",
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
        value.* = try arena.input(
            name,
            if (index == 0 or index == PHYSICAL_MAIN_COLUMN_COUNT - 1)
                .selector
            else
                .felt,
            span,
        );
    }
    const main = MainColumns{
        .enabler = main_values[0],
        .a = main_values[1..5].*,
        .inv = main_values[5..9].*,
        .circuit_id = main_values[9],
        .node_id = main_values[10],
        .lhs_id = main_values[11],
        .uses = main_values[12],
        .in_circuit = main_values[13],
    };
    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(name, if (index % 5 == 0) .selector else .felt, span);
    }
    const preprocessed = PreprocessedColumns{
        .segment = scheduleFrom(preprocessed_values[0..5].*),
        .binary = scheduleFrom(preprocessed_values[5..10].*),
        .empty = scheduleFrom(preprocessed_values[10..15].*),
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
        5,
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
    roots[1] = try component_support.booleanRoot(&arena, main.in_circuit, one, span);
    roots[2] = try arena.mul(
        main.in_circuit,
        try arena.sub(one, main.enabler, span),
        span,
    );
    roots[3] = try arena.sub(main.in_circuit, selected.mask, span);
    const committed_schedule = [_]types.ValueId{
        main.circuit_id, main.node_id, main.lhs_id, main.uses,
    };
    const selected_schedule = [_]types.ValueId{
        selected.circuit_id, selected.node_id, selected.lhs_id, selected.uses,
    };
    for (committed_schedule, selected_schedule, 4..) |committed, scheduled, index| {
        roots[index] = try arena.mul(
            main.in_circuit,
            try arena.sub(committed, scheduled, span),
            span,
        );
    }
    const product = try arithmetic.productCoordinates(&arena, main.a, main.inv, span);
    roots[8] = try arena.sub(product[0], main.enabler, span);
    @memcpy(roots[9..12], product[1..4]);
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
    const output_weight = try arena.mul(main.uses, main.in_circuit, span);
    const event_ids = try wire.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .role = .consume,
            .tuple = .{
                .circuit_id = main.circuit_id,
                .node_id = main.lhs_id,
                .value = main.a,
            },
            .weight = main.in_circuit,
        },
        .{
            .role = .emit,
            .tuple = .{
                .circuit_id = main.circuit_id,
                .node_id = main.node_id,
                .value = main.inv,
            },
            .weight = output_weight,
        },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .selected = selected,
        .product = product,
        .roots = roots,
        .constraints = constraints,
        .events = .{
            .input_consume = event_ids[0],
            .output_emit = event_ids[1],
            .output_weight = output_weight,
        },
    };
}

const InputClass = enum { main, preprocessed, parameters };

fn scheduleFrom(values: [5]types.ValueId) ScheduleColumns {
    return .{
        .mask = values[0],
        .circuit_id = values[1],
        .node_id = values[2],
        .lhs_id = values[3],
        .uses = values[4],
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    class: InputClass,
) error{InvalidQm31InvDefinition}!void {
    if (values.len != names.len) return error.InvalidQm31InvDefinition;
    for (values, names, 0..) |value, name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidQm31InvDefinition;
        const node = arena.node(value) orelse return error.InvalidQm31InvDefinition;
        const expected_type: types.Type = switch (class) {
            .main => if (local_index == 0 or local_index == values.len - 1)
                .selector
            else
                .felt,
            .preprocessed => if (local_index % 5 == 0) .selector else .felt,
            .parameters => .selector,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidQm31InvDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidQm31InvDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidQm31InvDefinition;
        if (!std.mem.eql(u8, actual_name, name))
            return error.InvalidQm31InvDefinition;
    }
}

fn validateEvents(self: *const Definition) ValidationError!void {
    const ids = self.events.ordered();
    const expected_values = [RELATION_EVENT_COUNT][wire.ARITY]types.ValueId{
        (wire.Tuple{
            .circuit_id = self.main.circuit_id,
            .node_id = self.main.lhs_id,
            .value = self.main.a,
        }).values(),
        (wire.Tuple{
            .circuit_id = self.main.circuit_id,
            .node_id = self.main.node_id,
            .value = self.main.inv,
        }).values(),
    };
    const expected_roles = [_]relation.Role{ .consume, .emit };
    const expected_liveness = [_]types.ValueId{
        self.main.in_circuit,
        self.events.output_weight,
    };
    const schema = relation.get(.recursion_wire);
    for (ids, expected_values, expected_roles, expected_liveness, 0..) |
        id,
        values,
        role,
        liveness,
        index,
    | {
        if (types.idIndex(id) != index) return error.InvalidQm31InvDefinition;
        const effect = self.arena.effect(id) orelse
            return error.InvalidQm31InvDefinition;
        const binding = effect.binding orelse return error.InvalidQm31InvDefinition;
        const actual_values = self.arena.effectValues(id) orelse
            return error.InvalidQm31InvDefinition;
        if (effect.kind != .component_call or binding.schema != schema.id or
            binding.schema_version != schema.version or binding.role != role or
            effect.liveness != liveness or effect.access_ordinal != null or
            !std.mem.eql(types.ValueId, actual_values, &values))
        {
            return error.InvalidQm31InvDefinition;
        }
    }
    const weight = binaryOp(&self.arena, self.events.output_weight, .mul) orelse
        return error.InvalidQm31InvDefinition;
    if (!unorderedPairEquals(
        weight,
        self.main.uses,
        self.main.in_circuit,
    )) return error.InvalidQm31InvDefinition;
}

const BinaryTag = enum { sub, mul };

fn binaryOp(
    arena: *const ir.Arena,
    value: types.ValueId,
    tag: BinaryTag,
) ?@import("../../air/lang/expr.zig").Binary {
    const node = arena.node(value) orelse return null;
    return switch (tag) {
        .sub => switch (node.key.op) {
            .sub => |binary| binary,
            else => null,
        },
        .mul => switch (node.key.op) {
            .mul => |binary| binary,
            else => null,
        },
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
