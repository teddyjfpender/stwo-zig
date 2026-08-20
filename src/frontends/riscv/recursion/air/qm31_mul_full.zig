//! Complete typed logical AIR for Stark-V's recursion QM31 multiplication row.
//!
//! The reference declares eighteen committed fields; its generated component
//! prepends the built-in `enabler`, so the physical main trace has nineteen
//! columns. It also consumes eighteen verifier-owned preprocessing columns and
//! three proof-kind parameters. The compiler owns the generated enabler root,
//! the twelve authored roots, and all three `wire(6)` effects.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const program = @import("../../air/lang/program.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const arithmetic = @import("qm31_mul.zig");
const wire = @import("wire_relation.zig");

pub const DECLARED_COMMITTED_COLUMN_COUNT: usize = 18;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 19;
pub const PREPROCESSED_COLUMN_COUNT: usize = 18;
pub const PROOF_KIND_PARAMETER_COUNT: usize = 3;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT +
    PROOF_KIND_PARAMETER_COUNT;
pub const AUTHORED_CONSTRAINT_COUNT: usize = 12;
pub const DIRECT_CONSTRAINT_COUNT: usize = 13;
pub const RELATION_EVENT_COUNT: usize = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const SEMANTIC_DIGEST_HEX =
    "3426203437eb16d60d76a1d106eed98c414980f3540a04390c9acf14bb535ad1";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid full recursion QM31 multiplication semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "3ae15fc4e0e3e89b3606ea20d46bda482386e04ac2101984b68ec2835a8f3468";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.qm31_mul.enabler",
    "recursion.qm31_mul.a.0",
    "recursion.qm31_mul.a.1",
    "recursion.qm31_mul.a.2",
    "recursion.qm31_mul.a.3",
    "recursion.qm31_mul.b.0",
    "recursion.qm31_mul.b.1",
    "recursion.qm31_mul.b.2",
    "recursion.qm31_mul.b.3",
    "recursion.qm31_mul.c.0",
    "recursion.qm31_mul.c.1",
    "recursion.qm31_mul.c.2",
    "recursion.qm31_mul.c.3",
    "recursion.qm31_mul.circuit_id",
    "recursion.qm31_mul.node_id",
    "recursion.qm31_mul.lhs_id",
    "recursion.qm31_mul.rhs_id",
    "recursion.qm31_mul.uses",
    "recursion.qm31_mul.in_circuit",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_qm31_mul_segment_mask",
    "recursion_qm31_mul_segment_circuit_id",
    "recursion_qm31_mul_segment_node_id",
    "recursion_qm31_mul_segment_lhs_id",
    "recursion_qm31_mul_segment_rhs_id",
    "recursion_qm31_mul_segment_uses",
    "recursion_qm31_mul_binary_mask",
    "recursion_qm31_mul_binary_circuit_id",
    "recursion_qm31_mul_binary_node_id",
    "recursion_qm31_mul_binary_lhs_id",
    "recursion_qm31_mul_binary_rhs_id",
    "recursion_qm31_mul_binary_uses",
    "recursion_qm31_mul_empty_mask",
    "recursion_qm31_mul_empty_circuit_id",
    "recursion_qm31_mul_empty_node_id",
    "recursion_qm31_mul_empty_lhs_id",
    "recursion_qm31_mul_empty_rhs_id",
    "recursion_qm31_mul_empty_uses",
};

pub const PARAMETER_NAMES = [PROOF_KIND_PARAMETER_COUNT][]const u8{
    "recursion.qm31_mul.param.segment_active",
    "recursion.qm31_mul.param.binary_active",
    "recursion.qm31_mul.param.empty_active",
};

pub const Location = arithmetic.Location;

pub const MainColumns = struct {
    enabler: types.ValueId,
    a: [4]types.ValueId,
    b: [4]types.ValueId,
    c: [4]types.ValueId,
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    lhs_id: types.ValueId,
    rhs_id: types.ValueId,
    uses: types.ValueId,
    in_circuit: types.ValueId,

    pub fn declared(self: MainColumns) [DECLARED_COMMITTED_COLUMN_COUNT]types.ValueId {
        return self.a ++ self.b ++ self.c ++ .{
            self.circuit_id,
            self.node_id,
            self.lhs_id,
            self.rhs_id,
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
    rhs_id: types.ValueId,
    uses: types.ValueId,

    pub fn physical(self: ScheduleColumns) [6]types.ValueId {
        return .{
            self.mask,
            self.circuit_id,
            self.node_id,
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

pub const SelectedSchedule = ScheduleColumns;

pub const ValidationError = validate_mod.Error || wire.Error || error{
    InvalidFullQm31MulDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: ProofKindParameters,
    selected: SelectedSchedule,
    expected: [4]types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    events: wire.Events,

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
            return error.InvalidFullQm31MulDefinition;
        }

        const main_physical = self.main.physical();
        const preprocessed_physical = self.preprocessed.physical();
        const parameter_physical = self.parameters.physical();
        try validateInputs(
            &self.arena,
            &main_physical,
            &MAIN_COLUMN_NAMES,
            0,
            .main,
        );
        try validateInputs(
            &self.arena,
            &preprocessed_physical,
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            .preprocessed,
        );
        try validateInputs(
            &self.arena,
            &parameter_physical,
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            .parameters,
        );

        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            if (types.idIndex(constraint_id) != index)
                return error.InvalidFullQm31MulDefinition;
            const constraint = self.arena.constraint(constraint_id) orelse
                return error.InvalidFullQm31MulDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidFullQm31MulDefinition;
            }
            const actual_name = self.arena.name(constraint.name) orelse
                return error.InvalidFullQm31MulDefinition;
            if (!std.mem.eql(u8, actual_name, CONSTRAINT_NAMES[index]))
                return error.InvalidFullQm31MulDefinition;
        }

        const product_start = DIRECT_CONSTRAINT_COUNT - arithmetic.CONSTRAINT_COUNT;
        for (self.roots[product_start..], self.expected, self.main.c) |root, expected, committed| {
            const operands = binaryOp(&self.arena, root, .sub) orelse
                return error.InvalidFullQm31MulDefinition;
            if (operands.lhs != expected or operands.rhs != committed)
                return error.InvalidFullQm31MulDefinition;
        }
        try validateEvents(self);
    }
};

const InputClass = enum { main, preprocessed, parameters };

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.qm31_mul.enabler_boolean",
    "recursion.qm31_mul.in_circuit_boolean",
    "recursion.qm31_mul.in_circuit_requires_enabler",
    "recursion.qm31_mul.schedule.mask",
    "recursion.qm31_mul.schedule.circuit_id",
    "recursion.qm31_mul.schedule.node_id",
    "recursion.qm31_mul.schedule.lhs_id",
    "recursion.qm31_mul.schedule.rhs_id",
    "recursion.qm31_mul.schedule.uses",
    "recursion.qm31_mul.product.0",
    "recursion.qm31_mul.product.1",
    "recursion.qm31_mul.product.2",
    "recursion.qm31_mul.product.3",
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
        .b = main_values[5..9].*,
        .c = main_values[9..13].*,
        .circuit_id = main_values[13],
        .node_id = main_values[14],
        .lhs_id = main_values[15],
        .rhs_id = main_values[16],
        .uses = main_values[17],
        .in_circuit = main_values[18],
    };

    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(
            name,
            if (index % 6 == 0) .selector else .felt,
            span,
        );
    }
    const preprocessed = PreprocessedColumns{
        .segment = scheduleFrom(preprocessed_values[0..6].*),
        .binary = scheduleFrom(preprocessed_values[6..12].*),
        .empty = scheduleFrom(preprocessed_values[12..18].*),
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
    const selected = try selectSchedule(&arena, preprocessed, parameters, span);

    const one = try arena.constantField(1, span);
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var cursor: usize = 0;
    roots[cursor] = try booleanRoot(&arena, main.enabler, one, span);
    cursor += 1;
    roots[cursor] = try booleanRoot(&arena, main.in_circuit, one, span);
    cursor += 1;
    roots[cursor] = try arena.mul(
        main.in_circuit,
        try arena.sub(one, main.enabler, span),
        span,
    );
    cursor += 1;
    roots[cursor] = try arena.sub(main.in_circuit, selected.mask, span);
    cursor += 1;
    const main_schedule = [_]types.ValueId{
        main.circuit_id, main.node_id, main.lhs_id, main.rhs_id, main.uses,
    };
    const selected_schedule = [_]types.ValueId{
        selected.circuit_id, selected.node_id, selected.lhs_id,
        selected.rhs_id,     selected.uses,
    };
    for (main_schedule, selected_schedule) |committed, scheduled| {
        roots[cursor] = try arena.mul(
            main.in_circuit,
            try arena.sub(committed, scheduled, span),
            span,
        );
        cursor += 1;
    }
    const expected = try arithmetic.productCoordinates(&arena, main.a, main.b, span);
    for (expected, main.c) |expected_coordinate, committed_coordinate| {
        roots[cursor] = try arena.sub(expected_coordinate, committed_coordinate, span);
        cursor += 1;
    }
    std.debug.assert(cursor == DIRECT_CONSTRAINT_COUNT);
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name| {
        constraint.* = try arena.assertZero(
            name,
            root,
            null,
            program.ConstraintCategory.semantic,
            span,
        );
    }

    const events = try wire.appendMultiplication(
        &arena,
        .{ .circuit_id = main.circuit_id, .node_id = main.lhs_id, .value = main.a },
        .{ .circuit_id = main.circuit_id, .node_id = main.rhs_id, .value = main.b },
        .{ .circuit_id = main.circuit_id, .node_id = main.node_id, .value = main.c },
        main.uses,
        main.in_circuit,
        span,
    );
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .selected = selected,
        .expected = expected,
        .roots = roots,
        .constraints = constraints,
        .events = events,
    };
}

fn selectSchedule(
    arena: *ir.Arena,
    columns: PreprocessedColumns,
    parameters: ProofKindParameters,
    span: source.SourceSpan,
) !SelectedSchedule {
    const modes = [_]ScheduleColumns{ columns.segment, columns.binary, columns.empty };
    const active = parameters.physical();
    var selected: [6]types.ValueId = undefined;
    for (&selected, 0..) |*value, field| {
        const fields = [_]types.ValueId{
            modes[0].physical()[field],
            modes[1].physical()[field],
            modes[2].physical()[field],
        };
        value.* = try arena.add(
            try arena.add(
                try arena.mul(active[0], fields[0], span),
                try arena.mul(active[1], fields[1], span),
                span,
            ),
            try arena.mul(active[2], fields[2], span),
            span,
        );
    }
    return scheduleFrom(selected);
}

fn scheduleFrom(values: [6]types.ValueId) ScheduleColumns {
    return .{
        .mask = values[0],
        .circuit_id = values[1],
        .node_id = values[2],
        .lhs_id = values[3],
        .rhs_id = values[4],
        .uses = values[5],
    };
}

fn booleanRoot(
    arena: *ir.Arena,
    value: types.ValueId,
    one: types.ValueId,
    span: source.SourceSpan,
) !types.ValueId {
    return arena.mul(value, try arena.sub(one, value, span), span);
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    class: InputClass,
) error{InvalidFullQm31MulDefinition}!void {
    if (values.len != names.len) return error.InvalidFullQm31MulDefinition;
    for (values, names, 0..) |value, name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidFullQm31MulDefinition;
        const node = arena.node(value) orelse return error.InvalidFullQm31MulDefinition;
        const expected_type: types.Type = switch (class) {
            .main => if (local_index == 0 or local_index == values.len - 1)
                .selector
            else
                .felt,
            .preprocessed => if (local_index % 6 == 0) .selector else .felt,
            .parameters => .selector,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidFullQm31MulDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidFullQm31MulDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidFullQm31MulDefinition;
        if (!std.mem.eql(u8, actual_name, name))
            return error.InvalidFullQm31MulDefinition;
    }
}

fn validateEvents(self: *const Definition) ValidationError!void {
    const ids = self.events.ordered();
    const expected_values = [RELATION_EVENT_COUNT][wire.ARITY]types.ValueId{
        (wire.Tuple{ .circuit_id = self.main.circuit_id, .node_id = self.main.lhs_id, .value = self.main.a }).values(),
        (wire.Tuple{ .circuit_id = self.main.circuit_id, .node_id = self.main.rhs_id, .value = self.main.b }).values(),
        (wire.Tuple{ .circuit_id = self.main.circuit_id, .node_id = self.main.node_id, .value = self.main.c }).values(),
    };
    const expected_liveness = [_]types.ValueId{
        self.main.in_circuit,
        self.main.in_circuit,
        self.events.result_weight,
    };
    const schema = relation.get(.recursion_wire);
    for (ids, wire.EVENT_SPECS, expected_values, expected_liveness, 0..) |
        id,
        spec,
        values,
        liveness,
        index,
    | {
        if (types.idIndex(id) != index)
            return error.InvalidFullQm31MulDefinition;
        const effect = self.arena.effect(id) orelse
            return error.InvalidFullQm31MulDefinition;
        const binding = effect.binding orelse
            return error.InvalidFullQm31MulDefinition;
        const actual_values = self.arena.effectValues(id) orelse
            return error.InvalidFullQm31MulDefinition;
        if (effect.kind != .component_call or binding.schema != schema.id or
            binding.schema_version != schema.version or binding.role != spec.role or
            effect.liveness != liveness or effect.access_ordinal != null or
            !std.mem.eql(types.ValueId, actual_values, &values))
        {
            return error.InvalidFullQm31MulDefinition;
        }
    }
    const weight = binaryOp(&self.arena, self.events.result_weight, .mul) orelse
        return error.InvalidFullQm31MulDefinition;
    const uses_first = types.idIndex(self.main.uses) < types.idIndex(self.main.in_circuit);
    if (weight.lhs != (if (uses_first) self.main.uses else self.main.in_circuit) or
        weight.rhs != (if (uses_first) self.main.in_circuit else self.main.uses))
    {
        return error.InvalidFullQm31MulDefinition;
    }
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

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
