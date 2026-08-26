const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const production = @import("../memory_commitment/poseidon2_air.zig");
const compat = @import("typed_poseidon2_compat.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "Poseidon2 compatibility binds every H-003 cut to its legacy path and value" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    var schedule = try compat.generate(std.testing.allocator);
    defer schedule.deinit(std.testing.allocator);
    var binding = try compat.bindPlan(
        std.testing.allocator,
        &fixture.arena,
        fixture.definition,
        fixture.spans,
        schedule,
        &plan,
    );
    defer binding.deinit(std.testing.allocator);

    try std.testing.expectEqualDeep(compat.Identity.canonical(), binding.identity);
    try std.testing.expectEqual(materializer.policy_version, binding.materializer_policy_version);
    try std.testing.expectEqual(plan.program_digest, binding.program_digest);
    try std.testing.expectEqual(fixture.gate, binding.gate);
    try std.testing.expectEqualDeep(plan.policy, binding.policy);
    try binding.validateAgainst(
        std.testing.allocator,
        &fixture.arena,
        fixture.definition,
        fixture.spans,
        &plan,
    );
    try std.testing.expectEqual(@as(usize, 426), binding.entries.len);
    for (binding.entries, 0..) |bound, ordinal| {
        const planned = plannedForValue(&plan, bound.value) orelse
            return error.UnmappedCompatibilityBinding;
        try std.testing.expectEqual(
            planned.source_value,
            plan.materializations[types.idIndex(bound.plan_materialization)].source_value,
        );
        try std.testing.expectEqualDeep(try compat.expected(ordinal), bound.materialization);
        try std.testing.expectEqual(planned.source_value, bound.value);
        try std.testing.expect(std.meta.eql(planned.source_span, bound.source_span));
        try std.testing.expectEqual(@as(materializer.Degree, 3), planned.constraint_degree);
    }

    try expectBindingValues(
        &fixture,
        binding.entries,
        .{ 1, 2 } ++ .{0} ** 14,
    );
    try expectBindingValues(
        &fixture,
        binding.entries,
        .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    );
    var prng = std.Random.DefaultPrng.init(0x4830_3034_2d76616c);
    const random = prng.random();
    for (0..16) |_| {
        var input: [poseidon.WIDTH]u32 = undefined;
        for (&input) |*value| value.* = random.int(u32) % m31.Modulus;
        try expectBindingValues(&fixture, binding.entries, input);
    }
}

test "Poseidon2 typed compatibility binding rejects policy order source and output drift" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    var schedule = try compat.generate(std.testing.allocator);
    defer schedule.deinit(std.testing.allocator);

    const original_first = schedule.materializations[0];
    schedule.materializations[0].column += 1;
    try std.testing.expectError(
        error.ColumnOutOfRange,
        compat.bindPlan(
            std.testing.allocator,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &plan,
        ),
    );
    schedule.materializations[0] = original_first;
    schedule.materializations[0].ordinal += 1;
    try std.testing.expectError(
        error.OrdinalMismatch,
        compat.bindPlan(
            std.testing.allocator,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &plan,
        ),
    );
    schedule.materializations[0] = original_first;
    schedule.materializations[0].phase = .output;
    try std.testing.expectError(
        error.PhaseMismatch,
        compat.bindPlan(
            std.testing.allocator,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &plan,
        ),
    );
    schedule.materializations[0] = original_first;
    schedule.materializations[0].role = .output;
    try std.testing.expectError(
        error.RoleMismatch,
        compat.bindPlan(
            std.testing.allocator,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &plan,
        ),
    );
    schedule.materializations[0] = original_first;
    const original_policy = plan.policy;
    plan.policy.maximum_constraint_degree += 1;
    try std.testing.expectError(
        error.MaterializerPolicyMismatch,
        compat.bindPlan(
            std.testing.allocator,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &plan,
        ),
    );
    plan.policy = original_policy;
    const original_gate = plan.gate;
    plan.gate = null;
    try std.testing.expectError(
        error.MissingEnabler,
        compat.bindPlan(
            std.testing.allocator,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &plan,
        ),
    );
    plan.gate = original_gate;

    var invalid_definition = fixture.definition;
    invalid_definition.function = try types.idFromIndex(types.FunctionId, 99_999);
    try std.testing.expectError(
        error.CanonicalDefinitionMismatch,
        compat.bindPlan(
            std.testing.allocator,
            &fixture.arena,
            invalid_definition,
            fixture.spans,
            schedule,
            &plan,
        ),
    );

    var valid_binding = try compat.bindPlan(
        std.testing.allocator,
        &fixture.arena,
        fixture.definition,
        fixture.spans,
        schedule,
        &plan,
    );
    defer valid_binding.deinit(std.testing.allocator);
    try valid_binding.validateAgainst(
        std.testing.allocator,
        &fixture.arena,
        fixture.definition,
        fixture.spans,
        &plan,
    );
    const saved_plan_id = valid_binding.entries[0].plan_materialization;
    valid_binding.entries[0].plan_materialization = valid_binding.entries[1].plan_materialization;
    try std.testing.expectError(
        error.PlanBindingMismatch,
        valid_binding.validateAgainst(
            std.testing.allocator,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            &plan,
        ),
    );
    valid_binding.entries[0].plan_materialization = saved_plan_id;
    std.mem.swap(
        materializer.MaterializationId,
        &valid_binding.entries[0].plan_materialization,
        &valid_binding.entries[1].plan_materialization,
    );
    std.mem.swap(
        types.ValueId,
        &valid_binding.entries[0].value,
        &valid_binding.entries[1].value,
    );
    std.mem.swap(
        source.SourceSpan,
        &valid_binding.entries[0].source_span,
        &valid_binding.entries[1].source_span,
    );
    try std.testing.expectError(
        error.PlanBindingMismatch,
        valid_binding.validateAgainst(
            std.testing.allocator,
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            &plan,
        ),
    );
    std.mem.swap(
        materializer.MaterializationId,
        &valid_binding.entries[0].plan_materialization,
        &valid_binding.entries[1].plan_materialization,
    );
    std.mem.swap(
        types.ValueId,
        &valid_binding.entries[0].value,
        &valid_binding.entries[1].value,
    );
    std.mem.swap(
        source.SourceSpan,
        &valid_binding.entries[0].source_span,
        &valid_binding.entries[1].source_span,
    );
    var values: [compat.N_MATERIALIZATIONS]types.ValueId = undefined;
    for (&values, valid_binding.entries) |*value, item| value.* = item.value;
    std.mem.swap(types.ValueId, &values[0], &values[1]);
    try std.testing.expectError(
        error.DependencyMismatch,
        compat.validateInOrder(
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &values,
        ),
    );
    std.mem.swap(types.ValueId, &values[0], &values[1]);
    values[0] = valid_binding.entries[2].value;
    try std.testing.expectError(
        error.DependencyMismatch,
        compat.validateInOrder(
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &values,
        ),
    );
    values[0] = valid_binding.entries[0].value;
    values[32] = valid_binding.entries[35].value;
    try std.testing.expectError(
        error.SemanticShapeMismatch,
        compat.validateInOrder(
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &values,
        ),
    );
    values[32] = valid_binding.entries[32].value;
    values[0] = valid_binding.entries[32].value;
    try std.testing.expectError(
        error.SourceSpanMismatch,
        compat.validateInOrder(
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &values,
        ),
    );
    values[0] = valid_binding.entries[0].value;
    values[425] = values[424];
    try std.testing.expectError(
        error.OutputMismatch,
        compat.validateInOrder(
            &fixture.arena,
            fixture.definition,
            fixture.spans,
            schedule,
            &values,
        ),
    );
}

test "Poseidon2 compatibility plan binding releases every partial allocation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    var schedule = try compat.generate(std.testing.allocator);
    defer schedule.deinit(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        bindingAllocationFailureCase,
        .{ &fixture, schedule, &plan },
    );
}

test "Poseidon2 compatibility slots bind the current production constraints" {
    var schedule = try compat.generate(std.testing.allocator);
    defer schedule.deinit(std.testing.allocator);
    const calls = [_]production.Call{
        production.Call.narrow(0, 0),
        production.Call.narrow(1, 2),
        production.Call.narrow(11, 22),
        production.Call.narrow(2_147_483_646, 1_073_741_823),
        .{ .input = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } },
    };
    for (calls) |call| {
        const honest = production.fill(call);
        const honest_constraints = production.evaluate(secure(honest));
        try expectAllZero(&honest_constraints);
        for (schedule.materializations) |entry| {
            var mutated = honest;
            mutated[entry.column] = mutated[entry.column].add(M31.one());
            const constraints = production.evaluate(secure(mutated));
            if (constraints[entry.constraint].isZero()) {
                std.debug.print(
                    "legacy Poseidon2 temporary {d}, column {d}, constraint {d}\n",
                    .{ entry.ordinal, entry.column, entry.constraint },
                );
                return error.UnboundCompatibilitySlot;
            }
        }
    }

    const honest = production.fill(production.Call.narrow(31, 41));
    var non_boolean_wide = honest;
    non_boolean_wide[compat.WIDE_COLUMN] = M31.fromU64(2);
    try std.testing.expect(!production.evaluate(secure(non_boolean_wide))[
        production.N_PERMUTATION_CONSTRAINTS
    ].isZero());
    var non_boolean_io = honest;
    non_boolean_io[compat.IO_COLUMN] = M31.fromU64(2);
    try std.testing.expect(!production.evaluate(secure(non_boolean_io))[
        production.N_PERMUTATION_CONSTRAINTS + 1
    ].isZero());
    var conflicting_modes = honest;
    conflicting_modes[compat.WIDE_COLUMN] = M31.one();
    conflicting_modes[compat.IO_COLUMN] = M31.one();
    try std.testing.expect(!production.evaluate(secure(conflicting_modes))[
        production.N_CONSTRAINTS - 1
    ].isZero());
}

test "Poseidon2 compatibility owned outputs survive every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var schedule = try compat.generate(allocator);
    defer schedule.deinit(allocator);
    try schedule.validate();
    var rendered: std.ArrayList(u8) = .empty;
    defer rendered.deinit(allocator);
    try compat.writeSchedule(rendered.writer(allocator), schedule);
}

fn bindingAllocationFailureCase(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
    schedule: compat.OwnedSchedule,
    plan: *const materializer.Plan,
) !void {
    var binding = try compat.bindPlan(
        allocator,
        &fixture.arena,
        fixture.definition,
        fixture.spans,
        schedule,
        plan,
    );
    defer binding.deinit(allocator);
}

fn secure(row: [production.N_MAIN_COLUMNS]M31) [production.N_MAIN_COLUMNS]QM31 {
    var result: [production.N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, row) |*destination, value| {
        destination.* = QM31.fromBase(value);
    }
    return result;
}

fn expectAllZero(values: []const QM31) !void {
    for (values) |value| try std.testing.expect(value.isZero());
}

fn expectBindingValues(
    fixture: *const Fixture,
    bindings: []const compat.Binding,
    input: [poseidon.WIDTH]u32,
) !void {
    const values = try evaluateNodes(std.testing.allocator, fixture, input);
    defer std.testing.allocator.free(values);
    const row = production.fill(.{ .input = input });
    for (bindings) |binding| {
        try std.testing.expectEqual(
            row[binding.materialization.column],
            values[types.idIndex(binding.value)],
        );
    }
}

fn evaluateNodes(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
    input: [poseidon.WIDTH]u32,
) ![]M31 {
    const values = try allocator.alloc(M31, fixture.arena.nodeCount());
    errdefer allocator.free(values);
    const input_ids = poseidon.values(fixture.definition.inputs);
    for (fixture.arena.nodesView(), 0..) |node, index| {
        const value_id: types.ValueId = @enumFromInt(index);
        values[index] = switch (node.key.op) {
            .constant => |constant| switch (constant) {
                .field => |value| M31.fromCanonical(value),
                .unsigned => |value| M31.fromU64(value),
            },
            .input => if (value_id == fixture.gate)
                M31.one()
            else
                M31.fromCanonical(input[
                    poseidonInputIndex(&input_ids, value_id) orelse
                        return error.UnknownPoseidonInput
                ]),
            .add => |binary| values[types.idIndex(binary.lhs)].add(
                values[types.idIndex(binary.rhs)],
            ),
            .sub => |binary| values[types.idIndex(binary.lhs)].sub(
                values[types.idIndex(binary.rhs)],
            ),
            .mul => |binary| values[types.idIndex(binary.lhs)].mul(
                values[types.idIndex(binary.rhs)],
            ),
            .neg => |value| values[types.idIndex(value)].neg(),
            .select => |selection| if (!values[
                types.idIndex(selection.selector)
            ].isZero())
                values[types.idIndex(selection.when_true)]
            else
                values[types.idIndex(selection.when_false)],
            .hint_output, .call_output, .machine_derived => return error.UnsupportedPoseidonNode,
        };
    }
    return values;
}

fn poseidonInputIndex(
    inputs: *const [poseidon.WIDTH]types.ValueId,
    target: types.ValueId,
) ?usize {
    for (inputs, 0..) |input, index| if (input == target) return index;
    return null;
}

fn plannedForValue(
    plan: *const materializer.Plan,
    value: types.ValueId,
) ?*const materializer.Materialization {
    for (plan.materializations, 0..) |item, index| {
        if (item.source_value == value) return &plan.materializations[index];
    }
    return null;
}

const Fixture = struct {
    arena: ir.Arena,
    gate: types.ValueId,
    spans: poseidon.DefinitionSpans,
    definition: poseidon.Definition,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const source_id = try arena.addSource("air/components/poseidon2_m31.typed.zig");
        const gate = try arena.input(
            compat.ENABLER_NAME,
            .selector,
            try spanAt(source_id, 1),
        );
        const spans = try distinctSpans(source_id);
        const definition = try poseidon.define(&arena, spans);
        return .{ .arena = arena, .gate = gate, .spans = spans, .definition = definition };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn makePlan(self: *const Fixture, allocator: std.mem.Allocator) !materializer.Plan {
        const roots = poseidon.values(self.definition.outputs);
        return materializer.plan(allocator, &self.arena, .{
            .roots = &roots,
            .gate = self.gate,
        });
    }
};

fn distinctSpans(source_id: types.SourceId) !poseidon.DefinitionSpans {
    var next_line: u32 = 2;
    const declaration = try spanAt(source_id, next_line);
    next_line += 1;
    var inputs: [poseidon.WIDTH]source.SourceSpan = undefined;
    for (&inputs) |*span| {
        span.* = try spanAt(source_id, next_line);
        next_line += 1;
    }
    const initial_linear = try spanAt(source_id, next_line);
    next_line += 1;
    var external: [poseidon.N_EXTERNAL_ROUNDS]poseidon.ExternalRoundSpans = undefined;
    for (&external) |*round| {
        round.* = .{
            .constants = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    var internal: [poseidon.N_INTERNAL_ROUNDS]poseidon.InternalRoundSpans = undefined;
    for (&internal) |*round| {
        round.* = .{
            .constant = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    return .{
        .declaration = declaration,
        .inputs = inputs,
        .body = .{
            .initial_linear = initial_linear,
            .external_rounds = external,
            .internal_rounds = internal,
        },
    };
}

fn spanAt(source_id: types.SourceId, line: u32) !source.SourceSpan {
    return source.SourceSpan.init(
        source_id,
        .{ .byte_offset = line * 8, .line = line, .column = 1 },
        .{ .byte_offset = line * 8 + 1, .line = line, .column = 2 },
    );
}
