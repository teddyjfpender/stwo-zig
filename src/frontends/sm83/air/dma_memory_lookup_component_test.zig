const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const prover_accumulation =
    @import("stwo_prover_engine").air.accumulation;
const prover_component =
    @import("stwo_prover_engine").air.component_prover;
const binding = @import("dma_binding.zig");
const dma_component = @import("dma_component.zig");
const dma_air = @import("dma.zig");
const lookup = @import("dma_memory_lookup.zig");
const subject = @import("dma_memory_lookup_component.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const runner = @import("../runner/mod.zig");
const dma = @import("../runner/dma.zig");
const memory = runner.cartridge_memory;
const mapper = @import("../cartridge/mbc3.zig");

test "DMA memory lookup component is exactly cubic and L plus one" {
    const binding_variables =
        [_]Degree{Degree.variable()} ** binding.N_MAIN_COLUMNS;
    const predecessor_variables =
        [_]Degree{Degree.variable()} ** lookup.N_MAIN_COLUMNS;
    const dma_row = try lookup.dmaRow(Degree, &binding_variables);
    const predecessor =
        try lookup.Row(Degree).fromColumns(&predecessor_variables);
    const semantic = lookup.evaluate(Degree, dma_row, predecessor);
    var maximum: u32 = 0;
    for (semantic.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    const recurrence = subject.recurrenceConstraint(
        Degree,
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.zero(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
    );
    maximum = @max(maximum, recurrence.degree);
    try std.testing.expectEqual(subject.MAX_CONSTRAINT_DEGREE, maximum);

    const fixture = try Fixture.init();
    const component = fixture.component();
    try std.testing.expectEqual(@as(u32, 5), component.maxConstraintLogDegreeBound());
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(
        binding.N_MAIN_COLUMNS + lookup.N_MAIN_COLUMNS,
        bounds.items[1].len,
    );
}

test "DMA memory lookup sampled and domain reject substitution and vacuity" {
    const fixture = try Fixture.init();
    const component = fixture.component();
    var main_storage =
        [_][1]QM31{.{QM31.zero()}} **
        (binding.N_MAIN_COLUMNS + lookup.N_MAIN_COLUMNS);
    for (
        main_storage[0..binding.N_MAIN_COLUMNS],
        fixture.binding_row,
    ) |*column, value| column[0] = QM31.fromBase(value);
    for (
        main_storage[binding.N_MAIN_COLUMNS..],
        fixture.predecessor_row,
    ) |*column, value| column[0] = QM31.fromBase(value);
    var main: [main_storage.len][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values| column.* = values;
    var first_storage = [_][1]QM31{.{QM31.one()}};
    var first = [_][]QM31{&first_storage[0]};
    var interaction_storage =
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} ** 8;
    for (fixture.claims, 0..) |claim, index|
        writeSecureSampled(
            interaction_storage[4 * index ..][0..4],
            claim,
        );
    var interaction: [8][]QM31 = undefined;
    for (&interaction, &interaction_storage) |*column, *values|
        column.* = values;
    var constraints = try component.evaluateSampled(
        &first,
        &main,
        &interaction,
    );
    for (constraints) |constraint|
        try std.testing.expect(constraint.isZero());

    main_storage[
        binding.N_MAIN_COLUMNS + lookup.SOURCE_PREVIOUS_CLOCK_OFFSET
    ][0] = QM31.one();
    constraints = try component.evaluateSampled(
        &first,
        &main,
        &interaction,
    );
    try std.testing.expect(!allZero(constraints));
    main_storage[
        binding.N_MAIN_COLUMNS + lookup.SOURCE_PREVIOUS_CLOCK_OFFSET
    ][0] = QM31.zero();

    const evaluation_log_size: u32 = 5;
    const evaluation_size: usize = 32;
    var first_values = [_]M31{M31.zero()} ** evaluation_size;
    first_values[0] = M31.one();
    var main_values =
        [_][evaluation_size]M31{
            [_]M31{M31.zero()} ** evaluation_size,
        } ** main_storage.len;
    for (&main_values, fixture.binding_row ++ fixture.predecessor_row) |
        *values,
        value,
    | values[0] = value;
    var interaction_values =
        [_][evaluation_size]M31{
            [_]M31{M31.zero()} ** evaluation_size,
        } ** 8;
    for (0..evaluation_size) |index|
        for (fixture.claims, 0..) |claim, claim_index|
            writeSecureDomain(
                interaction_values[4 * claim_index ..][0..4],
                index,
                claim,
            );
    var first_poly = [_]prover_component.Poly{.{
        .log_size = evaluation_log_size,
        .values = &first_values,
    }};
    var main_polys: [main_values.len]prover_component.Poly = undefined;
    for (&main_polys, &main_values) |*polynomial, *values|
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    var interaction_polys: [8]prover_component.Poly = undefined;
    for (&interaction_polys, &interaction_values) |*polynomial, *values|
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    var trees = [_][]const prover_component.Poly{
        &first_poly,
        &main_polys,
        &interaction_polys,
    };
    const trace = prover_component.Trace{
        .polys = core.pcs.TreeVec(
            []const prover_component.Poly,
        ).initOwned(&trees),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );
    main_values[
        binding.N_MAIN_COLUMNS + lookup.DESTINATION_PREVIOUS_VALUE_OFFSET
    ][0] = flip(main_values[
        binding.N_MAIN_COLUMNS + lookup.DESTINATION_PREVIOUS_VALUE_OFFSET
    ][0]);
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    main_values[
        binding.N_MAIN_COLUMNS + lookup.DESTINATION_PREVIOUS_VALUE_OFFSET
    ][0] = flip(main_values[
        binding.N_MAIN_COLUMNS + lookup.DESTINATION_PREVIOUS_VALUE_OFFSET
    ][0]);
    main_values[0][0] = M31.zero();
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

const Fixture = struct {
    relation: memory_lookup.Relation,
    claims: [2]QM31,
    binding_row: [binding.N_MAIN_COLUMNS]M31,
    predecessor_row: [lookup.N_MAIN_COLUMNS]M31,

    fn init() !Fixture {
        const relation = memory_lookup.Relation.dummy();
        const transition = try dma.Transition.apply(.{
            .clock = 0,
            .page = 0xc0,
            .phase = .transfer,
        }, .{ .transfer = 0x42 });
        const event = binding.EventRow{
            .mcycle = 0,
            .transition = transition,
            .provenance = .{ .execution_row = 0, .cycle = 0 },
        };
        const step = accessStep();
        const binding_row = try binding.columns(event, &.{step});
        const accesses = try lookup.accessesForEvent(event, .{
            .source = .{ .value = 0x42 },
            .destination = .{ .value = 0x99 },
        });
        const predecessor_row = try lookup.columnsForAccesses(accesses);
        const claims = .{
            try lookup.accumulate(
                QM31.zero(),
                try accessPair(accesses.source, relation),
            ),
            try lookup.accumulate(
                QM31.zero(),
                try accessPair(accesses.destination, relation),
            ),
        };
        return .{
            .relation = relation,
            .claims = claims,
            .binding_row = binding_row,
            .predecessor_row = predecessor_row,
        };
    }

    fn component(self: *const Fixture) subject.Component {
        return .{
            .log_size = 4,
            .is_first_column = 0,
            .binding_offset = 0,
            .predecessor_offset = binding.N_MAIN_COLUMNS,
            .interaction_offset = 0,
            .relation = &self.relation,
            .claims = self.claims,
        };
    }
};

fn accessPair(
    access: memory_lookup.Access,
    relation: memory_lookup.Relation,
) !memory_lookup.RowPair {
    if (!access.enabled) unreachable;
    return .{
        .n1 = QM31.one().neg(),
        .d1 = relation.combine(
            q(access.address),
            q(access.previous_clock),
            q(access.previous_value),
        ),
        .n2 = QM31.one(),
        .d2 = relation.combine(
            q(access.address),
            q(access.clock),
            q(access.next_value),
        ),
    };
}

fn accessStep() runner.CartridgeStepTrace {
    var result: runner.CartridgeStepTrace = undefined;
    result.instruction.cycle_count = 1;
    result.instruction.cycles[0] = .{
        .address = 0xff80,
        .value = 0,
        .action = .read,
    };
    result.accesses = [_]?memory.Access{null} ** 6;
    result.accesses[0] = .{
        .logical_address = 0xff80,
        .action = .read,
        .region = .system,
        .physical_offset = null,
        .mapper_before = mapper.State{},
        .mapper_after = mapper.State{},
        .value = 0,
    };
    return result;
}

fn writeSecureSampled(storage: [][2]QM31, value: QM31) void {
    for (storage, value.toM31Array()) |*column, coordinate| {
        column[0] = QM31.fromBase(coordinate);
        column[1] = QM31.fromBase(coordinate);
    }
}

fn writeSecureDomain(
    storage: [][32]M31,
    index: usize,
    value: QM31,
) void {
    for (storage, value.toM31Array()) |*column, coordinate|
        column[index] = coordinate;
}

fn expectDomain(
    component: *const subject.Component,
    trace: *const prover_component.Trace,
    challenge: QM31,
    evaluation_log_size: u32,
    expected: bool,
) !void {
    var accumulator =
        try prover_accumulation.DomainEvaluationAccumulator.init(
            std.testing.allocator,
            challenge,
            evaluation_log_size,
            component.nConstraints(),
        );
    defer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(
        trace,
        &accumulator,
    );
    var result = try accumulator.finalize();
    defer result.deinit(std.testing.allocator);
    var zero = true;
    for (0..result.len()) |index|
        zero = zero and result.at(index).isZero();
    try std.testing.expectEqual(expected, zero);
}

fn allZero(values: anytype) bool {
    for (values) |value| if (!value.isZero()) return false;
    return true;
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}

fn flip(value: M31) M31 {
    return if (value.isZero()) M31.one() else M31.zero();
}

const Degree = struct {
    degree: u32,

    fn variable() Degree {
        return .{ .degree = 1 };
    }
    pub fn zero() Degree {
        return .{ .degree = 0 };
    }
    pub fn one() Degree {
        return .{ .degree = 0 };
    }
    pub fn fromBase(_: M31) Degree {
        return .{ .degree = 0 };
    }
    pub fn add(left: Degree, right: Degree) Degree {
        return .{ .degree = @max(left.degree, right.degree) };
    }
    pub fn sub(left: Degree, right: Degree) Degree {
        return left.add(right);
    }
    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .degree = left.degree + right.degree };
    }
    pub fn isZero(_: Degree) bool {
        return false;
    }
};
