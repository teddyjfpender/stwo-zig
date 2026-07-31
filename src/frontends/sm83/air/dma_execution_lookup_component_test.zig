const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const prover_accumulation =
    @import("stwo_prover_engine").air.accumulation;
const prover_component =
    @import("stwo_prover_engine").air.component_prover;
const binding = @import("dma_binding.zig");
const execution = @import("execution.zig");
const lookup = @import("dma_execution_lookup.zig");
const subject = @import("dma_execution_lookup_component.zig");
const runner = @import("../runner/mod.zig");
const memory = runner.cartridge_memory;
const mapper = @import("../cartridge/mbc3.zig");

test "DMA execution lookup recurrence is exactly cubic and L plus one" {
    const constraint = lookup.pairConstraint(
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
    try std.testing.expectEqual(
        lookup.MAX_CONSTRAINT_DEGREE,
        constraint.degree,
    );

    const fixture = try Fixture.init();
    const component = fixture.component(.dma);
    try std.testing.expectEqual(@as(u32, 5), component.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(@as(usize, 1), component.nConstraints());
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(
        binding.N_MAIN_COLUMNS,
        bounds.items[1].len,
    );
}

test "DMA execution lookup sampled and domain paths reject mutations" {
    const fixture = try Fixture.init();
    const component = fixture.component(.dma);
    var main_storage =
        [_][1]QM31{.{QM31.zero()}} ** binding.N_MAIN_COLUMNS;
    for (&main_storage, fixture.row) |*column, value|
        column[0] = QM31.fromBase(value);
    var main: [binding.N_MAIN_COLUMNS][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values| column.* = values;
    var first_storage = [_][1]QM31{.{QM31.one()}};
    var first = [_][]QM31{&first_storage[0]};
    var interaction_storage =
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} ** 4;
    writeSecureSampled(&interaction_storage, fixture.claim);
    var interaction: [4][]QM31 = undefined;
    for (&interaction, &interaction_storage) |*column, *values|
        column.* = values;
    var constraints: [subject.N_MAX_CONSTRAINTS]QM31 = undefined;
    const count = try component.evaluateSampled(
        &first,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expect(constraints[0].isZero());

    main_storage[binding.MCYCLE_OFFSET][0] =
        QM31.fromBase(M31.one());
    _ = try component.evaluateSampled(
        &first,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!constraints[0].isZero());
    main_storage[binding.MCYCLE_OFFSET][0] = QM31.zero();

    const evaluation_log_size: u32 = 5;
    const evaluation_size: usize = 32;
    const first_index: usize = 0;
    var first_values = [_]M31{M31.zero()} ** evaluation_size;
    first_values[first_index] = M31.one();
    var main_values =
        [_][evaluation_size]M31{
            [_]M31{M31.zero()} ** evaluation_size,
        } ** binding.N_MAIN_COLUMNS;
    for (&main_values, fixture.row) |*values, value|
        values[first_index] = value;
    var interaction_values =
        [_][evaluation_size]M31{
            [_]M31{M31.zero()} ** evaluation_size,
        } ** 4;
    for (0..evaluation_size) |index|
        writeSecureDomain(&interaction_values, index, fixture.claim);
    var first_poly = [_]prover_component.Poly{.{
        .log_size = evaluation_log_size,
        .values = &first_values,
    }};
    var main_polys: [binding.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (&main_polys, &main_values) |*polynomial, *values|
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    var interaction_polys: [4]prover_component.Poly = undefined;
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
    main_values[binding.MCYCLE_OFFSET][first_index] = M31.one();
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    main_values[binding.MCYCLE_OFFSET][first_index] = M31.zero();
    main_values[0][first_index] = M31.zero();
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

test "DMA execution lookup execution owner binds all six cycle slots" {
    const fixture = try Fixture.init();
    const component = fixture.component(.execution);
    const machine = execution.columns(fixture.step.instruction, 0);
    var main_storage =
        [_][1]QM31{.{QM31.zero()}} ** execution.N_MAIN_COLUMNS;
    for (&main_storage, machine) |*column, value|
        column[0] = QM31.fromBase(value);
    var main: [execution.N_MAIN_COLUMNS][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values| column.* = values;
    var first_storage = [_][1]QM31{.{QM31.one()}};
    var first = [_][]QM31{&first_storage[0]};
    var interaction_storage =
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
        lookup.N_EXECUTION_INTERACTION_COLUMNS;
    for (fixture.claims.execution, 0..) |claim, index|
        writeSecureSampled(
            interaction_storage[4 * index ..][0..4],
            claim,
        );
    var interaction: [lookup.N_EXECUTION_INTERACTION_COLUMNS][]QM31 = undefined;
    for (&interaction, &interaction_storage) |*column, *values|
        column.* = values;
    var constraints: [subject.N_MAX_CONSTRAINTS]QM31 = undefined;
    const count = try component.evaluateSampled(
        &first,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expectEqual(
        lookup.N_EXECUTION_CONSTRAINTS,
        count,
    );
    for (constraints[0..count]) |constraint|
        try std.testing.expect(constraint.isZero());

    const address_offset = 2 * execution.N_STATE_COLUMNS;
    main_storage[address_offset][0] =
        QM31.fromBase(M31.fromCanonical(0xff81));
    _ = try component.evaluateSampled(
        &first,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!constraints[0].isZero());
}

const Fixture = struct {
    relations: lookup.Relations,
    claims: lookup.Claims,
    row: [binding.N_MAIN_COLUMNS]M31,
    claim: QM31,
    step: runner.CartridgeStepTrace,

    fn init() !Fixture {
        const relations = lookup.Relations.dummy();
        const step = accessStep();
        const transition = try @import("../runner/dma.zig").Transition.apply(
            .{},
            .tick,
        );
        const event = binding.EventRow{
            .mcycle = 0,
            .transition = transition,
            .provenance = .{ .execution_row = 0, .cycle = 0 },
        };
        const row = try binding.columns(event, &.{step});
        var lifted: [binding.N_MAIN_COLUMNS]QM31 = undefined;
        for (&lifted, row) |*destination, value|
            destination.* = QM31.fromBase(value);
        const pair = lookup.dmaPair(
            try lookup.dmaRow(QM31, &lifted),
            relations,
        );
        const claim = pair.n1.mul(try pair.d1.inv())
            .add(pair.n2.mul(try pair.d2.inv()));
        var execution_claims =
            [_]QM31{QM31.zero()} ** lookup.N_EXECUTION_SUMS;
        execution_claims[0] = claim.neg();
        return .{
            .relations = relations,
            .claims = .{
                .execution = execution_claims,
                .dma = claim,
                .execution_count = 1,
                .dma_count = 1,
            },
            .row = row,
            .claim = claim,
            .step = step,
        };
    }

    fn component(self: *const Fixture, kind: subject.Kind) subject.Component {
        return .{
            .kind = kind,
            .log_size = 4,
            .is_first_column = 0,
            .interaction_offset = 0,
            .relations = &self.relations,
            .claims = self.claims,
        };
    }
};

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

fn writeSecureSampled(
    storage: [][2]QM31,
    value: QM31,
) void {
    for (storage, value.toM31Array()) |*column, coordinate| {
        column[0] = QM31.fromBase(coordinate);
        column[1] = QM31.fromBase(coordinate);
    }
}

fn writeSecureDomain(
    storage: *[4][32]M31,
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

const Degree = struct {
    degree: u32,

    fn variable() Degree {
        return .{ .degree = 1 };
    }
    pub fn zero() Degree {
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
};
