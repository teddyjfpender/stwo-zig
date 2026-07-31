const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const TreeVec = @import("stwo_core").pcs.TreeVec;
const circle = @import("stwo_core").circle;
const utils = @import("stwo_core").utils;
const prover_air_accumulation =
    @import("stwo_prover_engine").air.accumulation;
const prover_component =
    @import("stwo_prover_engine").air.component_prover;
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");
const cartridge_access = @import("cartridge_access.zig");
const cartridge_access_component =
    @import("cartridge_access_component.zig");
const execution = @import("execution.zig");
const lookup = @import("cartridge_memory_lookup.zig");
const subject = @import("cartridge_memory_lookup_component.zig");

// Keep the synthetic quotient domain aligned with the exact cubic bound.
const EVALUATION_LOG_SIZE: u32 = 5;
const EVALUATION_SIZE: usize = 1 << EVALUATION_LOG_SIZE;
const MAIN_COLUMNS: usize = execution.N_MAIN_COLUMNS +
    cartridge_access_component.N_MAIN_COLUMNS +
    lookup.N_MAIN_COLUMNS;

test "cartridge memory lookup component pins ownership and exact degree" {
    const relation = lookup.Relation.dummy();
    const execution_component = subject.Component{
        .kind = .execution,
        .log_size = 4,
        .is_first_column = 0,
        .execution_offset = 0,
        .access_offset = execution.N_MAIN_COLUMNS,
        .main_offset = execution.N_MAIN_COLUMNS +
            cartridge_access_component.N_MAIN_COLUMNS,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = .{QM31.zero()} ** lookup.N_EXECUTION_SUMS,
    };
    const boundary_component = subject.Component{
        .kind = .boundary,
        .log_size = lookup.BOUNDARY_LOG_SIZE,
        .is_first_column = 0,
        .enabled_column = 1,
        .address_column = 2,
        .initial_value_column = 3,
        .final_value_column = 4,
        .main_offset = MAIN_COLUMNS,
        .interaction_offset = lookup.N_EXECUTION_COLUMNS,
        .relation = &relation,
        .claims = .{QM31.zero()} ** lookup.N_EXECUTION_SUMS,
    };
    try std.testing.expectEqual(
        lookup.N_CONSTRAINTS + lookup.N_EXECUTION_SUMS,
        execution_component.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(usize, 6),
        boundary_component.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        execution_component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expectEqual(
        lookup.BOUNDARY_LOG_SIZE + 1,
        boundary_component.maxConstraintLogDegreeBound(),
    );
    _ = execution_component.asVerifierComponent();
    _ = boundary_component.asProverComponent();

    var execution_bounds = try execution_component.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer execution_bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(
        @as(usize, 1),
        execution_bounds.items[0].len,
    );
    try std.testing.expectEqual(
        lookup.N_MAIN_COLUMNS,
        execution_bounds.items[1].len,
    );
    try std.testing.expectEqual(
        lookup.N_EXECUTION_COLUMNS,
        execution_bounds.items[2].len,
    );

    var boundary_bounds = try boundary_component.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer boundary_bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), boundary_bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 1), boundary_bounds.items[1].len);
    try std.testing.expectEqual(
        lookup.N_BOUNDARY_COLUMNS,
        boundary_bounds.items[2].len,
    );
    for (boundary_bounds.items[0]) |log_size|
        try std.testing.expectEqual(lookup.BOUNDARY_LOG_SIZE, log_size);

    var execution_mask = try execution_component.maskPoints(
        std.testing.allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        execution_component.maxConstraintLogDegreeBound(),
    );
    defer execution_mask.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), execution_mask.items[0].len);
    try std.testing.expectEqual(
        lookup.N_MAIN_COLUMNS,
        execution_mask.items[1].len,
    );
    try std.testing.expectEqual(
        lookup.N_EXECUTION_COLUMNS,
        execution_mask.items[2].len,
    );
    for (execution_mask.items[2]) |points|
        try std.testing.expectEqual(@as(usize, 2), points.len);

    var boundary_mask = try boundary_component.maskPoints(
        std.testing.allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        boundary_component.maxConstraintLogDegreeBound(),
    );
    defer boundary_mask.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), boundary_mask.items[0].len);
    try std.testing.expectEqual(@as(usize, 1), boundary_mask.items[1].len);
    try std.testing.expectEqual(
        lookup.N_BOUNDARY_COLUMNS,
        boundary_mask.items[2].len,
    );

    const invalid = subject.Component{
        .kind = .boundary,
        .log_size = lookup.BOUNDARY_LOG_SIZE - 1,
        .is_first_column = 0,
        .enabled_column = 1,
        .address_column = 2,
        .initial_value_column = 3,
        .final_value_column = 4,
        .main_offset = 0,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = .{QM31.zero()} ** lookup.N_EXECUTION_SUMS,
    };
    try std.testing.expectError(
        error.InvalidBoundaryLogSize,
        invalid.preprocessedColumnIndices(std.testing.allocator),
    );
}

test "execution domain rejects key value clock and activity mutations" {
    const relation = lookup.Relation.dummy();
    var component = subject.Component{
        .kind = .execution,
        .log_size = 4,
        .is_first_column = 0,
        .execution_offset = 0,
        .access_offset = execution.N_MAIN_COLUMNS,
        .main_offset = execution.N_MAIN_COLUMNS +
            cartridge_access_component.N_MAIN_COLUMNS,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = .{QM31.zero()} ** lookup.N_EXECUTION_SUMS,
    };
    const trace_row = try syntheticRead();
    const execution_row = execution.columns(trace_row.instruction, 0);
    const access_row = try cartridge_access_component.columns(trace_row);
    var lookup_row = [_]M31{M31.zero()} ** lookup.N_MAIN_COLUMNS;
    lookup_row[lookup.PROJECTED_VALUE_OFFSET] =
        M31.fromCanonical(0x7e);
    const memory_offset = lookup.N_ACCESS_COLUMNS;
    lookup_row[memory_offset + lookup.PREVIOUS_VALUE_OFFSET] =
        M31.fromCanonical(0x42);
    lookup_row[memory_offset + lookup.NEXT_VALUE_OFFSET] =
        M31.fromCanonical(0x42);
    const access_clock = try lookup.memory_clock.cpuClock(0, 1);
    const difference = access_clock - 1;
    for (0..lookup.N_DIFF_BITS) |bit|
        lookup_row[
            memory_offset + lookup.DIFFERENCE_BITS_OFFSET + bit
        ] = M31.fromCanonical(difference >> @intCast(bit) & 1);
    lookup_row[memory_offset + lookup.PROJECTED_ENABLED_OFFSET] = M31.one();
    lookup_row[memory_offset + lookup.PROJECTED_READ_OFFSET] = M31.one();
    lookup_row[memory_offset + lookup.PROJECTED_KEY_OFFSET] =
        M31.fromCanonical(0x8000);
    lookup_row[memory_offset + lookup.PROJECTED_VALUE_OFFSET] =
        M31.fromCanonical(0x42);
    const direct = try lookup.evaluate(
        execution_row,
        lookup.accessColumns(
            try cartridge_access.ValidatedStep.init(trace_row),
        ),
        lookup_row,
    );
    try std.testing.expect(direct.allZero());

    var first_values = [_]M31{M31.zero()} ** EVALUATION_SIZE;
    var preprocessed = [_]prover_component.Poly{.{
        .log_size = EVALUATION_LOG_SIZE,
        .values = &first_values,
    }};
    var main_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** MAIN_COLUMNS;
    fillConstants(
        main_values[0..execution.N_MAIN_COLUMNS],
        &execution_row,
    );
    fillConstants(
        main_values[execution.N_MAIN_COLUMNS..][0..cartridge_access_component.N_MAIN_COLUMNS],
        &access_row,
    );
    fillConstants(
        main_values[execution.N_MAIN_COLUMNS +
            cartridge_access_component.N_MAIN_COLUMNS ..],
        &lookup_row,
    );
    var main: [MAIN_COLUMNS]prover_component.Poly = undefined;
    for (&main, &main_values) |*polynomial, *values|
        polynomial.* = .{
            .log_size = EVALUATION_LOG_SIZE,
            .values = values,
        };

    var interaction_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** lookup.N_EXECUTION_COLUMNS;
    const initial_denominator = relation.combine(
        q(0x8000),
        QM31.zero(),
        q(0x42),
    );
    const final_denominator = relation.combine(
        q(0x8000),
        q(access_clock),
        q(0x42),
    );
    const increment = QM31.one().neg()
        .mul(try initial_denominator.inv())
        .add(QM31.one().mul(try final_denominator.inv()));
    const cycle_size = try writeAccumulatorCycle(
        &first_values,
        interaction_values[4..8],
        increment,
        component.log_size,
    );
    component.claims[1] = increment.mul(q(cycle_size));
    var interaction: [lookup.N_EXECUTION_COLUMNS]prover_component.Poly =
        undefined;
    for (&interaction, &interaction_values) |*polynomial, *values|
        polynomial.* = .{
            .log_size = EVALUATION_LOG_SIZE,
            .values = values,
        };
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
        &interaction,
    };
    const trace = prover_component.Trace{
        .polys = TreeVec([]const prover_component.Poly).initOwned(&trees),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomainZero(
        &component,
        &trace,
        challenge,
        true,
    );

    const access_cycle = execution.N_MAIN_COLUMNS +
        cartridge_access.N_MAIN_COLUMNS;
    const system_region = access_cycle + cartridge_access.REGION_OFFSET +
        @intFromEnum(runner.cartridge_memory.Region.system);
    const echo_region = access_cycle + cartridge_access.REGION_OFFSET +
        @intFromEnum(runner.cartridge_memory.Region.system_echo);
    @memset(&main_values[system_region], M31.zero());
    @memset(&main_values[echo_region], M31.one());
    try expectDomainZero(&component, &trace, challenge, false);
    @memset(&main_values[system_region], M31.one());
    @memset(&main_values[echo_region], M31.zero());

    const value_bit = access_cycle + cartridge_access.ACCESS_VALUE_OFFSET;
    @memset(&main_values[value_bit], M31.one());
    try expectDomainZero(&component, &trace, challenge, false);
    @memset(&main_values[value_bit], M31.zero());

    const lookup_start = execution.N_MAIN_COLUMNS +
        cartridge_access_component.N_MAIN_COLUMNS + memory_offset;
    @memset(
        &main_values[lookup_start + lookup.PREVIOUS_CLOCK_OFFSET],
        M31.one(),
    );
    @memset(
        &main_values[lookup_start + lookup.DIFFERENCE_BITS_OFFSET],
        M31.zero(),
    );
    try expectDomainZero(&component, &trace, challenge, false);
    @memset(
        &main_values[lookup_start + lookup.PREVIOUS_CLOCK_OFFSET],
        M31.zero(),
    );
    @memset(
        &main_values[lookup_start + lookup.DIFFERENCE_BITS_OFFSET],
        M31.one(),
    );

    const timer_region = access_cycle + cartridge_access.REGION_OFFSET +
        @intFromEnum(runner.cartridge_memory.Region.timer_mmio);
    @memset(&main_values[system_region], M31.zero());
    @memset(&main_values[timer_region], M31.one());
    try expectDomainZero(&component, &trace, challenge, false);
}

test "boundary rejects final memory hidden MMIO and padding mutations" {
    const relation = lookup.Relation.dummy();
    var component = subject.Component{
        .kind = .boundary,
        .log_size = lookup.BOUNDARY_LOG_SIZE,
        .is_first_column = 0,
        .enabled_column = 1,
        .address_column = 2,
        .initial_value_column = 3,
        .final_value_column = 4,
        .main_offset = 0,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = .{QM31.zero()} ** lookup.N_EXECUTION_SUMS,
    };
    const address = q(0x8000);
    const initial_value = q(2);
    const final_clock = q(5);
    const final_value = q(3);
    component.claims[0] = try boundaryIncrement(
        relation,
        address,
        initial_value,
        final_clock,
        final_value,
    );
    var honest = component.evaluateBoundaryRow(
        QM31.one(),
        address,
        initial_value,
        final_clock,
        final_value,
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
    );
    try std.testing.expect(allZero(&honest));

    honest = component.evaluateBoundaryRow(
        QM31.one(),
        address,
        initial_value,
        final_clock,
        q(2),
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
    );
    try std.testing.expect(!allZero(&honest));

    component.claims[0] = QM31.zero();
    const hidden_mmio = component.evaluateBoundaryRow(
        QM31.one(),
        q(runner.cartridge_memory.INTERRUPT_FLAGS),
        QM31.zero(),
        QM31.one(),
        QM31.one(),
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
    );
    try std.testing.expect(!allZero(&hidden_mmio));

    const padding = component.evaluateBoundaryRow(
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
    );
    try std.testing.expect(allZero(&padding));
    const forged_padding = component.evaluateBoundaryRow(
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
    );
    try std.testing.expect(!allZero(&forged_padding));
}

fn syntheticRead() !runner.CartridgeStepTrace {
    var trace: runner.CartridgeStepTrace = undefined;
    trace.instruction.before = .{ .h = 0x80 };
    trace.instruction.after = .{ .a = 0x42, .h = 0x80, .pc = 1 };
    trace.instruction.decoded = try isa.decode(&.{0x7e});
    trace.instruction.cycle_count = 2;
    trace.instruction.branch_taken = false;
    trace.instruction.result = 0x42;
    trace.instruction.cycles[0] = .{
        .address = 0,
        .value = 0x7e,
        .action = .read,
    };
    trace.instruction.cycles[1] = .{
        .address = 0x8000,
        .value = 0x42,
        .action = .read,
    };
    trace.accesses = [_]?runner.cartridge_memory.Access{null} ** 6;
    trace.accesses[0] = .{
        .logical_address = 0,
        .action = .read,
        .region = .cartridge_rom,
        .physical_offset = 0,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = 0x7e,
    };
    trace.accesses[1] = .{
        .logical_address = 0x8000,
        .action = .read,
        .region = .system,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = 0x42,
    };
    return trace;
}

fn fillConstants(
    destinations: [][EVALUATION_SIZE]M31,
    values: []const M31,
) void {
    std.debug.assert(destinations.len == values.len);
    for (destinations, values) |*destination, value|
        @memset(destination, value);
}

fn writeAccumulatorCycle(
    first_values: *[EVALUATION_SIZE]M31,
    columns: [][EVALUATION_SIZE]M31,
    increment: QM31,
    component_log_size: u32,
) !usize {
    std.debug.assert(columns.len == 4);
    var next: [EVALUATION_SIZE]usize = undefined;
    for (0..EVALUATION_SIZE) |row| {
        const previous = utils.previousBitReversedCircleDomainIndex(
            row,
            component_log_size,
            EVALUATION_LOG_SIZE,
        );
        next[previous] = row;
    }
    var visited = [_]bool{false} ** EVALUATION_SIZE;
    var accumulators = [_]QM31{QM31.zero()} ** EVALUATION_SIZE;
    var cycle_size: usize = 0;
    for (0..EVALUATION_SIZE) |start| {
        if (visited[start]) continue;
        first_values[start] = M31.one();
        visited[start] = true;
        var current = start;
        var length: usize = 1;
        while (next[current] != start) {
            const following = next[current];
            accumulators[following] =
                accumulators[current].add(increment);
            visited[following] = true;
            current = following;
            length += 1;
        }
        if (cycle_size == 0)
            cycle_size = length
        else
            try std.testing.expectEqual(cycle_size, length);
    }
    for (accumulators, 0..) |value, row| {
        const coordinates = value.toM31Array();
        for (coordinates, 0..) |coordinate, column|
            columns[column][row] = coordinate;
    }
    return cycle_size;
}

fn boundaryIncrement(
    relation: lookup.Relation,
    address: QM31,
    initial_value: QM31,
    final_clock: QM31,
    final_value: QM31,
) !QM31 {
    const initial_denominator = relation.combine(
        address,
        QM31.zero(),
        initial_value,
    );
    const final_denominator = relation.combine(
        address,
        final_clock,
        final_value,
    );
    return QM31.one().mul(try initial_denominator.inv()).add(
        QM31.one().neg().mul(try final_denominator.inv()),
    );
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}

fn allZero(values: []const QM31) bool {
    for (values) |value|
        if (!value.isZero()) return false;
    return true;
}

fn expectDomainZero(
    component: *const subject.Component,
    trace: *const prover_component.Trace,
    challenge: QM31,
    expected_zero: bool,
) !void {
    var accumulator =
        try prover_air_accumulation.DomainEvaluationAccumulator.init(
            std.testing.allocator,
            challenge,
            EVALUATION_LOG_SIZE,
            component.nConstraints(),
        );
    defer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
    var result = try accumulator.finalize();
    defer result.deinit(std.testing.allocator);
    var zero = true;
    for (0..result.len()) |row|
        zero = zero and result.at(row).isZero();
    try std.testing.expectEqual(expected_zero, zero);
}
