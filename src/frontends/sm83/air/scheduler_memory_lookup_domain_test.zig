//! Prover-domain controls for authenticated scheduler IE/IF samples.

const std = @import("std");
const core = @import("stwo_core");
const TreeVec = core.pcs.TreeVec;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const prover_accumulation =
    @import("stwo_prover_engine").air.accumulation;
const prover_component =
    @import("stwo_prover_engine").air.component_prover;
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");
const scheduler = @import("scheduler.zig");
const scheduler_component = @import("scheduler_component.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const lookup = @import("scheduler_memory_lookup.zig");
const subject = @import("scheduler_memory_lookup_component.zig");

const LOG_SIZE: u32 = 4;
const SIZE: usize = 1 << LOG_SIZE;
const EVALUATION_LOG_SIZE: u32 = LOG_SIZE + 1;
const EVALUATION_SIZE: usize = 1 << EVALUATION_LOG_SIZE;
const FIRST_COLUMN: usize = 2;
const LAST_COLUMN: usize = 4;
const SCHEDULER_OFFSET: usize = 5;
const MEMORY_OFFSET: usize =
    SCHEDULER_OFFSET + scheduler_component.N_MAIN_COLUMNS + 3;
const MAIN_COLUMNS: usize = MEMORY_OFFSET + lookup.N_MAIN_COLUMNS;
const INTERACTION_OFFSET: usize = 7;
const INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_INTERACTION_COLUMNS;
const SCHEDULER_MCYCLE_OFFSET: usize = 1;
const IF_SAMPLE_OFFSET: usize =
    @intFromEnum(lookup.SampleIndex.interrupt_flags) *
    lookup.N_SAMPLE_COLUMNS;
const INITIAL_IE: u8 = 0xa5;
const INITIAL_IF: u8 = 0x92;

test "scheduler memory prover domain rejects omission substitution and vacuity" {
    const relation = memory_lookup.Relation.dummy();
    const steps = try instructionSteps();
    const predecessors = stablePredecessors();
    const scheduled = try scheduler_component.columns(
        try scheduler.ValidatedStep.init(steps[1]),
        1,
    );
    const memory = try lookup.columns(
        try scheduler.ValidatedStep.init(steps[1]),
        1,
        predecessors[1],
    );
    var scheduled_q: [scheduler_component.N_MAIN_COLUMNS]QM31 =
        undefined;
    var memory_q: [lookup.N_MAIN_COLUMNS]QM31 = undefined;
    lift(&scheduled_q, &scheduled);
    lift(&memory_q, &memory);
    const pairs = lookup.pairsForRows(
        try scheduler_component.Row(QM31).fromColumns(&scheduled_q),
        try lookup.Row(QM31).fromColumns(&memory_q),
        QM31.zero(),
        relation,
    );
    var increments: [lookup.N_SAMPLES]QM31 = undefined;
    for (&increments, pairs) |*increment, pair|
        increment.* = try pairIncrement(pair);

    var preprocessed_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** (LAST_COLUMN + 1);
    var main_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** MAIN_COLUMNS;
    fillDomainConstants(
        main_values[SCHEDULER_OFFSET..][0..scheduler_component.N_MAIN_COLUMNS],
        &scheduled,
    );
    fillDomainConstants(
        main_values[MEMORY_OFFSET..][0..lookup.N_MAIN_COLUMNS],
        &memory,
    );
    var interaction_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** INTERACTION_COLUMNS;
    const cycle_size = try writeAccumulatorCycles(
        &preprocessed_values[FIRST_COLUMN],
        interaction_values[INTERACTION_OFFSET..][0..4],
        increments[0],
    );
    _ = try writeAccumulatorCycles(
        &preprocessed_values[FIRST_COLUMN],
        interaction_values[INTERACTION_OFFSET + 4 ..][0..4],
        increments[1],
    );
    _ = try writeAccumulatorCycles(
        &preprocessed_values[FIRST_COLUMN],
        interaction_values[INTERACTION_OFFSET + 8 ..][0..4],
        increments[2],
    );
    var claims = lookup.Claims{
        .samples = [_]QM31{QM31.zero()} ** lookup.N_SAMPLES,
    };
    for (&claims.samples, increments) |*claim, increment|
        claim.* = increment.mul(q(cycle_size));
    const boundary = lookup.Boundary{
        .initial_mcycle = 1,
        .final_mcycle = 2,
    };
    var component = makeComponent(&relation, claims, boundary);
    var preprocessed: [LAST_COLUMN + 1]prover_component.Poly =
        undefined;
    domainPolys(&preprocessed, &preprocessed_values);
    var main: [MAIN_COLUMNS]prover_component.Poly = undefined;
    domainPolys(&main, &main_values);
    var interaction: [INTERACTION_COLUMNS]prover_component.Poly =
        undefined;
    domainPolys(&interaction, &interaction_values);
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
        &interaction,
    };
    const trace = prover_component.Trace{
        .polys = TreeVec([]const prover_component.Poly).initOwned(
            &trees,
        ),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomain(&component, &trace, challenge, true);

    @memset(&preprocessed_values[FIRST_COLUMN], M31.zero());
    try expectDomain(&component, &trace, challenge, false);
    _ = try writeAccumulatorCycles(
        &preprocessed_values[FIRST_COLUMN],
        interaction_values[INTERACTION_OFFSET..][0..4],
        increments[0],
    );

    @memset(
        &main_values[SCHEDULER_OFFSET + SCHEDULER_MCYCLE_OFFSET],
        M31.fromCanonical(2),
    );
    try expectDomain(&component, &trace, challenge, false);
    @memset(
        &main_values[SCHEDULER_OFFSET + SCHEDULER_MCYCLE_OFFSET],
        M31.one(),
    );

    @memset(
        &main_values[
            MEMORY_OFFSET + IF_SAMPLE_OFFSET +
                lookup.PREVIOUS_CLOCK_OFFSET
        ],
        M31.one(),
    );
    try expectDomain(&component, &trace, challenge, false);
    @memset(
        &main_values[
            MEMORY_OFFSET + IF_SAMPLE_OFFSET +
                lookup.PREVIOUS_CLOCK_OFFSET
        ],
        M31.zero(),
    );

    component.claims.samples[0] =
        component.claims.samples[0].add(QM31.one());
    try expectDomain(&component, &trace, challenge, false);
    component.claims = claims;

    @memset(&main_values[SCHEDULER_OFFSET], M31.zero());
    for (
        interaction_values[INTERACTION_OFFSET..][0..lookup.N_INTERACTION_COLUMNS],
    ) |*column| @memset(column, M31.zero());
    component.claims = .{
        .samples = [_]QM31{QM31.zero()} ** lookup.N_SAMPLES,
    };
    try expectDomain(&component, &trace, challenge, false);
}

fn instructionSteps() ![SIZE]machine.StepResult {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    @memset(memory.bytes[0..SIZE], 0);
    memory.write(0xffff, INITIAL_IE);
    memory.write(0xff0f, INITIAL_IF);
    var scheduler_machine = machine.Machine.init(&memory, .{});
    var steps: [SIZE]machine.StepResult = undefined;
    for (&steps) |*step| step.* = try scheduler_machine.step();
    return steps;
}

fn stablePredecessors() [SIZE]lookup.Predecessors {
    var result = [_]lookup.Predecessors{.{}} ** SIZE;
    for (&result, 0..) |*row, index| {
        row.* = .{
            .interrupt_enable = .{
                .clock = if (index == 0)
                    0
                else
                    schedulerClock(index - 1),
                .value = INITIAL_IE,
            },
            .interrupt_flags = .{
                .clock = if (index == 0)
                    0
                else
                    postClock(index - 1),
                .value = INITIAL_IF,
            },
            .post_interrupt_flags = .{
                .clock = schedulerClock(index),
                .value = INITIAL_IF,
            },
        };
    }
    return result;
}

fn schedulerClock(mcycle: usize) u32 {
    return memory_lookup.memory_clock.phaseClock(
        @intCast(mcycle),
        lookup.SCHEDULER_PHASE,
    ) catch unreachable;
}

fn postClock(mcycle: usize) u32 {
    return memory_lookup.memory_clock.phaseClock(
        @intCast(mcycle),
        lookup.OBSERVATION_PHASE,
    ) catch unreachable;
}

fn makeComponent(
    relation: *const memory_lookup.Relation,
    claims: lookup.Claims,
    boundary: lookup.Boundary,
) subject.Component {
    return .{
        .log_size = LOG_SIZE,
        .is_first_column = FIRST_COLUMN,
        .is_last_column = LAST_COLUMN,
        .scheduler_offset = SCHEDULER_OFFSET,
        .memory_offset = MEMORY_OFFSET,
        .interaction_offset = INTERACTION_OFFSET,
        .relation = relation,
        .claims = claims,
        .boundary = boundary,
    };
}

fn writeAccumulatorCycles(
    first: *[EVALUATION_SIZE]M31,
    columns: [][EVALUATION_SIZE]M31,
    increment: QM31,
) !usize {
    var next: [EVALUATION_SIZE]usize = undefined;
    for (0..EVALUATION_SIZE) |row| {
        const previous =
            core.utils.previousBitReversedCircleDomainIndex(
                row,
                LOG_SIZE,
                EVALUATION_LOG_SIZE,
            );
        next[previous] = row;
    }
    var visited = [_]bool{false} ** EVALUATION_SIZE;
    var values =
        [_]QM31{QM31.zero()} ** EVALUATION_SIZE;
    var cycle_size: usize = 0;
    for (0..EVALUATION_SIZE) |start| {
        if (visited[start]) continue;
        first[start] = M31.one();
        visited[start] = true;
        var current = start;
        var length: usize = 1;
        while (next[current] != start) {
            const following = next[current];
            values[following] = values[current].add(increment);
            visited[following] = true;
            current = following;
            length += 1;
        }
        if (cycle_size == 0)
            cycle_size = length
        else
            try std.testing.expectEqual(cycle_size, length);
    }
    for (values, 0..) |value, row| {
        for (value.toM31Array(), 0..) |coordinate, column|
            columns[column][row] = coordinate;
    }
    return cycle_size;
}

fn expectDomain(
    component: *const subject.Component,
    trace: *const prover_component.Trace,
    challenge: QM31,
    expected: bool,
) !void {
    var accumulator =
        try prover_accumulation.DomainEvaluationAccumulator.init(
            std.testing.allocator,
            challenge,
            EVALUATION_LOG_SIZE,
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
    for (0..result.len()) |row|
        zero = zero and result.at(row).isZero();
    try std.testing.expectEqual(expected, zero);
}

fn pairIncrement(pair: memory_lookup.RowPair) !QM31 {
    if (pair.n1.isZero() and pair.n2.isZero())
        return QM31.zero();
    const denominator = pair.d1.mul(pair.d2);
    const numerator =
        pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return numerator.mul(try denominator.inv());
}

fn lift(output: []QM31, values: []const M31) void {
    for (output, values) |*target, value|
        target.* = QM31.fromBase(value);
}

fn fillDomainConstants(destinations: anytype, values: []const M31) void {
    for (destinations, values) |*destination, value|
        @memset(destination, value);
}

fn domainPolys(output: anytype, values: anytype) void {
    for (output, values) |*polynomial, *column| {
        polynomial.* = .{
            .log_size = EVALUATION_LOG_SIZE,
            .values = column,
        };
    }
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}
