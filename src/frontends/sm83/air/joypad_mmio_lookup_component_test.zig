const std = @import("std");
const TreeVec = @import("stwo_core").pcs.TreeVec;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const utils = @import("stwo_core").utils;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");
const joypad = @import("../runner/joypad.zig");
const cartridge_access_leaf = @import("cartridge_access.zig");
const cartridge_access = @import("cartridge_access_component.zig");
const execution = @import("execution.zig");
const joypad_air = @import("joypad.zig");
const joypad_binding = @import("joypad_binding.zig");
const joypad_component = @import("joypad_component.zig");
const lookup = @import("joypad_mmio_lookup.zig");
const subject = @import("joypad_mmio_lookup_component.zig");

const LOG_SIZE: u32 = 4;
const EVALUATION_LOG_SIZE: u32 = LOG_SIZE + 1;
const EVALUATION_SIZE: usize = 1 << EVALUATION_LOG_SIZE;
const FIRST_COLUMN: usize = 2;
const EXECUTION_OFFSET: usize = 3;
const ACCESS_OFFSET: usize =
    EXECUTION_OFFSET + execution.N_MAIN_COLUMNS + 2;
const EXECUTION_MAIN_COLUMNS: usize =
    ACCESS_OFFSET + cartridge_access.N_MAIN_COLUMNS;
const BINDING_OFFSET: usize = 5;
const JOYPAD_MAIN_COLUMNS: usize =
    BINDING_OFFSET + joypad_binding.N_MAIN_COLUMNS;
const INTERACTION_OFFSET: usize = 7;
const EXECUTION_INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_EXECUTION_INTERACTION_COLUMNS;
const JOYPAD_INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_JOYPAD_INTERACTION_COLUMNS;

test "owners expose exact cubic geometry at nonzero offsets" {
    const relations = lookup.Relations.dummy();
    const claims = zeroClaims();
    const execution_owner = executionComponent(&relations, claims);
    const joypad_owner = joypadComponent(&relations, claims);
    try std.testing.expectEqual(
        lookup.N_EXECUTION_CONSTRAINTS,
        execution_owner.nConstraints(),
    );
    try std.testing.expectEqual(
        lookup.N_JOYPAD_CONSTRAINTS,
        joypad_owner.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, LOG_SIZE + 1),
        execution_owner.maxConstraintLogDegreeBound(),
    );
    _ = execution_owner.asVerifierComponent();
    _ = joypad_owner.asProverComponent();

    var execution_bounds = try execution_owner.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer execution_bounds.deinitDeep(std.testing.allocator);
    try expectShape(
        execution_bounds.items,
        FIRST_COLUMN + 1,
        EXECUTION_MAIN_COLUMNS,
        EXECUTION_INTERACTION_COLUMNS,
    );

    var joypad_bounds = try joypad_owner.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer joypad_bounds.deinitDeep(std.testing.allocator);
    try expectShape(
        joypad_bounds.items,
        FIRST_COLUMN + 1,
        JOYPAD_MAIN_COLUMNS,
        JOYPAD_INTERACTION_COLUMNS,
    );

    var execution_mask = try execution_owner.maskPoints(
        std.testing.allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        LOG_SIZE + 1,
    );
    defer execution_mask.deinitDeep(std.testing.allocator);
    try expectShape(
        execution_mask.items,
        FIRST_COLUMN + 1,
        EXECUTION_MAIN_COLUMNS,
        EXECUTION_INTERACTION_COLUMNS,
    );
    for (execution_mask.items[2]) |points|
        try std.testing.expectEqual(@as(usize, 2), points.len);

    const indices = try joypad_owner.preprocessedColumnIndices(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(
        usize,
        &.{FIRST_COLUMN},
        indices,
    );
}

test "sampled execution owner rejects claim activity and provenance changes" {
    const relations = lookup.Relations.dummy();
    const step = try makeJoypadRead();
    const machine = execution.columns(step.instruction, 100);
    const accesses = try cartridge_access.columns(step);
    const pairs = lookup.executionPairs(
        try liftExecution(machine),
        try liftAccess(accesses),
        relations,
    );
    var claims = zeroClaims();
    var preprocessed_values =
        [_][1]QM31{[_]QM31{QM31.zero()}} ** (FIRST_COLUMN + 1);
    preprocessed_values[FIRST_COLUMN][0] = QM31.one();
    var preprocessed: [FIRST_COLUMN + 1][]QM31 = undefined;
    pointSlices(&preprocessed, &preprocessed_values);
    var main_values =
        [_][1]QM31{[_]QM31{QM31.zero()}} ** EXECUTION_MAIN_COLUMNS;
    fillPointConstants(
        main_values[EXECUTION_OFFSET..][0..execution.N_MAIN_COLUMNS],
        &machine,
    );
    fillPointConstants(
        main_values[ACCESS_OFFSET..][0..cartridge_access.N_MAIN_COLUMNS],
        &accesses,
    );
    var main: [EXECUTION_MAIN_COLUMNS][]QM31 = undefined;
    pointSlices(&main, &main_values);
    var interaction_values =
        [_][2]QM31{
            [_]QM31{QM31.zero()} ** 2,
        } ** EXECUTION_INTERACTION_COLUMNS;
    for (pairs, 0..) |relation_pairs, relation_index| {
        for (relation_pairs, 0..) |entry, sum_index| {
            claims.execution[relation_index][sum_index] =
                try pairIncrement(entry);
        }
    }
    var interaction: [EXECUTION_INTERACTION_COLUMNS][]QM31 = undefined;
    pointSlices(&interaction, &interaction_values);
    var component = executionComponent(&relations, claims);
    var constraints: [subject.N_MAX_CONSTRAINTS]QM31 = undefined;
    const count = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(allZero(constraints[0..count]));

    component.claims.execution[0][0] =
        component.claims.execution[0][0].add(QM31.one());
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(constraints[0..count]));
    component.claims = claims;

    main_values[
        EXECUTION_OFFSET + 2 * execution.N_STATE_COLUMNS + 2
    ][0] = QM31.zero();
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(constraints[0..count]));
    main_values[
        EXECUTION_OFFSET + 2 * execution.N_STATE_COLUMNS + 2
    ][0] = QM31.one();

    const joypad_region = ACCESS_OFFSET +
        cartridge_access_leaf.REGION_OFFSET +
        @intFromEnum(runner.cartridge_memory.Region.joypad_mmio);
    main_values[joypad_region][0] = QM31.zero();
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(constraints[0..count]));
}

test "execution prover domain rejects claim provenance and vacuity mutations" {
    const relations = lookup.Relations.dummy();
    const step = try makeJoypadRead();
    const machine = execution.columns(step.instruction, 100);
    const accesses = try cartridge_access.columns(step);
    const pairs = lookup.executionPairs(
        try liftExecution(machine),
        try liftAccess(accesses),
        relations,
    );
    var component = executionComponent(&relations, zeroClaims());
    var preprocessed_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** (FIRST_COLUMN + 1);
    var main_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** EXECUTION_MAIN_COLUMNS;
    fillDomainConstants(
        main_values[EXECUTION_OFFSET..][0..execution.N_MAIN_COLUMNS],
        &machine,
    );
    fillDomainConstants(
        main_values[ACCESS_OFFSET..][0..cartridge_access.N_MAIN_COLUMNS],
        &accesses,
    );
    var interaction_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** EXECUTION_INTERACTION_COLUMNS;
    try fillExecutionInteraction(
        &component,
        &preprocessed_values[FIRST_COLUMN],
        &interaction_values,
        pairs,
    );
    var preprocessed: [FIRST_COLUMN + 1]prover_component.Poly = undefined;
    domainPolys(&preprocessed, &preprocessed_values);
    var main: [EXECUTION_MAIN_COLUMNS]prover_component.Poly = undefined;
    domainPolys(&main, &main_values);
    var interaction: [EXECUTION_INTERACTION_COLUMNS]prover_component.Poly = undefined;
    domainPolys(&interaction, &interaction_values);
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
        &interaction,
    };
    const trace = prover_component.Trace{
        .polys = TreeVec([]const prover_component.Poly).initOwned(&trees),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomainZero(&component, &trace, challenge, true);

    component.claims.execution[0][0] =
        component.claims.execution[0][0].add(QM31.one());
    try expectDomainZero(&component, &trace, challenge, false);
    component.claims.execution[0][0] =
        component.claims.execution[0][0].sub(QM31.one());

    const joypad_region = ACCESS_OFFSET +
        cartridge_access_leaf.REGION_OFFSET +
        @intFromEnum(runner.cartridge_memory.Region.joypad_mmio);
    @memset(&main_values[joypad_region], M31.zero());
    try expectDomainZero(&component, &trace, challenge, false);
    @memset(&main_values[joypad_region], M31.one());

    const active = EXECUTION_OFFSET +
        2 * execution.N_STATE_COLUMNS + 2;
    @memset(&main_values[active], M31.zero());
    try expectDomainZero(&component, &trace, challenge, false);
}

test "joypad prover domain rejects claim read and inactive-clock mutations" {
    const relations = lookup.Relations.dummy();
    const binding = try tickBinding();
    const row = try liftJoypad(binding);
    const pairs = lookup.joypadPairs(row, relations);
    var component = joypadComponent(&relations, zeroClaims());
    var preprocessed_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** (FIRST_COLUMN + 1);
    var main_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** JOYPAD_MAIN_COLUMNS;
    fillDomainConstants(
        main_values[BINDING_OFFSET..][0..joypad_binding.N_MAIN_COLUMNS],
        &binding,
    );
    var interaction_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** JOYPAD_INTERACTION_COLUMNS;
    try fillJoypadInteraction(
        &component,
        &preprocessed_values[FIRST_COLUMN],
        &interaction_values,
        pairs,
    );
    var preprocessed: [FIRST_COLUMN + 1]prover_component.Poly = undefined;
    domainPolys(&preprocessed, &preprocessed_values);
    var main: [JOYPAD_MAIN_COLUMNS]prover_component.Poly = undefined;
    domainPolys(&main, &main_values);
    var interaction: [JOYPAD_INTERACTION_COLUMNS]prover_component.Poly = undefined;
    domainPolys(&interaction, &interaction_values);
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
        &interaction,
    };
    const trace = prover_component.Trace{
        .polys = TreeVec([]const prover_component.Poly).initOwned(&trees),
    };
    const challenge = QM31.fromU32Unchecked(13, 17, 19, 23);
    try expectDomainZero(&component, &trace, challenge, true);

    component.claims.joypad[0] =
        component.claims.joypad[0].add(QM31.one());
    try expectDomainZero(&component, &trace, challenge, false);
    component.claims.joypad[0] =
        component.claims.joypad[0].sub(QM31.one());

    @memset(
        &main_values[BINDING_OFFSET + joypad_binding.READ_ENABLED_OFFSET],
        M31.fromCanonical(2),
    );
    try expectDomainZero(&component, &trace, challenge, false);
    @memset(
        &main_values[BINDING_OFFSET + joypad_binding.READ_ENABLED_OFFSET],
        M31.one(),
    );

    @memset(&main_values[BINDING_OFFSET], M31.zero());
    try expectDomainZero(&component, &trace, challenge, false);
}

fn executionComponent(
    relations: *const lookup.Relations,
    claims: lookup.Claims,
) subject.Component {
    return .{
        .kind = .execution,
        .log_size = LOG_SIZE,
        .is_first_column = FIRST_COLUMN,
        .execution_offset = EXECUTION_OFFSET,
        .access_offset = ACCESS_OFFSET,
        .interaction_offset = INTERACTION_OFFSET,
        .relations = relations,
        .claims = claims,
    };
}

fn joypadComponent(
    relations: *const lookup.Relations,
    claims: lookup.Claims,
) subject.Component {
    return .{
        .kind = .joypad,
        .log_size = LOG_SIZE,
        .is_first_column = FIRST_COLUMN,
        .binding_offset = BINDING_OFFSET,
        .interaction_offset = INTERACTION_OFFSET,
        .relations = relations,
        .claims = claims,
    };
}

fn zeroClaims() lookup.Claims {
    return .{
        .execution = [_][lookup.N_EXECUTION_SUMS]QM31{
            [_]QM31{QM31.zero()} ** lookup.N_EXECUTION_SUMS,
        } ** lookup.N_RELATIONS,
        .joypad = [_]QM31{QM31.zero()} ** lookup.N_RELATIONS,
    };
}

fn makeJoypadRead() !runner.CartridgeStepTrace {
    var step = std.mem.zeroes(runner.CartridgeStepTrace);
    step.instruction.before = .{};
    step.instruction.after = .{ .pc = 1 };
    step.instruction.decoded = try isa.decode(&.{0});
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = joypad.P1_ADDRESS,
        .value = 0xcf,
        .action = .read,
    };
    step.accesses[0] = .{
        .logical_address = joypad.P1_ADDRESS,
        .action = .read,
        .region = .joypad_mmio,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = 0xcf,
    };
    return step;
}

fn tickBinding() ![joypad_binding.N_MAIN_COLUMNS]M31 {
    const transition = try joypad.Transition.apply(
        try joypad.State.init(0xcf, 0, 0, 0),
        .tick_mcycle,
    );
    const semantic = joypad_component.columns(
        try joypad_air.ValidatedStep.init(transition),
    );
    var result =
        [_]M31{M31.zero()} ** joypad_binding.N_MAIN_COLUMNS;
    @memcpy(result[0..joypad_component.N_MAIN_COLUMNS], &semantic);
    result[joypad_binding.MCYCLE_OFFSET] = M31.fromCanonical(100);
    result[joypad_binding.READ_ENABLED_OFFSET] = M31.one();
    return result;
}

fn liftExecution(
    values: [execution.N_MAIN_COLUMNS]M31,
) !execution.Row(QM31) {
    var lifted: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    lift(&lifted, &values);
    return execution.Row(QM31).fromColumns(&lifted);
}

fn liftAccess(
    values: [cartridge_access.N_MAIN_COLUMNS]M31,
) !cartridge_access.PackedRow(QM31) {
    var lifted: [cartridge_access.N_MAIN_COLUMNS]QM31 = undefined;
    lift(&lifted, &values);
    return cartridge_access.PackedRow(QM31).fromColumns(&lifted);
}

fn liftJoypad(
    values: [joypad_binding.N_MAIN_COLUMNS]M31,
) !lookup.JoypadRow(QM31) {
    var lifted: [joypad_binding.N_MAIN_COLUMNS]QM31 = undefined;
    lift(&lifted, &values);
    return lookup.joypadRow(QM31, &lifted);
}

fn lift(output: []QM31, values: []const M31) void {
    for (output, values) |*target, value|
        target.* = QM31.fromBase(value);
}

fn pairIncrement(entry: lookup.Pair) !QM31 {
    return entry.numerator.mul(try entry.denominator.inv());
}

fn fillExecutionInteraction(
    component: *subject.Component,
    first: *[EVALUATION_SIZE]M31,
    interaction: *[EXECUTION_INTERACTION_COLUMNS][EVALUATION_SIZE]M31,
    pairs: [lookup.N_RELATIONS][lookup.N_EXECUTION_SUMS]lookup.Pair,
) !void {
    var at: usize = 0;
    for (pairs, 0..) |relation_pairs, relation_index| {
        for (relation_pairs, 0..) |entry, sum_index| {
            const increment = try pairIncrement(entry);
            const cycle_size = try writeAccumulatorCycle(
                first,
                interaction[INTERACTION_OFFSET + 4 * at ..][0..4],
                increment,
            );
            component.claims.execution[relation_index][sum_index] =
                increment.mul(q(cycle_size));
            at += 1;
        }
    }
}

fn fillJoypadInteraction(
    component: *subject.Component,
    first: *[EVALUATION_SIZE]M31,
    interaction: *[JOYPAD_INTERACTION_COLUMNS][EVALUATION_SIZE]M31,
    pairs: [lookup.N_RELATIONS]lookup.Pair,
) !void {
    for (pairs, 0..) |entry, index| {
        const increment = try pairIncrement(entry);
        const cycle_size = try writeAccumulatorCycle(
            first,
            interaction[INTERACTION_OFFSET + 4 * index ..][0..4],
            increment,
        );
        component.claims.joypad[index] = increment.mul(q(cycle_size));
    }
}

fn writeAccumulatorCycle(
    first: *[EVALUATION_SIZE]M31,
    columns: [][EVALUATION_SIZE]M31,
    increment: QM31,
) !usize {
    var next: [EVALUATION_SIZE]usize = undefined;
    for (0..EVALUATION_SIZE) |row| {
        const previous = utils.previousBitReversedCircleDomainIndex(
            row,
            LOG_SIZE,
            EVALUATION_LOG_SIZE,
        );
        next[previous] = row;
    }
    var visited = [_]bool{false} ** EVALUATION_SIZE;
    var values = [_]QM31{QM31.zero()} ** EVALUATION_SIZE;
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
        const coordinates = value.toM31Array();
        for (coordinates, 0..) |coordinate, column|
            columns[column][row] = coordinate;
    }
    return cycle_size;
}

fn pointSlices(output: anytype, values: anytype) void {
    for (output, values) |*column, *source| column.* = source;
}

fn fillPointConstants(destinations: anytype, values: []const M31) void {
    for (destinations, values) |*destination, value|
        destination[0] = QM31.fromBase(value);
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

fn expectShape(
    items: anytype,
    preprocessed: usize,
    main: usize,
    interaction: usize,
) !void {
    try std.testing.expectEqual(@as(usize, 3), items.len);
    try std.testing.expectEqual(preprocessed, items[0].len);
    try std.testing.expectEqual(main, items[1].len);
    try std.testing.expectEqual(interaction, items[2].len);
}

fn expectDomainZero(
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
    try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
    var result = try accumulator.finalize();
    defer result.deinit(std.testing.allocator);
    var zero = true;
    for (0..result.len()) |row|
        zero = zero and result.at(row).isZero();
    try std.testing.expectEqual(expected, zero);
}

fn allZero(values: []const QM31) bool {
    for (values) |value|
        if (!value.isZero()) return false;
    return true;
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}
