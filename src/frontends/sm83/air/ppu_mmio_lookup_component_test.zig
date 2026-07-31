const std = @import("std");
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const runner = @import("../runner/mod.zig");
const cartridge_access_air = @import("cartridge_access.zig");
const cartridge_access = @import("cartridge_access_component.zig");
const execution = @import("execution.zig");
const ppu_binding = @import("ppu_binding.zig");
const lookup = @import("ppu_mmio_lookup.zig");
const subject = @import("ppu_mmio_lookup_component.zig");

const LOG_SIZE: u32 = 4;
const FIRST_COLUMN: usize = 2;
const EXECUTION_OFFSET: usize = 3;
const ACCESS_OFFSET: usize =
    EXECUTION_OFFSET + execution.N_MAIN_COLUMNS + 2;
const EXECUTION_MAIN_COLUMNS: usize =
    ACCESS_OFFSET + cartridge_access.N_MAIN_COLUMNS;
const BINDING_OFFSET: usize = 5;
const AUXILIARY_OFFSET: usize =
    BINDING_OFFSET + ppu_binding.N_MAIN_COLUMNS + 2;
const PPU_MAIN_COLUMNS: usize = AUXILIARY_OFFSET + 1;
const INTERACTION_OFFSET: usize = 7;
const EXECUTION_INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_EXECUTION_INTERACTION_COLUMNS;
const PPU_INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_PPU_INTERACTION_COLUMNS;

test "PPU lookup owners expose offset-safe exact cubic proof geometry" {
    const relations = lookup.Relations.dummy();
    const claims = zeroClaims();
    const execution_owner = executionComponent(&relations, claims);
    const ppu_owner = ppuComponent(&relations, claims);
    try std.testing.expectEqual(
        @as(usize, 18),
        execution_owner.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(usize, 5),
        ppu_owner.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, 3),
        lookup.MAX_CONSTRAINT_DEGREE,
    );
    try std.testing.expectEqual(
        @as(u32, LOG_SIZE + 1),
        ppu_owner.maxConstraintLogDegreeBound(),
    );
    _ = execution_owner.asVerifierComponent();
    _ = ppu_owner.asProverComponent();

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
    var ppu_bounds = try ppu_owner.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer ppu_bounds.deinitDeep(std.testing.allocator);
    try expectShape(
        ppu_bounds.items,
        FIRST_COLUMN + 1,
        PPU_MAIN_COLUMNS,
        PPU_INTERACTION_COLUMNS,
    );
    var ppu_mask = try ppu_owner.maskPoints(
        std.testing.allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        LOG_SIZE + 1,
    );
    defer ppu_mask.deinitDeep(std.testing.allocator);
    try expectShape(
        ppu_mask.items,
        FIRST_COLUMN + 1,
        PPU_MAIN_COLUMNS,
        PPU_INTERACTION_COLUMNS,
    );
    for (ppu_mask.items[2]) |points|
        try std.testing.expectEqual(@as(usize, 2), points.len);
    const indices = try ppu_owner.preprocessedColumnIndices(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(
        usize,
        &.{FIRST_COLUMN},
        indices,
    );
}

test "sampled execution owner rejects claim and PPU provenance mutations" {
    const relations = lookup.Relations.dummy();
    const step = makePpuRead();
    const machine = execution.columns(step.instruction, 100);
    const accesses = try cartridge_access.columns(step);
    const pairs = lookup.executionPairs(
        try liftExecution(machine),
        try liftAccess(accesses),
        relations,
    );
    var claims = zeroClaims();
    for (pairs, 0..) |relation_pairs, relation_index| {
        for (relation_pairs, 0..) |entry, sum_index|
            claims.execution[relation_index][sum_index] =
                try pairIncrement(entry);
    }

    var preprocessed_values =
        [_][1]QM31{.{QM31.zero()}} ** (FIRST_COLUMN + 1);
    preprocessed_values[FIRST_COLUMN][0] = QM31.one();
    var preprocessed: [FIRST_COLUMN + 1][]QM31 = undefined;
    pointSlices(&preprocessed, &preprocessed_values);
    var main_values =
        [_][1]QM31{.{QM31.zero()}} ** EXECUTION_MAIN_COLUMNS;
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
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
        EXECUTION_INTERACTION_COLUMNS;
    var interaction: [EXECUTION_INTERACTION_COLUMNS][]QM31 =
        undefined;
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

    const ppu_region = ACCESS_OFFSET +
        cartridge_access_air.REGION_OFFSET +
        @intFromEnum(runner.cartridge_memory.Region.ppu_mmio);
    main_values[ppu_region][0] = QM31.zero();
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(constraints[0..count]));
}

test "sampled PPU owner rejects omitted read accumulator and auxiliary vacuity" {
    const relations = lookup.Relations.dummy();
    const step = makePpuRead();
    var trace = try ppu_binding.generateFromExecution(
        std.testing.allocator,
        100,
        101,
        .{},
        &.{step},
    );
    defer trace.deinit(std.testing.allocator);
    const ppu_columns = try ppu_binding.columns(trace.rows[0]);
    const ppu = try liftPpu(ppu_columns, M31.zero());
    const pairs = lookup.ppuPairs(ppu, relations);
    var claims = zeroClaims();
    for (pairs, 0..) |entry, index|
        claims.ppu[index] = try pairIncrement(entry);

    var preprocessed_values =
        [_][1]QM31{.{QM31.zero()}} ** (FIRST_COLUMN + 1);
    preprocessed_values[FIRST_COLUMN][0] = QM31.one();
    var preprocessed: [FIRST_COLUMN + 1][]QM31 = undefined;
    pointSlices(&preprocessed, &preprocessed_values);
    var main_values =
        [_][1]QM31{.{QM31.zero()}} ** PPU_MAIN_COLUMNS;
    fillPointConstants(
        main_values[BINDING_OFFSET..][0..ppu_binding.N_MAIN_COLUMNS],
        &ppu_columns,
    );
    var main: [PPU_MAIN_COLUMNS][]QM31 = undefined;
    pointSlices(&main, &main_values);
    var interaction_values =
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
        PPU_INTERACTION_COLUMNS;
    var interaction: [PPU_INTERACTION_COLUMNS][]QM31 = undefined;
    pointSlices(&interaction, &interaction_values);

    const component = ppuComponent(&relations, claims);
    var constraints: [subject.N_MAX_CONSTRAINTS]QM31 = undefined;
    const count = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(allZero(constraints[0..count]));

    main_values[
        BINDING_OFFSET + ppu_binding.READ_MARKER_OFFSET
    ][0] = QM31.zero();
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(constraints[0..count]));
    main_values[
        BINDING_OFFSET + ppu_binding.READ_MARKER_OFFSET
    ][0] = QM31.one();

    interaction_values[INTERACTION_OFFSET][0] = QM31.one();
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(constraints[0..count]));
    interaction_values[INTERACTION_OFFSET][0] = QM31.zero();

    main_values[AUXILIARY_OFFSET][0] = QM31.one();
    _ = try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(constraints[0..count]));
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

fn ppuComponent(
    relations: *const lookup.Relations,
    claims: lookup.Claims,
) subject.Component {
    return .{
        .kind = .ppu,
        .log_size = LOG_SIZE,
        .is_first_column = FIRST_COLUMN,
        .binding_offset = BINDING_OFFSET,
        .auxiliary_offset = AUXILIARY_OFFSET,
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
        .ppu = [_]QM31{QM31.zero()} ** lookup.N_RELATIONS,
    };
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

fn liftPpu(
    values: [ppu_binding.N_MAIN_COLUMNS]M31,
    auxiliary: M31,
) !lookup.PpuRow(QM31) {
    var lifted: [ppu_binding.N_MAIN_COLUMNS]QM31 = undefined;
    lift(&lifted, &values);
    return lookup.ppuRow(
        QM31,
        &lifted,
        QM31.fromBase(auxiliary),
    );
}

fn lift(output: []QM31, values: []const M31) void {
    for (output, values) |*target, value|
        target.* = QM31.fromBase(value);
}

fn pairIncrement(entry: lookup.Pair) !QM31 {
    return entry.numerator.mul(try entry.denominator.inv());
}

fn pointSlices(output: anytype, values: anytype) void {
    for (output, values) |*column, *source| column.* = source;
}

fn fillPointConstants(destinations: anytype, values: []const M31) void {
    for (destinations, values) |*destination, value|
        destination[0] = QM31.fromBase(value);
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

fn allZero(values: []const QM31) bool {
    for (values) |value|
        if (!value.isZero()) return false;
    return true;
}

fn makePpuRead() runner.CartridgeStepTrace {
    const state = @import("../cartridge/mbc3.zig").State{};
    var step = std.mem.zeroes(runner.CartridgeStepTrace);
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = 0xff40,
        .value = 0,
        .action = .read,
    };
    step.accesses[0] = .{
        .logical_address = 0xff40,
        .action = .read,
        .region = .ppu_mmio,
        .physical_offset = null,
        .mapper_before = state,
        .mapper_after = state,
        .value = 0,
    };
    return step;
}
