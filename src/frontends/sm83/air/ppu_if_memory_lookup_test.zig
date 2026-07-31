const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const runner = @import("../runner/mod.zig");
const ppu_runner = @import("../runner/ppu_timing.zig");
const ppu_binding = @import("ppu_binding.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const subject = @import("ppu_if_memory_lookup.zig");

test "PPU IF row binds a dual request to one canonical bit-0 and bit-1 OR" {
    const event = dualEvent(7);
    const access = try subject.accessForEvent(
        event,
        .{ .clock = 3, .value = 0xa5 },
    );
    try std.testing.expect(access.vblank);
    try std.testing.expect(access.stat);
    try std.testing.expectEqual(requestClock(7), access.clock);
    try std.testing.expectEqual(@as(u8, 0xa7), access.next_value);

    const binding_values = try ppu_binding.columns(event);
    const predecessor_values = try subject.columnsForAccess(access);
    var ppu = try liftPpu(binding_values);
    var predecessor = try liftRow(predecessor_values);
    try std.testing.expect(
        subject.evaluate(QM31, ppu, predecessor).allZero(),
    );

    predecessor.previous_clock =
        predecessor.previous_clock.add(QM31.one());
    try std.testing.expect(
        !subject.evaluate(QM31, ppu, predecessor).allZero(),
    );
    predecessor = try liftRow(predecessor_values);
    predecessor.previous_value[4] =
        predecessor.previous_value[4].sub(QM31.one());
    try std.testing.expect(
        !subject.evaluate(QM31, ppu, predecessor).allZero(),
    );
    predecessor = try liftRow(predecessor_values);
    predecessor.difference_bits[0] =
        predecessor.difference_bits[0].sub(QM31.one());
    try std.testing.expect(
        !subject.evaluate(QM31, ppu, predecessor).allZero(),
    );
    predecessor = try liftRow(predecessor_values);
    predecessor.masked_previous[0] = QM31.zero();
    try std.testing.expect(
        !subject.evaluate(QM31, ppu, predecessor).allZero(),
    );

    predecessor = try liftRow(predecessor_values);
    ppu.semantic.interrupts[0] = QM31.zero();
    try std.testing.expect(
        !subject.evaluate(QM31, ppu, predecessor).allZero(),
    );
}

test "PPU IF witness orders requests and coalesces same-row dual edges" {
    const events = [_]ppu_binding.EventRow{
        dualEvent(7),
        statEvent(8),
        quietEvent(9),
    };
    var witness = try subject.generateWitness(
        std.testing.allocator,
        4,
        &events,
        &.{
            .{ .clock = 3, .value = 0x10 },
            .{ .clock = requestClock(7), .value = 0x13 },
            .{},
        },
    );
    defer witness.deinit();
    try std.testing.expectEqual(@as(usize, 16), witness.accesses.len);
    try std.testing.expectEqual(
        @as(u8, 0x13),
        witness.accesses[0].next_value,
    );
    try std.testing.expectEqual(
        @as(u8, 0x13),
        witness.accesses[1].next_value,
    );
    try std.testing.expectEqual(subject.Access{}, witness.accesses[2]);

    const storage = try core_air_utils.circleBitReversedIndex(4, 0);
    try std.testing.expectEqual(
        M31.fromCanonical(3),
        witness.main[subject.PREVIOUS_CLOCK_OFFSET][storage],
    );
    try std.testing.expectEqual(
        M31.zero(),
        witness.main[subject.MASKED_BITS_OFFSET][storage],
    );
    try std.testing.expectEqual(
        M31.zero(),
        witness.main[subject.MASKED_BITS_OFFSET + 1][storage],
    );

    try std.testing.expectError(
        error.PpuIfClockCollision,
        subject.generateWitness(
            std.testing.allocator,
            4,
            &.{ dualEvent(7), statEvent(7) },
            &.{
                .{ .clock = 3, .value = 0 },
                .{ .clock = 4, .value = 3 },
            },
        ),
    );
}

test "PPU IF host validation rejects forged binding and predecessor metadata" {
    var forged = dualEvent(7);
    forged.transition.interrupts.vblank = false;
    try std.testing.expectError(
        error.InvalidPpuBindingEvent,
        subject.accessForEvent(forged, .{}),
    );
    try std.testing.expectError(
        error.InvalidInactivePredecessor,
        subject.accessForEvent(
            quietEvent(8),
            .{ .clock = 1, .value = 2 },
        ),
    );
    var late = dualEvent(M31_MODULUS - 1);
    late.mcycle = M31_MODULUS - 1;
    try std.testing.expectError(
        error.NonCanonicalPpuIfClock,
        subject.accessForEvent(late, .{}),
    );
    try std.testing.expectError(
        error.InvalidPpuIfPredecessorClock,
        subject.accessForEvent(
            dualEvent(7),
            .{ .clock = requestClock(7), .value = 0 },
        ),
    );
}

test "PPU IF interaction cancels only the authenticated shared-memory update" {
    const relation = memory_lookup.Relation.dummy();
    const access = try subject.accessForEvent(
        dualEvent(7),
        .{ .clock = 3, .value = 0x04 },
    );
    var accesses = [_]subject.Access{.{}} ** 16;
    accesses[0] = access;
    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        &accesses,
        4,
        relation,
    );
    defer interaction.deinit();

    var total = interaction.claim;
    total = try subject.accumulate(
        total,
        boundaryPair(
            relation,
            3,
            0x04,
            requestClock(7),
            0x07,
        ),
    );
    try std.testing.expect(total.isZero());
    try std.testing.expect(!interaction.claim.isZero());

    const mutations = [_]subject.Access{
        .{
            .enabled = true,
            .vblank = true,
            .stat = true,
            .previous_clock = 2,
            .previous_value = 0x04,
            .clock = requestClock(7),
            .next_value = 0x07,
        },
        .{
            .enabled = true,
            .vblank = true,
            .stat = true,
            .previous_clock = 3,
            .previous_value = 0,
            .clock = requestClock(7),
            .next_value = 3,
        },
        .{
            .enabled = true,
            .vblank = false,
            .stat = true,
            .previous_clock = 3,
            .previous_value = 0x04,
            .clock = requestClock(7),
            .next_value = 0x06,
        },
    };
    for (mutations) |mutation| {
        var forged_total = try subject.accumulate(
            QM31.zero(),
            try subject.pair(mutation, relation),
        );
        forged_total = try subject.accumulate(
            forged_total,
            boundaryPair(
                relation,
                3,
                0x04,
                requestClock(7),
                0x07,
            ),
        );
        try std.testing.expect(!forged_total.isZero());
    }

    const wrong_address = memory_lookup.RowPair{
        .n1 = QM31.one().neg(),
        .d1 = relation.combine(q(0xff0e), q(3), q(0x04)),
        .n2 = QM31.one(),
        .d2 = relation.combine(
            q(0xff0e),
            q(requestClock(7)),
            q(0x07),
        ),
    };
    var wrong_total = try subject.accumulate(
        QM31.zero(),
        wrong_address,
    );
    wrong_total = try subject.accumulate(
        wrong_total,
        boundaryPair(
            relation,
            3,
            0x04,
            requestClock(7),
            0x07,
        ),
    );
    try std.testing.expect(!wrong_total.isZero());
    const omitted = try subject.accumulate(
        QM31.zero(),
        boundaryPair(
            relation,
            3,
            0x04,
            requestClock(7),
            0x07,
        ),
    );
    try std.testing.expect(!omitted.isZero());
}

test "PPU IF inactive rows are neutral and witness garbage is rejected" {
    const ppu = try liftPpu(ppu_binding.inactiveColumns());
    const row = try liftRow(subject.inactiveColumns());
    try std.testing.expect(subject.evaluate(QM31, ppu, row).allZero());
    const neutral = try subject.pair(
        .{},
        memory_lookup.Relation.dummy(),
    );
    try std.testing.expect(neutral.n1.isZero());
    try std.testing.expect(neutral.n2.isZero());

    try std.testing.expectError(
        error.InvalidPpuIfValueTransition,
        subject.columnsForAccess(.{
            .enabled = true,
            .vblank = true,
            .previous_clock = 3,
            .clock = requestClock(7),
            .next_value = 0,
        }),
    );
    try std.testing.expectError(
        error.InvalidInactiveAccess,
        subject.columnsForAccess(.{ .stat = true }),
    );
    try std.testing.expectError(
        error.InvalidLogSize,
        subject.generateWitness(
            std.testing.allocator,
            3,
            &.{quietEvent(0)},
            &.{.{}},
        ),
    );
}

pub fn dualEvent(mcycle: u32) ppu_binding.EventRow {
    const before = ppu_runner.State{
        .lcd_enabled = true,
        .line = ppu_runner.VISIBLE_LINES,
        .dot = 0,
        .stat_enable = 0x4,
    };
    const transition = ppu_runner.Transition.apply(
        before,
        .tick_dot,
    ) catch unreachable;
    std.debug.assert(transition.interrupts.vblank);
    std.debug.assert(transition.interrupts.stat);
    return .{
        .mcycle = mcycle,
        .transition = transition,
        .lcdc_before = 0x80,
        .lcdc_after = 0x80,
        .dot_phase = 0,
    };
}

pub fn statEvent(mcycle: u32) ppu_binding.EventRow {
    return eventAt(mcycle, 1, true);
}

fn quietEvent(mcycle: u32) ppu_binding.EventRow {
    const transition = ppu_runner.Transition.apply(
        .{},
        .tick_dot,
    ) catch unreachable;
    return .{
        .mcycle = mcycle,
        .transition = transition,
        .lcdc_before = 0,
        .lcdc_after = 0,
        .dot_phase = 0,
    };
}

fn eventAt(
    mcycle: u32,
    line: u8,
    enable_mode2: bool,
) ppu_binding.EventRow {
    const before = ppu_runner.State{
        .lcd_enabled = true,
        .line = line,
        .dot = ppu_runner.DOTS_PER_LINE - 1,
        .stat_enable = if (enable_mode2) 0x4 else 0,
        .coincidence = false,
        .lyc_interrupt_line = false,
        .stat_interrupt_line = false,
    };
    const transition = ppu_runner.Transition.apply(
        before,
        .tick_dot,
    ) catch unreachable;
    std.debug.assert(!transition.interrupts.vblank);
    std.debug.assert(transition.interrupts.stat == enable_mode2);
    return .{
        .mcycle = mcycle,
        .transition = transition,
        .lcdc_before = 0x80,
        .lcdc_after = 0x80,
        .dot_phase = 3,
    };
}

fn requestClock(mcycle: u32) u32 {
    return memory_lookup.memory_clock.phaseClock(
        mcycle,
        memory_lookup.memory_clock.PPU_PHASE,
    ) catch unreachable;
}

fn liftPpu(
    values: [ppu_binding.N_MAIN_COLUMNS]M31,
) !subject.PpuRow(QM31) {
    var lifted: [ppu_binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*target, source|
        target.* = QM31.fromBase(source);
    return subject.PpuRow(QM31).fromColumns(&lifted);
}

fn liftRow(
    values: [subject.N_MAIN_COLUMNS]M31,
) !subject.Row(QM31) {
    var lifted: [subject.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*target, source|
        target.* = QM31.fromBase(source);
    return subject.Row(QM31).fromColumns(&lifted);
}

fn boundaryPair(
    relation: memory_lookup.Relation,
    initial_clock: u32,
    initial_value: u8,
    final_clock: u32,
    final_value: u8,
) memory_lookup.RowPair {
    return .{
        .n1 = QM31.one(),
        .d1 = relation.combine(
            q(runner.cartridge_memory.INTERRUPT_FLAGS),
            q(initial_clock),
            q(initial_value),
        ),
        .n2 = QM31.one().neg(),
        .d2 = relation.combine(
            q(runner.cartridge_memory.INTERRUPT_FLAGS),
            q(final_clock),
            q(final_value),
        ),
    };
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}
