const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const binding = @import("ppu_binding.zig");
const subject = @import("ppu_binding_component.zig");

const PPU_INTERRUPT_OFFSET: usize = 1 + 88;

test "PPU binding permits one dual IF request and rejects a second per M-cycle" {
    const initial = binding.State{
        .timing = .{
            .lcd_enabled = true,
            .line = 144,
            .dot = 0,
            .lyc = 0xff,
            .stat_enable = 0x4,
        },
        .lcdc = 0x80,
    };
    var trace = try binding.generateTrace(
        std.testing.allocator,
        0,
        2,
        initial,
        &.{ .{}, .{} },
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expect(trace.rows[0].transition.interrupts.vblank);
    try std.testing.expect(trace.rows[0].transition.interrupts.stat);

    var witness = try binding.generateWitness(std.testing.allocator, trace);
    defer witness.deinit();
    for (trace.rows, 0..) |_, index| {
        const storage = try core.air.utils.circleBitReversedIndex(
            witness.log_size,
            index,
        );
        try std.testing.expectEqual(
            index > 0 and index < 4,
            witness.main[binding.REQUEST_SEEN_OFFSET][storage].isOne(),
        );
    }

    const component = componentFor(trace);
    const first = try columns(trace, 0);
    const second = try columns(trace, 1);
    try expect(&component, &first, &second, true, true);

    var missing_seen = second;
    missing_seen[binding.REQUEST_SEEN_OFFSET] = QM31.zero();
    try expect(&component, &first, &missing_seen, true, false);

    var second_request = second;
    second_request[PPU_INTERRUPT_OFFSET] = QM31.one();
    const third = try columns(trace, 2);
    try expect(&component, &second_request, &third, false, false);

    const phase_three = try columns(trace, 3);
    var bad_reset = try columns(trace, 4);
    bad_reset[binding.REQUEST_SEEN_OFFSET] = QM31.one();
    try expect(&component, &phase_three, &bad_reset, false, false);
}

fn componentFor(trace: binding.Trace) subject.Component {
    return .{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial_mcycle = trace.rows[0].mcycle,
        .final_mcycle = trace.final_mcycle,
        .initial = .{
            .timing = trace.rows[0].transition.before,
            .lcdc = trace.rows[0].lcdc_before,
        },
        .final = trace.final_state,
    };
}

fn columns(
    trace: binding.Trace,
    index: usize,
) ![binding.N_MAIN_COLUMNS]QM31 {
    var base = try binding.columns(trace.rows[index]);
    const mcycle = trace.rows[index].mcycle;
    var seen = false;
    for (trace.rows[0..index]) |row| {
        if (row.mcycle != mcycle) continue;
        seen = seen or row.transition.interrupts.vblank or
            row.transition.interrupts.stat;
    }
    base[binding.REQUEST_SEEN_OFFSET] =
        M31.fromCanonical(@intFromBool(seen));
    var result: [binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, base) |*target, value|
        target.* = QM31.fromBase(value);
    return result;
}

fn expect(
    component: *const subject.Component,
    current: []const QM31,
    next: []const QM31,
    is_first: bool,
    accepted: bool,
) !void {
    const evaluation = try component.evaluateRow(
        current,
        next,
        if (is_first) QM31.one() else QM31.zero(),
        QM31.zero(),
    );
    try std.testing.expectEqual(accepted, evaluation.allZero());
}
