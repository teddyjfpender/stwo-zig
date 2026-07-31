const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const binding = @import("ppu_binding.zig");
const component_air = @import("ppu_binding_component.zig");

test "SCY SCX and WY latches are chained and endpoint bound" {
    const cycles = [_]binding.Cycle{
        write(.scy, 0x12),
        read(.scy, 0x12),
        write(.scx, 0x34),
        read(.scx, 0x34),
        write(.wy, 0x56),
        read(.wy, 0x56),
    };
    var trace = try binding.generateTrace(
        std.testing.allocator,
        20,
        26,
        .{},
        &cycles,
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 24), trace.rows.len);
    try std.testing.expectEqual(@as(u8, 0x12), trace.final_state.scy);
    try std.testing.expectEqual(@as(u8, 0x34), trace.final_state.scx);
    try std.testing.expectEqual(@as(u8, 0x56), trace.final_state.wy);

    const component = componentFor(trace);
    try expectTrace(&component, trace);

    const first = try lift(try binding.columns(trace.rows[0]));
    const second = try lift(try binding.columns(trace.rows[1]));
    var forged = first;
    forged[binding.LATCH_WRITE_VALUE_OFFSET] =
        QM31.fromBase(M31.fromCanonical(0x13));
    try expect(&component, &forged, &second, true, false);

    forged = first;
    forged[binding.LATCH_WRITE_MARKER_OFFSET] = QM31.zero();
    forged[binding.LATCH_WRITE_MARKER_OFFSET + 1] = QM31.one();
    try expect(&component, &forged, &second, true, false);

    forged = first;
    forged[binding.LATCH_AFTER_OFFSET] =
        forged[binding.LATCH_AFTER_OFFSET].add(QM31.one());
    try expect(&component, &forged, &second, true, false);

    const before_read = try lift(try binding.columns(trace.rows[3]));
    var forged_read = try lift(try binding.columns(trace.rows[4]));
    forged_read[binding.READ_VALUE_OFFSET + 1] = QM31.zero();
    try expect(&component, &before_read, &forged_read, false, false);

    var forged_initial = component;
    forged_initial.initial.scy = 1;
    try expect(&forged_initial, &first, &second, true, false);

    const inactive = [_]QM31{QM31.zero()} ** binding.N_MAIN_COLUMNS;
    const last = try lift(try binding.columns(trace.rows[trace.rows.len - 1]));
    var forged_final = component;
    forged_final.final.wy ^= 1;
    try expect(&forged_final, &last, &inactive, false, false);
}

test "latch write row shape rejects phase and state mutations" {
    var trace = try binding.generateTrace(
        std.testing.allocator,
        0,
        1,
        .{},
        &.{write(.scy, 0xa5)},
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(?u2, 0), trace.rows[0].dot_phase);
    try std.testing.expectEqual(
        @as(?binding.RegisterAccess, .{ .register = .scy, .value = 0xa5 }),
        trace.rows[0].latch_write,
    );
    var malformed = trace.rows[0];
    malformed.dot_phase = 1;
    try std.testing.expectError(
        error.InvalidPpuAccessPhase,
        binding.columns(malformed),
    );
    malformed = trace.rows[0];
    malformed.latches_after[0] ^= 1;
    try std.testing.expectError(
        error.InvalidPpuLatchState,
        binding.columns(malformed),
    );
    malformed = trace.rows[0];
    malformed.latch_write.?.register = .lcdc;
    try std.testing.expectError(
        error.InvalidPpuLatchWrite,
        binding.columns(malformed),
    );
}

fn write(register: binding.Register, value: u8) binding.Cycle {
    return .{ .access = .{ .write = .{
        .register = register,
        .value = value,
    } } };
}

fn read(register: binding.Register, value: u8) binding.Cycle {
    return .{ .access = .{ .read = .{
        .register = register,
        .value = value,
    } } };
}

fn componentFor(trace: binding.Trace) component_air.Component {
    const first = trace.rows[0];
    return .{
        .log_size = 5,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial_mcycle = first.mcycle,
        .final_mcycle = trace.final_mcycle,
        .initial = .{
            .timing = first.transition.before,
            .lcdc = first.lcdc_before,
            .scy = first.latches_before[0],
            .scx = first.latches_before[1],
            .wy = first.latches_before[2],
        },
        .final = trace.final_state,
    };
}

fn expectTrace(
    component: *const component_air.Component,
    trace: binding.Trace,
) !void {
    const inactive = [_]QM31{QM31.zero()} ** binding.N_MAIN_COLUMNS;
    for (trace.rows, 0..) |row, index| {
        const current = try lift(try binding.columns(row));
        const next = if (index + 1 < trace.rows.len)
            try lift(try binding.columns(trace.rows[index + 1]))
        else
            inactive;
        try expect(component, &current, &next, index == 0, true);
    }
}

fn expect(
    component: *const component_air.Component,
    current: []const QM31,
    next: []const QM31,
    is_first: bool,
    valid: bool,
) !void {
    const evaluation = try component.evaluateRow(
        current,
        next,
        if (is_first) QM31.one() else QM31.zero(),
        QM31.zero(),
    );
    try std.testing.expectEqual(valid, evaluation.allZero());
}

fn lift(
    values: [binding.N_MAIN_COLUMNS]M31,
) ![binding.N_MAIN_COLUMNS]QM31 {
    var result: [binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, values) |*target, source|
        target.* = QM31.fromBase(source);
    return result;
}
