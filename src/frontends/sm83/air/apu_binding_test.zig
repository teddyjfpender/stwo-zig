const std = @import("std");
const core = @import("stwo_core");
const binding = @import("apu_binding.zig");
const apu = @import("../runner/apu_mmio.zig");

test "APU binding read-mask table stays equivalent to runner oracle" {
    var state = apu.State{ .enabled = true };
    for (0..binding.layout.REGISTER_COUNT) |register| {
        const address: u16 = @intCast(apu.FIRST_ADDRESS + register);
        if (address == apu.NR52 or address >= apu.WAVE_START or
            address == 0xff15 or address == 0xff1f or
            (address >= 0xff27 and address <= 0xff2f)) continue;
        for (0..256) |raw| {
            const value: u8 = @intCast(raw);
            state.registers[register] = value;
            try std.testing.expectEqual(
                value | binding.READ_MASKS[register],
                try state.read(address),
            );
        }
    }
}

test "APU binding builds one row per supplied access and chains state" {
    const events = [_]apu.Event{
        .{ .write = .{ .address = apu.NR11, .value = 0xff } },
        .{ .write = .{ .address = apu.NR52, .value = 0x80 } },
        .{ .write = .{ .address = 0xff12, .value = 0xf3 } },
        .{ .read = 0xff12 },
        .{ .write = .{ .address = apu.WAVE_START, .value = 0x42 } },
        .{ .write = .{ .address = apu.NR52, .value = 0 } },
    };
    var trace = try binding.generateTrace(
        std.testing.allocator,
        .{},
        &events,
    );
    defer trace.deinit(std.testing.allocator);
    try binding.validateTrace(trace);
    try std.testing.expectEqual(events.len, trace.rows.len);
    try std.testing.expect(!trace.final_state.enabled);
    try std.testing.expectEqual(
        @as(u8, 0x42),
        trace.final_state.registers[binding.registerIndex(apu.WAVE_START)],
    );

    var witness = try binding.generateWitness(std.testing.allocator, trace);
    defer witness.deinit();
    try std.testing.expectEqual(events.len, witness.event_count);
    try std.testing.expectEqual(@as(u32, 4), witness.log_size);
    var active_rows: usize = 0;
    for (witness.main[binding.layout.ACTIVE_OFFSET]) |value|
        active_rows += @intFromBool(value.eql(core.fields.m31.M31.one()));
    try std.testing.expectEqual(events.len, active_rows);
}

test "APU binding represents an empty segment with inactive padding" {
    var initial = apu.State{};
    initial.registers[binding.registerIndex(apu.WAVE_START)] = 0x42;
    var trace = try binding.generateTrace(
        std.testing.allocator,
        initial,
        &.{},
    );
    defer trace.deinit(std.testing.allocator);
    try binding.validateTrace(trace);
    try std.testing.expectEqual(@as(usize, 0), trace.rows.len);
    try std.testing.expect(std.meta.eql(initial, trace.final_state));
    var witness = try binding.generateWitness(std.testing.allocator, trace);
    defer witness.deinit();
    try std.testing.expectEqual(@as(u32, 4), witness.log_size);
    try std.testing.expectEqual(@as(usize, 0), witness.event_count);
    for (witness.main) |column|
        for (column) |value|
            try std.testing.expect(value.eql(core.fields.m31.M31.zero()));
}

test "APU binding fails closed on opaque live state" {
    var unknown_status = apu.State{
        .enabled = true,
        .channel_status = null,
    };
    try std.testing.expectError(
        error.UnknownChannelStatus,
        binding.generateTrace(
            std.testing.allocator,
            unknown_status,
            &.{.{ .read = apu.NR52 }},
        ),
    );
    unknown_status.wave_access = .unknown;
    try std.testing.expectError(
        error.UnknownWavePhase,
        binding.generateTrace(
            std.testing.allocator,
            unknown_status,
            &.{.{ .write = .{
                .address = apu.WAVE_START,
                .value = 1,
            } }},
        ),
    );
}

test "APU binding rejects disconnected and forged host transitions" {
    const first = try apu.Transition.apply(.{}, .{ .write = .{
        .address = apu.NR11,
        .value = 0x3f,
    } });
    const second = try apu.Transition.apply(first.after, .{ .write = .{
        .address = apu.NR52,
        .value = 0x80,
    } });
    var rows = [_]apu.Transition{ first, second };
    var trace = binding.Trace{
        .rows = &rows,
        .initial_state = first.before,
        .final_state = second.after,
    };
    try binding.validateTrace(trace);
    trace.rows[1].before.registers[0] ^= 1;
    try std.testing.expectError(
        error.InvalidTransition,
        binding.validateTrace(trace),
    );
}
