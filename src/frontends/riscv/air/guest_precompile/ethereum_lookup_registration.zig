//! Transactional fixed-table registration for the combined Ethereum callers.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const table_counter = @import("../lookups/tables/counter.zig");
const table_schema = @import("../lookups/tables/schema.zig");
const keccak_calls = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const recovery_calls = @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig");

pub const Context = struct {
    keccak: []const keccak_calls.Record,
    recovery: []const recovery_calls.Record,

    pub fn register(self: *const Context, counters: *table_counter.Set) !void {
        try validateCounterSet(counters);
        try visit(false, self, null);
        visit(true, self, counters) catch unreachable;
    }

    pub fn erased(
        context_ptr: *const anyopaque,
        counters: *table_counter.Set,
    ) anyerror!void {
        const self: *const Context = @ptrCast(@alignCast(context_ptr));
        try self.register(counters);
    }
};

fn visit(
    comptime apply: bool,
    context: *const Context,
    counters: ?*table_counter.Set,
) !void {
    for (context.keccak) |record| {
        try range20(
            apply,
            try gap(record.execution_clock, 1, record.pointer_previous_clock),
            counters,
        );
        for (record.memory_previous_clocks) |previous| {
            try range20(
                apply,
                try gap(record.execution_clock, 2, previous),
                counters,
            );
        }
        try span(
            apply,
            record.state_ptr / 4 + @as(u32, keccak_calls.word_count - 1),
            record.state_ptr,
            counters,
        );
    }
    for (context.recovery) |record| {
        try range20(
            apply,
            try gap(record.execution_clock, 1, record.pointer_previous_clock),
            counters,
        );
        for (record.input_previous_clocks) |previous| {
            try range20(
                apply,
                try gap(record.execution_clock, 2, previous),
                counters,
            );
        }
        for (record.output_previous_clocks) |previous| {
            try range20(
                apply,
                try gap(record.execution_clock, 2, previous),
                counters,
            );
        }
        try span(
            apply,
            record.io_ptr / 4 + @as(
                u32,
                record.input_previous_clocks.len +
                    record.output_previous_clocks.len - 1,
            ),
            record.io_ptr,
            counters,
        );
    }
}

fn gap(clock: u32, ordinal: u8, previous: u32) !u32 {
    if (clock == 0) return error.InvalidExecutionClock;
    const current = (@as(u64, clock) - 1) * 4 + ordinal;
    if (current <= previous) return error.InvalidPreviousClock;
    const value = current - previous - 1;
    if (value >= (1 << 20)) return error.ClockGapOutOfRange;
    return @intCast(value);
}

fn span(
    comptime apply: bool,
    last_word: u32,
    pointer: u32,
    counters: ?*table_counter.Set,
) !void {
    try request(apply, .range_check_8_8, &.{
        M31.fromCanonical(@intCast(last_word & 0xff)),
        M31.fromCanonical(@intCast((last_word >> 8) & 0xff)),
    }, counters);
    try request(apply, .range_check_8_8_4, &.{
        M31.fromCanonical(@intCast((last_word >> 16) & 0xff)),
        M31.fromCanonical(@intCast(((pointer >> 24) & 0xff) * 4)),
        M31.fromCanonical(@intCast((last_word >> 24) & 0x0f)),
    }, counters);
}

fn range20(
    comptime apply: bool,
    value: u32,
    counters: ?*table_counter.Set,
) !void {
    try request(
        apply,
        .range_check_20,
        &.{M31.fromCanonical(value)},
        counters,
    );
}

fn request(
    comptime apply: bool,
    kind: table_schema.Kind,
    tuple: []const M31,
    counters: ?*table_counter.Set,
) !void {
    const index = if (comptime apply)
        table_schema.indexBase(kind, tuple) catch unreachable
    else
        try table_schema.indexBase(kind, tuple);
    if (comptime apply) {
        const value = &counters.?.get(kind).values[index];
        value.* = value.sub(M31.one());
    }
}

fn validateCounterSet(counters: *const table_counter.Set) !void {
    for (&counters.counters, 0..) |*counter, index| {
        const kind: table_schema.Kind = @enumFromInt(index);
        if (counter.kind != kind or counter.values.len != table_schema.size(kind))
            return error.InvalidCounterSet;
    }
}

test "Ethereum lookup registration is transactional and exact" {
    const allocator = std.testing.allocator;
    var counters = try table_counter.Set.init(allocator);
    defer counters.deinit(allocator);
    const keccak = [_]keccak_calls.Record{.{
        .execution_clock = 5,
        .pc = 0x1000,
        .state_ptr = 0x4000,
        .pointer_register = 5,
        .pointer_previous_clock = 0,
        .input = @splat(0),
        .output = @splat(0),
        .memory_previous_clocks = @splat(0),
    }};
    const recovery = [_]recovery_calls.Record{.{
        .execution_clock = 7,
        .pc = 0x1004,
        .io_ptr = 0x5000,
        .pointer_register = 6,
        .pointer_previous_clock = 0,
        .digest_big_endian = @splat(0),
        .r_big_endian = @splat(1),
        .s_big_endian = @splat(2),
        .recovery_id = 1,
        .public_key_xy_big_endian = @splat(3),
        .status = 1,
        .input_previous_clocks = @splat(0),
        .output_previous_words = @splat(0),
        .output_previous_clocks = @splat(0),
    }};
    const context = Context{ .keccak = &keccak, .recovery = &recovery };
    try context.register(&counters);
    try std.testing.expectEqual(
        M31.fromCanonical(m31Modulus() - 94),
        counters.get(.range_check_20).signedTotal(),
    );
    try std.testing.expectEqual(
        M31.fromCanonical(m31Modulus() - 2),
        counters.get(.range_check_8_8).signedTotal(),
    );

    var malformed = keccak;
    malformed[0].pointer_previous_clock = 100;
    const before = counters.get(.range_check_20).signedTotal();
    try std.testing.expectError(
        error.InvalidPreviousClock,
        (Context{ .keccak = &malformed, .recovery = &recovery }).register(&counters),
    );
    try std.testing.expect(before.eql(counters.get(.range_check_20).signedTotal()));
}

fn m31Modulus() u32 {
    return @import("stwo_core").fields.m31.Modulus;
}
