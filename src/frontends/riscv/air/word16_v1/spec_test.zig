//! LOCAL ALGEBRA ONLY, run after the full-block campaign was stopped. Tests exercise
//! local equations + exact fixed-table predicates, NOT original/global proof
//! closure, a generated degree audit, or recursive soundness qualification.
const std = @import("std");
const A = @import("abi.zig");
const R = @import("relations.zig");
const Arithmetic = @import("arithmetic.zig");
const Logic = @import("logic.zig");
const LS = @import("load_store.zig");
const W = @import("writer.zig");
const Range = @import("range_plan.zig");
const Legacy = @import("legacy_adapter.zig");
pub const Checks = struct {
    bad: bool = false,
    degree: u8 = 0,
    pub fn add(self: *@This(), residual: A.M, degree: u8) void {
        self.bad = self.bad or !residual.isZero();
        self.degree = @max(self.degree, degree);
    }
};
pub const Events = struct {
    bad: bool = false,
    counts: Range.Requests = .{ .range16 = 0, .byte_pairs = 0, .bitwise = 0, .clock_orders = 0 },
    fn enabled(self: *@This(), active: A.M) bool {
        if (active.v > 1) self.bad = true;
        return active.v == 1;
    }
    pub fn range16(self: *@This(), active: A.M, value: A.M) void {
        if (!self.enabled(active)) return;
        self.bad = self.bad or value.v > 65535;
        self.counts.range16 += 1;
    }
    pub fn range8_8(self: *@This(), active: A.M, values: [2]A.M) void {
        if (!self.enabled(active)) return;
        self.bad = self.bad or values[0].v > 255 or values[1].v > 255;
        self.counts.byte_pairs += 1;
    }
    pub fn bitwise(self: *@This(), active: A.M, operation: u32, values: [3]A.M) void {
        if (!self.enabled(active)) return;
        if (values[0].v > 255 or values[1].v > 255 or values[2].v > 255) {
            self.bad = true;
            return;
        }
        const expected = switch (operation) {
            5 => values[0].v ^ values[1].v,
            8 => values[0].v | values[1].v,
            9 => values[0].v & values[1].v,
            else => {
                self.bad = true;
                return;
            },
        };
        self.bad = self.bad or values[2].v != expected;
        self.counts.bitwise += 1;
    }
    pub fn clock(self: *@This(), previous: A.M, current: A.M, active: A.M) void {
        if (!self.enabled(active)) return;
        self.bad = self.bad or previous.v >= current.v or current.v % 4 == 0 or (previous.v != 0 and previous.v % 4 == 0);
        self.counts.clock_orders += 1;
    }
    // Deliberately OPEN: no claim that these local tests close a public
    // register, RAM, ROM or CPU relation.
    pub fn access(_: *@This(), comptime _: R.Domain, _: A.M, _: R.Tuple(A.M)) void {}
    pub fn cpu(_: *@This(), _: A.M, _: [2]A.M) void {}
    pub fn rom(_: *@This(), _: A.M, _: A.M, _: u32, _: A.M, _: A.M, _: A.M) void {}
};
fn clean(checks: Checks, events: Events, operation: Range.Operation) !void {
    try std.testing.expect(!checks.bad);
    try std.testing.expect(!events.bad);
    try std.testing.expect(checks.degree <= 4);
    try std.testing.expectEqualDeep(Range.perActiveRow(operation), events.counts);
}
test "word16 source-only local add sub addi wrap and x0 equations" {
    inline for (.{ Arithmetic.RegOp.add, Arithmetic.RegOp.sub }) |operation| {
        for ([_]u32{ 0, 1, 65535, 65536, 0xffffffff, 0x80000000 }) |left| {
            for ([_]u32{ 0, 1, 65535, 0xffffffff }) |right| {
                var checks: Checks = .{};
                var events: Events = .{};
                const row = try W.arithmetic(operation, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = left }, .{ .address = 2, .previous_clock = 0, .value = right }, .{ .address = 3, .previous_clock = 0, .before = 0x12345678 }, .{});
                Arithmetic.register(A.M, operation, row, A.M.one(), &checks, &events);
                try clean(checks, events, if (operation == .add) .add else .sub);
            }
        }
    }
    for ([_]i32{ -2048, -1, 0, 1, 2047 }) |immediate| {
        var checks: Checks = .{};
        var events: Events = .{};
        const row = try W.addi(1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0xffffffff }, .{ .address = 0, .previous_clock = 0, .before = 0 }, immediate, .{});
        Arithmetic.immediate(A.M, row, A.M.one(), &checks, &events);
        try clean(checks, events, .addi);
    }
}
test "word16 source-only all load store offsets signs and request inventories" {
    inline for (comptime std.meta.tags(LS.Load)) |operation| {
        for (0..4) |offset| {
            if ((operation == .lw and offset != 0) or ((operation == .lh or operation == .lhu) and offset % 2 != 0)) continue;
            for ([_]u32{ 0, 0x80, 0x8000, 0xffffffff }) |before| {
                var checks: Checks = .{};
                var events: Events = .{};
                const row = try W.load(operation, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x4000 + @as(u32, @intCast(offset)) }, .{ .address = 2, .previous_clock = 0, .before = 0x12345678 }, -16, .{ .previous_clock = 0, .before = before }, .{ .address = 0x8000 }, .{});
                LS.load(A.M, operation, row, A.M.one(), .{ .address = 0x8000 }, &checks, &events);
                try clean(checks, events, switch (operation) {
                    .lb => .lb,
                    .lbu => .lbu,
                    .lh => .lh,
                    .lhu => .lhu,
                    .lw => .lw,
                });
            }
        }
    }
    inline for (comptime std.meta.tags(LS.Store)) |operation| {
        for (0..4) |offset| {
            if ((operation == .sw and offset != 0) or (operation == .sh and offset % 2 != 0)) continue;
            var checks: Checks = .{};
            var events: Events = .{};
            const row = try W.store(operation, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x4000 + @as(u32, @intCast(offset)) }, .{ .address = 2, .previous_clock = 0, .value = 0x89abcdef }, -16, .{ .previous_clock = 0, .before = 0x12345678 }, .{ .address = 0x8000 }, .{});
            LS.store(A.M, operation, row, A.M.one(), .{ .address = 0x8000 }, &checks, &events);
            try clean(checks, events, switch (operation) {
                .sb => .sb,
                .sh => .sh,
                .sw => .sw,
            });
        }
    }
}
test "word16 source-only register and signed immediate bitwise equations" {
    inline for (comptime std.meta.tags(Logic.Op)) |operation| {
        var checks: Checks = .{};
        var events: Events = .{};
        const row = try W.logic(operation, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x89abcdef }, .{ .address = 2, .previous_clock = 0, .value = 0x12345678 }, .{ .address = 3, .previous_clock = 0, .before = 0 }, .{});
        Logic.evaluate(A.M, operation, row, A.M.one(), &checks, &events);
        try clean(checks, events, switch (operation) {
            .xor => .xor,
            .or_ => .or_,
            .and_ => .and_,
        });
    }
    inline for (comptime std.meta.tags(Logic.ImmediateOp)) |operation| {
        for ([_]i32{ -2048, -1, 0, 2047 }) |immediate| {
            var checks: Checks = .{};
            var events: Events = .{};
            const row = try W.logicImmediate(operation, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x89abcdef }, .{ .address = 0, .previous_clock = 0, .before = 0 }, immediate, .{});
            Logic.immediate(A.M, operation, row, A.M.one(), &checks, &events);
            try clean(checks, events, switch (operation) {
                .xor => .xori,
                .or_ => .ori,
                .and_ => .andi,
            });
        }
    }
}
test "word16 source-only wrong sign unchanged-byte corruption and inactive row reject" {
    var row = try W.load(.lb, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x4000 }, .{ .address = 2, .previous_clock = 0, .before = 0 }, 0, .{ .previous_clock = 0, .before = 0x80 }, .{ .address = 0x8000 }, .{});
    row.sign = A.M.zero();
    row.result = A.Word(A.M).fromU32(0x80);
    row.destination.after = row.result;
    var checks: Checks = .{};
    var events: Events = .{};
    LS.load(A.M, .lb, row, A.M.one(), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(events.bad);
    var stored = try W.store(.sb, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x4000 }, .{ .address = 2, .previous_clock = 0, .value = 7 }, 0, .{ .previous_clock = 0, .before = 0x12345678 }, .{ .address = 0x8000 }, .{});
    stored.after_bytes[1] = stored.after_bytes[1].add(A.M.one());
    stored.memory.after = A.Word(A.M).packedBytes(stored.after_bytes);
    checks = .{};
    events = .{};
    LS.store(A.M, .sb, stored, A.M.one(), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(checks.bad);
    var inactive = std.mem.zeroes(Arithmetic.RegisterRow(A.M));
    inactive.clock = A.M.one();
    checks = .{};
    events = .{};
    Arithmetic.register(A.M, .add, inactive, A.M.zero(), &checks, &events);
    try std.testing.expect(checks.bad);
}
test "word16 source-only transient halt and noncanonical output limb reject" {
    const halted = try W.store(.sw, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x4000 }, .{ .address = 2, .previous_clock = 0, .value = 1 }, 0, .{ .previous_clock = 0, .before = 0 }, .{ .address = 0x4000 }, .{});
    var checks: Checks = .{};
    var events: Events = .{};
    LS.store(A.M, .sw, halted, A.M.one(), .{ .address = 0x4000 }, &checks, &events);
    try std.testing.expect(checks.bad);
    var arithmetic = try W.arithmetic(.add, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 1 }, .{ .address = 2, .previous_clock = 0, .value = 2 }, .{ .address = 3, .previous_clock = 0, .before = 0 }, .{});
    arithmetic.result.lo = A.c(A.M, 65536);
    arithmetic.destination.after = arithmetic.result;
    checks = .{};
    events = .{};
    Arithmetic.register(A.M, .add, arithmetic, A.M.one(), &checks, &events);
    try std.testing.expect(events.bad);
}
test "word16 source-only inverse-four quarter alias requires unscaled range rejection" {
    var row = try W.load(.lw, 1, 0x2000, .{ .address = 1, .previous_clock = 0, .value = 0x4000 }, .{ .address = 2, .previous_clock = 0, .before = 0 }, 0, .{ .previous_clock = 0, .before = 7 }, .{ .address = 0x8000 }, .{});
    row.base.value = A.Word(A.M).fromU32(1);
    row.address.quarter_low14 = try A.c(A.M, 4).inv();
    row.memory.address = A.M.one();
    row.halt_auxiliary = .{ A.M.zero(), try A.M.one().sub(A.c(A.M, 0x8000)).inv() };
    // Every direct polynomial, including address, aligned tuple and HALT
    // bindings, is satisfiable. The scaled quarter is exactly 1 in M31.
    try std.testing.expectEqual(@as(u32, 1), row.address.quarter_low14.mul(A.c(A.M, 4)).v);
    var checks: Checks = .{};
    var events: Events = .{};
    LS.load(A.M, .lw, row, A.M.one(), .{ .address = 0x8000 }, &checks, &events);
    try std.testing.expect(!checks.bad);
    try std.testing.expect(events.bad);
    try std.testing.expectEqual(@as(u32, 4), events.counts.range16);
}
test "word16 source-only legacy scaled-immediate alias requires unscaled range rejection" {
    const low12 = try A.c(A.M, 16).inv();
    var checks: Checks = .{};
    var events: Events = .{};
    _ = Legacy.signedImmediate(A.M, low12, A.M.zero(), A.M.one(), &checks, &events);
    try std.testing.expect(!checks.bad);
    try std.testing.expect(events.bad);
    try std.testing.expectEqual(Legacy.signed_immediate_range16_requests, events.counts.range16);
    try std.testing.expectEqual(@as(u32, 1), low12.mul(A.c(A.M, 16)).v);
    try std.testing.expectEqual(@as(u32, 2), low12.mul(A.c(A.M, 32)).v);
}
