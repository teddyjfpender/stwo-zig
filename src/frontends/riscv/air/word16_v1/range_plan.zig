//! Bounded natural witness counters and exact semantic request census.
//! These are NOT proof receipts. A future range AIR must authenticate all
//! multiplicities/physical sums and close these requests under the SAME draw.
const std = @import("std");
const A = @import("abi.zig");
pub const table_rows: usize = 1 << 16;
pub const Requests = struct { range16: u32, byte_pairs: u32, bitwise: u32, clock_orders: u32 };
pub const Operation = enum { add, sub, addi, xor, or_, and_, xori, ori, andi, lw, lb, lbu, lh, lhu, sw, sb, sh };
pub fn perActiveRow(operation: Operation) Requests {
    return switch (operation) {
        .add, .sub => .{ .range16 = 2, .byte_pairs = 0, .bitwise = 0, .clock_orders = 3 },
        .addi => .{ .range16 = 2, .byte_pairs = 0, .bitwise = 0, .clock_orders = 2 },
        .xor, .or_, .and_ => .{ .range16 = 0, .byte_pairs = 0, .bitwise = 4, .clock_orders = 3 },
        .xori, .ori, .andi => .{ .range16 = 2, .byte_pairs = 0, .bitwise = 4, .clock_orders = 2 },
        .lw, .sw => .{ .range16 = 4, .byte_pairs = 0, .bitwise = 0, .clock_orders = 3 },
        .lb, .lh => .{ .range16 = 5, .byte_pairs = 2, .bitwise = 0, .clock_orders = 3 },
        .lbu, .lhu => .{ .range16 = 4, .byte_pairs = 2, .bitwise = 0, .clock_orders = 3 },
        .sb, .sh => .{ .range16 = 4, .byte_pairs = 4, .bitwise = 0, .clock_orders = 3 },
    };
}
pub const Mass = struct {
    range16: u64 = 0,
    byte_pairs: u64 = 0,
    bitwise: u64 = 0,
    clock_orders: u64 = 0,
    pub fn add(self: *Mass, operation: Operation, rows: u32) !void {
        const per_row = perActiveRow(operation);
        var result = self.*;
        inline for (.{ "range16", "byte_pairs", "bitwise", "clock_orders" }) |name| {
            const next = try std.math.add(u64, @field(self, name), try std.math.mul(u64, rows, @field(per_row, name)));
            if (next >= 0x7fffffff) return error.Word16LookupMassWrap;
            @field(result, name) = next;
        }
        self.* = result;
    }
};
/// Host bounded multiplicities for the new canonical R16 and byte-pair tables.
/// Never accept these arrays/counts as a verifier receipt.
pub const Counter = struct {
    a: std.mem.Allocator,
    range16: []u32,
    byte_pairs: []u32,
    range16_mass: u32 = 0,
    byte_pair_mass: u32 = 0,
    max_requests: u32,
    pub fn init(a: std.mem.Allocator, max_requests: u32, byte_budget: usize) !Counter {
        if (max_requests == 0 or max_requests >= 0x7fffffff or byte_budget < 2 * table_rows * @sizeOf(u32)) return error.InvalidWord16CounterBounds;
        const range = try a.alloc(u32, table_rows);
        errdefer a.free(range);
        const pairs = try a.alloc(u32, table_rows);
        @memset(range, 0);
        @memset(pairs, 0);
        return .{ .a = a, .range16 = range, .byte_pairs = pairs, .max_requests = max_requests };
    }
    fn addCount(self: *Counter, table: []u32, mass: *u32, index: usize, multiplicity: u32) !void {
        const next_mass = try std.math.add(u32, mass.*, multiplicity);
        if (next_mass > self.max_requests or next_mass >= 0x7fffffff) return error.Word16CounterMassExceeded;
        const next_count = try std.math.add(u32, table[index], multiplicity);
        if (next_count >= 0x7fffffff) return error.Word16CounterMassExceeded;
        table[index] = next_count;
        mass.* = next_mass;
    }
    pub fn addRange16(self: *Counter, value: u32, multiplicity: u32) !void {
        if (value >= table_rows) return error.NonCanonicalWord16RangeRequest;
        try self.addCount(self.range16, &self.range16_mass, value, multiplicity);
    }
    pub fn addBytePair(self: *Counter, first: u8, second: u8, multiplicity: u32) !void {
        try self.addCount(self.byte_pairs, &self.byte_pair_mass, @as(usize, first) + 256 * @as(usize, second), multiplicity);
    }
    pub fn deinit(self: *Counter) void {
        self.a.free(self.range16);
        self.a.free(self.byte_pairs);
        self.* = undefined;
    }
};
pub fn ProviderRow(comptime S: type) type {
    return struct { multiplicity: S };
}
/// The receiver independently derives the entire 65536-row fixed table.
/// Multiplicity is a committed main cell. Its physical fraction and count
/// claims must both be absorbed before the interaction commitment.
pub fn range16Provider(comptime S: type, row: ProviderRow(S), canonical_fixed_value: S, events: anytype) void {
    events.provideRange16(row.multiplicity, canonical_fixed_value);
    events.provideRange16Count(row.multiplicity);
}
pub fn bytePairProvider(comptime S: type, row: ProviderRow(S), canonical_fixed_pair: [2]S, events: anytype) void {
    events.provideBytePair(row.multiplicity, canonical_fixed_pair);
    events.provideBytePairCount(row.multiplicity);
}
