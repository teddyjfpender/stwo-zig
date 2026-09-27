//! Nonproving regression fixtures for original public-schedule authority.
const std = @import("std");
const core = @import("stwo_core");
const Unique = @import("public_wire_uniqueness_v1.zig");
const modules = .{
    @import("block_v5_recursive_public_bus_v1.zig"),
    @import("block_v5_capacity_recursive_public_bus_v1.zig"),
    @import("block_v5_open_parent_public_bus_v1.zig"),
    @import("block_v5_range16_recursive_public_bus_v1.zig"),
    @import("block_v5_ram_lanes_recursive_public_bus_v1.zig"),
    @import("block_v5_program_table_recursive_public_bus_v1.zig"),
    @import("block_v5_caller_arithmetic_recursive_public_bus_v1.zig"),
    @import("block_v5_native_lookup_recursive_public_bus_v1.zig"),
};
const domains = [_]u32{ 0x42355057, 0x42354357, 0x42354f57, 0x42355257, 0x42354c57, 0x42355057, 0x42354157, 0x42354c57 };
const failures = .{ error.InvalidRecursivePublicSchedule, error.InvalidRecursivePublicSchedule, error.InvalidV5OpenParentSchedule, error.InvalidRangePublicSchedule, error.InvalidRamPublicSchedule, error.InvalidProgramPublicSchedule, error.InvalidCallerRecursiveSchedule, error.InvalidLookupPublicSchedule };
fn wireFor(comptime W: type, ordinal: u32) W {
    var wire: W = undefined;
    wire.circuit = 3 + ordinal % 3;
    wire.wire = ordinal;
    wire.uses = 1 + ordinal % 7;
    wire.coordinate = 0;
    if (@hasField(W, "source")) wire.source = @enumFromInt(0);
    if (@hasField(W, "child")) wire.child = @intCast(ordinal % 4);
    if (@hasField(W, "kind")) wire.kind = @enumFromInt(0);
    return wire;
}
// Original transcript words, independently framed. Uniqueness must never sort
// the schedule being hashed or include unrelated metadata in wire identity.
fn expected(comptime B: type, domain: u32, wires: []const B.Wire) [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ domain, 1, @intCast(wires.len) });
    for (wires) |wire| {
        if (@hasField(B.Wire, "child")) {
            channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, wire.child, @intFromEnum(wire.kind), wire.coordinate });
        } else {
            channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromEnum(wire.source), wire.coordinate });
        }
    }
    return channel.digestBytes();
}
test "public wire uniqueness: all eight exact original transcript framings preserve arbitrary order" {
    inline for (modules, domains) |B, domain| {
        var wires: [9]B.Wire = undefined;
        for (&wires, 0..) |*wire, i| wire.* = wireFor(B.Wire, @intCast(8 - i));
        const wanted = expected(B, domain, &wires);
        try std.testing.expectEqualSlices(u8, &wanted, &(try B.scheduleDigest(&wires)));
        std.mem.swap(B.Wire, &wires[0], &wires[8]);
        const reordered = expected(B, domain, &wires);
        try std.testing.expect(!std.mem.eql(u8, &wanted, &reordered));
        try std.testing.expectEqualSlices(u8, &reordered, &(try B.scheduleDigest(&wires)));
    }
}
test "public wire uniqueness: separated duplicates reject regardless of differing uses and source metadata" {
    inline for (modules, failures) |B, failure| {
        var wires: [9]B.Wire = undefined;
        for (&wires, 0..) |*wire, i| wire.* = wireFor(B.Wire, @intCast(i));
        wires[8] = wires[0];
        wires[8].uses += 1;
        if (@hasField(B.Wire, "child")) wires[8].child = 1;
        try std.testing.expectError(failure, B.scheduleDigest(&wires));
    }
}
test "public wire uniqueness: original zero size canonical field and source bounds remain fail closed" {
    inline for (modules, failures) |B, failure| {
        try std.testing.expectError(failure, B.scheduleDigest(&.{}));
        var wires = [_]B.Wire{wireFor(B.Wire, 0)};
        wires[0].uses = 0;
        try std.testing.expectError(failure, B.scheduleDigest(&wires));
        wires[0] = wireFor(B.Wire, 0);
        wires[0].circuit = core.fields.m31.Modulus;
        try std.testing.expectError(failure, B.scheduleDigest(&wires));
        wires[0] = wireFor(B.Wire, 0);
        wires[0].wire = core.fields.m31.Modulus;
        try std.testing.expectError(failure, B.scheduleDigest(&wires));
        if (@hasField(B.Wire, "source")) {
            wires[0] = wireFor(B.Wire, 0);
            wires[0].coordinate = std.math.maxInt(@TypeOf(wires[0].coordinate));
            try std.testing.expectError(failure, B.scheduleDigest(&wires));
        }
    }
}
test "public wire uniqueness: maximum caller schedule and full u32 wire identity need no heap allocation" {
    const B = modules[6];
    const Check = Unique.For(B.Wire, B.MAX_WIRES);
    const wires = try std.testing.allocator.alloc(B.Wire, B.MAX_WIRES);
    defer std.testing.allocator.free(wires);
    for (wires, 0..) |*wire, i| wire.* = wireFor(B.Wire, @intCast(i));
    try std.testing.expect(Check.unique(wires));
    std.mem.reverse(B.Wire, wires);
    try std.testing.expect(Check.unique(wires));
    const wanted = expected(B, domains[6], wires);
    try std.testing.expectEqualSlices(u8, &wanted, &(try B.scheduleDigest(wires)));
    wires[wires.len - 1] = wires[0];
    try std.testing.expect(!Check.unique(wires));
    try std.testing.expectError(error.InvalidCallerRecursiveSchedule, B.scheduleDigest(wires));
    const Pair = struct { circuit: u32, wire: u32 };
    const Wide = Unique.For(Pair, 4);
    const extrema = [_]Pair{ .{ .circuit = 0xffffffff, .wire = 0 }, .{ .circuit = 0, .wire = 0xffffffff }, .{ .circuit = 0xffffffff, .wire = 0xffffffff }, .{ .circuit = 0, .wire = 0 } };
    try std.testing.expect(Wide.unique(&extrema));
    try std.testing.expect(Unique.For(Pair, 1).unique(&.{}));
    try std.testing.expect(!Unique.For(Pair, 1).unique(&extrema));
}
test "public wire uniqueness: exhaustive small arbitrary permutations agree with independent pairwise authority" {
    const Pair = struct { circuit: u32, wire: u32 };
    const Check = Unique.For(Pair, 5);
    for (0..1024) |encoded| {
        var pairs: [5]Pair = undefined;
        var value = encoded;
        for (&pairs) |*pair| {
            const digit: u32 = @intCast(value % 4);
            pair.* = .{ .circuit = digit / 2, .wire = digit % 2 };
            value /= 4;
        }
        for (0..6) |len| {
            var independent = true;
            for (pairs[0..len], 0..) |pair, i| for (pairs[0..i]) |prior| {
                if (pair.circuit == prior.circuit and pair.wire == prior.wire) independent = false;
            };
            try std.testing.expectEqual(independent, Check.unique(pairs[0..len]));
        }
    }
}
