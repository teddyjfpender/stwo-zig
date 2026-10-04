//! Pure recipe bytes/lookup custody only. No guest, PCS, STARK or proof runs.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Bus = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Digest = @import("../block_v5_public_supply_identity_v2.zig");
const Session = @import("../block_v5_public_supply_session_v2.zig");
const Fixture = struct {
    bias: u32 = 0,
    guards: usize = 0,
    reads: usize = 0,
    pub fn validate(self: *@This()) !void {
        self.guards += 1;
    }
    pub fn at(self: *@This(), wire: Bus.Wire) ![4]M {
        self.reads += 1;
        return .{ M.fromCanonical(wire.coordinate + self.bias), M.fromCanonical(wire.child), M.fromCanonical(wire.uses), M.fromCanonical(123456789) };
    }
};
fn makeWire(index: usize) Bus.Wire {
    return .{ .circuit = @intCast(1 + index / 19), .wire = @intCast(index % 19), .uses = @intCast(1 + index % 7), .negative = index % 3 == 0, .kind = .child_cell, .child = @intCast(index % 4), .coordinate = @intCast(index), .part = if (index % 5 == 0) null else @intCast(index % 4) };
}
fn oracle(wires: []const Bus.Wire, bias: u32) !Digest.Identity {
    var schedule: std.ArrayList(u8) = .empty;
    defer schedule.deinit(std.testing.allocator);
    var values: std.ArrayList(u8) = .empty;
    defer values.deinit(std.testing.allocator);
    try schedule.appendSlice(std.testing.allocator, Digest.SCHEDULE_DOMAIN);
    try values.appendSlice(std.testing.allocator, Digest.VALUE_DOMAIN);
    var count: [8]u8 = undefined;
    std.mem.writeInt(u64, &count, @intCast(wires.len), .little);
    try schedule.appendSlice(std.testing.allocator, &count);
    try values.appendSlice(std.testing.allocator, &count);
    for (wires) |item| {
        const fields = [_]u32{ item.circuit, item.wire, item.uses, @intFromBool(item.negative), @intFromEnum(item.kind), item.child, item.coordinate, if (item.part) |part| part else 4 };
        for (fields) |field| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, field, .little);
            try schedule.appendSlice(std.testing.allocator, &bytes);
        }
        for ([_]u32{ item.coordinate + bias, item.child, item.uses, 123456789 }) |field| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, field, .little);
            try values.appendSlice(std.testing.allocator, &bytes);
        }
    }
    var result: Digest.Identity = undefined;
    std.crypto.hash.Blake3.hash(schedule.items, &result.schedule, .{});
    std.crypto.hash.Blake3.hash(values.items, &result.values, .{});
    const header = Digest.CLOSURE_DOMAIN.len;
    var closure: [header + 8 + 64]u8 = undefined;
    @memcpy(closure[0..header], Digest.CLOSURE_DOMAIN);
    @memcpy(closure[header..][0..8], &count);
    @memcpy(closure[header + 8 ..][0..32], &result.schedule);
    @memcpy(closure[header + 40 ..][0..32], &result.values);
    std.crypto.hash.Blake3.hash(&closure, &result.closure, .{});
    return result;
}
test "streaming public supply: canonical one-shot bytes match across buffer and chunk boundaries" {
    var wires: [257]Bus.Wire = undefined;
    for (&wires, 0..) |*item, index| item.* = makeWire(index);
    for ([_]usize{ 1, 2, 63, 64, 65, 127, 128, 129, 257 }) |count| {
        var fixture = Fixture{};
        const actual = try Digest.compute(&fixture, wires[0..count], .{});
        try std.testing.expect(std.meta.eql(actual, try oracle(wires[0..count], 0)));
        try std.testing.expectEqual(@as(usize, 1), fixture.guards);
        try std.testing.expectEqual(count, fixture.reads);
    }
}
const Forbidden = struct {
    pub fn validate(_: *@This()) !void {
        return error.UnexpectedPolicyAccess;
    }
    pub fn at(_: *@This(), _: Bus.Wire) ![4]M {
        return error.UnexpectedPolicyAccess;
    }
};
test "streaming public supply: caps ordering duplicate and field guards precede policy access" {
    var forbidden = Forbidden{};
    const first = makeWire(0);
    try std.testing.expectError(error.ClosedPublicSupplyResourceLimit, Digest.compute(&forbidden, &.{first}, .{ .max_local_wires = 0 }));
    try std.testing.expectError(error.ClosedPublicSupplyResourceLimit, Digest.compute(&forbidden, &.{}, .{}));
    try std.testing.expectError(error.ClosedPublicSupplyResourceLimit, Digest.compute(&forbidden, &.{ first, makeWire(1) }, .{ .max_local_wires = 1 }));
    try std.testing.expectError(error.InvalidScopedPublicSchedule, Digest.compute(&forbidden, &.{ first, first }, .{}));
    try std.testing.expectError(error.InvalidScopedPublicSchedule, Digest.compute(&forbidden, &.{ makeWire(1), first }, .{}));
    var invalid = first;
    invalid.uses = 0;
    try std.testing.expectError(error.InvalidScopedPublicSchedule, Digest.compute(&forbidden, &.{invalid}, .{}));
    invalid = first;
    invalid.uses = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidScopedPublicSchedule, Digest.compute(&forbidden, &.{invalid}, .{}));
    invalid = first;
    invalid.circuit = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidScopedPublicSchedule, Digest.compute(&forbidden, &.{invalid}, .{}));
    invalid = first;
    invalid.wire = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidScopedPublicSchedule, Digest.compute(&forbidden, &.{invalid}, .{}));
}
test "streaming public supply: partial failed excessive and finalized builders cannot mint identity" {
    const coordinates = [_]M{ M.zero(), M.one(), M.zero(), M.one() };
    var partial = try Digest.Builder.init(2, .{});
    try partial.append(makeWire(0), coordinates);
    try std.testing.expectError(error.IncompletePublicSupplyIdentity, partial.finish());
    try std.testing.expectError(error.InvalidPublicSupplySession, partial.append(makeWire(1), coordinates));
    var invalid = try Digest.Builder.init(1, .{});
    var noncanonical = coordinates;
    noncanonical[3] = .{ .v = core.fields.m31.Modulus };
    try std.testing.expectError(error.InvalidPublicSupplySession, invalid.append(makeWire(0), noncanonical));
    try std.testing.expectError(error.InvalidPublicSupplySession, invalid.finish());
    var excessive = try Digest.Builder.init(1, .{});
    try excessive.append(makeWire(0), coordinates);
    try std.testing.expectError(error.InvalidPublicSupplySession, excessive.append(makeWire(1), coordinates));
    try std.testing.expectError(error.InvalidPublicSupplySession, excessive.finish());
    var finished = try Digest.Builder.init(1, .{});
    try finished.append(makeWire(0), coordinates);
    _ = try finished.finish();
    try std.testing.expectError(error.InvalidPublicSupplySession, finished.finish());
}
test "streaming public supply: every schedule field values count and stream domains bind identity" {
    var fixture = Fixture{};
    const first = makeWire(0);
    const original = try Digest.compute(&fixture, &.{first}, .{});
    for (0..8) |field| {
        var changed = first;
        switch (field) {
            0 => changed.circuit += 1,
            1 => changed.wire += 1,
            2 => changed.uses += 1,
            3 => changed.negative = !changed.negative,
            4 => changed.kind = .output_slot,
            5 => changed.child += 1,
            6 => changed.coordinate += 1,
            7 => changed.part = 0,
            else => unreachable,
        }
        const actual = try Digest.compute(&fixture, &.{changed}, .{});
        try std.testing.expect(!std.meta.eql(original.schedule, actual.schedule));
        try std.testing.expect(!std.meta.eql(original.closure, actual.closure));
    }
    fixture.bias = 1;
    const changed_value = try Digest.compute(&fixture, &.{first}, .{});
    try std.testing.expectEqual(original.schedule, changed_value.schedule);
    try std.testing.expect(!std.meta.eql(original.values, changed_value.values));
    try std.testing.expect(!std.meta.eql(original.closure, changed_value.closure));
    const longer = try Digest.compute(&fixture, &.{ first, makeWire(1) }, .{});
    try std.testing.expect(!std.meta.eql(original.schedule, longer.schedule));
    try std.testing.expect(!std.meta.eql(original.schedule, original.values));
}
test "streaming public supply: one entry and exit admission with bounded exact coordinate lookups" {
    var fixture = Fixture{};
    var wires: [129]Bus.Wire = undefined;
    for (&wires, 0..) |*item, index| item.* = makeWire(index);
    var session = try Session.ForValues(*Fixture).begin(&fixture, &wires, .{});
    for (wires, 0..) |item, ordinal| {
        const actual = try session.at(ordinal);
        try std.testing.expectEqual(item.coordinate, actual[0].v);
    }
    try std.testing.expectError(error.InvalidPublicSupplySession, session.at(wires.len));
    const identity = try session.finish();
    try std.testing.expectEqual((try oracle(&wires, 0)).closure, identity);
    try std.testing.expectEqual(@as(usize, 2), fixture.guards);
    try std.testing.expectEqual(3 * wires.len, fixture.reads);
    try std.testing.expectError(error.InvalidPublicSupplySession, session.at(0));
    try std.testing.expectError(error.InvalidPublicSupplySession, session.finish());
}
test "streaming public supply: changed borrowed values or schedule poison immutable session" {
    var fixture = Fixture{};
    var wires = [_]Bus.Wire{makeWire(0)};
    var values_session = try Session.ForValues(*Fixture).begin(&fixture, &wires, .{});
    fixture.bias = 1;
    try std.testing.expectError(error.MutatedPublicSupplySession, values_session.finish());
    try std.testing.expectError(error.InvalidPublicSupplySession, values_session.finish());
    var schedule_session = try Session.ForValues(*Fixture).begin(&fixture, &wires, .{});
    wires[0].negative = !wires[0].negative;
    try std.testing.expectError(error.MutatedPublicSupplySession, schedule_session.finish());
    try std.testing.expectError(error.InvalidPublicSupplySession, schedule_session.at(0));
}
