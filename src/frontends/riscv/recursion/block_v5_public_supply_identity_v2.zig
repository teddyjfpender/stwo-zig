//! Bounded streaming identity for NEW closed-node recipes only. These domains
//! do not replace an existing proof transcript or version1 schedule digest.
//! Explicit count, widths and little-endian encoding make buffer boundaries
//! irrelevant. This identity authenticates a recipe; it is not proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Bus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
const M = core.fields.m31.M31;
const Hash = std.crypto.hash.Blake3;
pub const VERSION: u32 = 2;
pub const BUFFER_RECORDS: usize = 64;
pub const SCHEDULE_BYTES: usize = 32;
pub const VALUE_BYTES: usize = 16;
pub const SCHEDULE_DOMAIN = "STWO:B5SC:SCHEDULE:2\x00";
pub const VALUE_DOMAIN = "STWO:B5SC:VALUES:2\x00";
pub const CLOSURE_DOMAIN = "STWO:B5SC:CLOSURE:2\x00";
pub const Limits = struct { max_local_wires: usize = 1 << 20 };
pub const Identity = struct {
    schedule: [32]u8,
    values: [32]u8,
    closure: [32]u8,
};
fn requireCount(count: usize, limits: Limits) !void {
    if (limits.max_local_wires == 0 or count == 0 or count > limits.max_local_wires or count > std.math.maxInt(u32)) return error.ClosedPublicSupplyResourceLimit;
}
fn requireWire(wire: Bus.Wire, previous: ?Bus.Wire) !void {
    if (wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus) return error.InvalidScopedPublicSchedule;
    if (previous) |prior| if (prior.circuit > wire.circuit or (prior.circuit == wire.circuit and prior.wire >= wire.wire)) return error.InvalidScopedPublicSchedule;
}
fn encodeWire(destination: *[SCHEDULE_BYTES]u8, wire: Bus.Wire) void {
    const words = [_]u32{ wire.circuit, wire.wire, wire.uses, @intFromBool(wire.negative), @intFromEnum(wire.kind), wire.child, wire.coordinate, if (wire.part) |part| part else 4 };
    for (words, 0..) |word, part| std.mem.writeInt(u32, destination[4 * part ..][0..4], word, .little);
}
fn encodeValue(destination: *[VALUE_BYTES]u8, coordinates: [4]M) !void {
    for (coordinates, 0..) |value, part| {
        if (value.v >= core.fields.m31.Modulus) return error.InvalidPublicSupplySession;
        std.mem.writeInt(u32, destination[4 * part ..][0..4], value.v, .little);
    }
}
fn initialize(domain: []const u8, count: usize) Hash {
    var hash = Hash.init(.{});
    hash.update(domain);
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(count), .little);
    hash.update(&encoded);
    return hash;
}
/// One fixed-size stack buffer per stream, no allocation or framed hash per
/// record. A rejected append poisons the builder, preventing partial identity.
pub const Builder = struct {
    expected: usize,
    appended: usize = 0,
    buffered: usize = 0,
    previous: ?Bus.Wire = null,
    active: bool = true,
    schedules: Hash,
    values: Hash,
    schedule_buffer: [BUFFER_RECORDS * SCHEDULE_BYTES]u8 = undefined,
    value_buffer: [BUFFER_RECORDS * VALUE_BYTES]u8 = undefined,
    pub fn init(count: usize, limits: Limits) !Builder {
        try requireCount(count, limits);
        return .{ .expected = count, .schedules = initialize(SCHEDULE_DOMAIN, count), .values = initialize(VALUE_DOMAIN, count) };
    }
    pub fn append(self: *Builder, wire: Bus.Wire, coordinates: [4]M) !void {
        if (!self.active) return error.InvalidPublicSupplySession;
        errdefer self.active = false;
        if (self.appended >= self.expected) return error.InvalidPublicSupplySession;
        try requireWire(wire, self.previous);
        try encodeValue(self.value_buffer[self.buffered * VALUE_BYTES ..][0..VALUE_BYTES], coordinates);
        encodeWire(self.schedule_buffer[self.buffered * SCHEDULE_BYTES ..][0..SCHEDULE_BYTES], wire);
        self.previous = wire;
        self.appended += 1;
        self.buffered += 1;
        if (self.buffered == BUFFER_RECORDS) self.flush();
    }
    fn flush(self: *Builder) void {
        self.schedules.update(self.schedule_buffer[0 .. self.buffered * SCHEDULE_BYTES]);
        self.values.update(self.value_buffer[0 .. self.buffered * VALUE_BYTES]);
        self.buffered = 0;
    }
    pub fn finish(self: *Builder) !Identity {
        if (!self.active) return error.InvalidPublicSupplySession;
        self.active = false;
        if (self.appended != self.expected) return error.IncompletePublicSupplyIdentity;
        self.flush();
        var identity: Identity = undefined;
        self.schedules.final(&identity.schedule);
        self.values.final(&identity.values);
        var closure = initialize(CLOSURE_DOMAIN, self.expected);
        closure.update(&identity.schedule);
        closure.update(&identity.values);
        closure.final(&identity.closure);
        return identity;
    }
};
/// Reject malformed geometry before touching a pointer-bearing policy. Full
/// admission runs once, then only exact admitted coordinate lookups occur.
pub fn compute(values: anytype, wires: []const Bus.Wire, limits: Limits) !Identity {
    try requireCount(wires.len, limits);
    var previous: ?Bus.Wire = null;
    for (wires) |wire| {
        try requireWire(wire, previous);
        previous = wire;
    }
    try values.validate();
    var builder = try Builder.init(wires.len, limits);
    for (wires) |wire| try builder.append(wire, try values.at(wire));
    return builder.finish();
}
