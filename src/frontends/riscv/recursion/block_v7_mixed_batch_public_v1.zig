//! Public supply for proof-of-mixed-batch reduction. Every original typed frame
//! survives; range metadata is public, not an aggregate-only replacement.
//! Complete coverage/global algebra remain independent final-receiver checks.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Capture = @import("block_v7_mixed_batch_capture_v1.zig");
const Ranges = @import("block_v7_mixed_batch_ranges_v1.zig");
const Universal = @import("air/universal_challenges.zig");
pub const VERSION: u32 = 1;
pub const MAX_CHILDREN: usize = 32;
pub const MAX_WIRES: usize = 1 << 20;
pub const PUBLIC_CIRCUIT = Capture.PUBLIC_CIRCUIT;
pub const Kind = enum(u32) { frame_cell, child_supply_packed };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, negative: bool = false, child: u8, kind: Kind, coordinate: u32 };
pub const Expected = struct {
    scope: Ranges.Scope,
    job_identity: [32]u8,
    range: Ranges.Range,
    key_id: [32]u8,
    public_input_identity: [32]u8,
    pub fn from(source: *const Capture.Source) Expected {
        return .{ .scope = source.scope, .job_identity = source.job_identity, .range = source.range, .key_id = source.expected_id, .public_input_identity = source.public_input_digest };
    }
    pub fn fromPolicy(a: std.mem.Allocator, policy: Capture.Policy, limits: Capture.Limits) !Expected {
        const selected = try policy.admit(a, limits);
        return .{ .scope = policy.scope, .job_identity = selected.job_identity, .range = selected.range, .key_id = policy.expected_key, .public_input_identity = policy.expected_public_input_identity };
    }
    fn mix(self: Expected, channel: anytype) !void {
        try self.scope.mix(channel);
        channel.mixRoot(self.job_identity);
        channel.mixU32s(&.{ self.range.ordinal, self.range.first, self.range.count });
        channel.mixRoot(self.range.roster_digest);
        channel.mixRoot(self.key_id);
        channel.mixRoot(self.public_input_identity);
    }
};
pub fn rosterDigest(expected: []const Expected) ![32]u8 {
    if (expected.len == 0 or expected.len > MAX_CHILDREN) return error.InvalidMixedBatchFanIn;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42375252, VERSION, @intCast(expected.len) });
    for (expected, 0..) |pin, i| {
        if (pin.range.count == 0 or pin.range.count > 64 or pin.range.first >= 1 << 30 or pin.range.ordinal >= 1 << 30 or
            std.mem.allEqual(u8, &pin.job_identity, 0) or std.mem.allEqual(u8, &pin.key_id, 0) or std.mem.allEqual(u8, &pin.public_input_identity, 0) or std.mem.allEqual(u8, &pin.range.roster_digest, 0)) return error.InvalidMixedBatchRange;
        if (i != 0) {
            const previous = expected[i - 1];
            if (!std.meta.eql(pin.scope, previous.scope) or !std.meta.eql(pin.job_identity, previous.job_identity) or
                pin.range.first != try std.math.add(u32, previous.range.first, previous.range.count) or
                pin.range.ordinal != try std.math.add(u32, previous.range.ordinal, 1)) return error.InvalidMixedBatchAdjacency;
        }
        try pin.mix(&channel);
    }
    return channel.digestBytes();
}
/// Borrows owned, freshly reconstructed sources. Values never imply a proof.
pub const Values = struct {
    children: []const *const Capture.Source,
    pub fn validate(self: Values) !void {
        if (self.children.len == 0 or self.children.len > MAX_CHILDREN) return error.InvalidMixedBatchFanIn;
        var expected: [MAX_CHILDREN]Expected = undefined;
        for (self.children, 0..) |child, i| {
            try child.validate();
            expected[i] = Expected.from(child);
        }
        _ = try rosterDigest(expected[0..self.children.len]);
    }
    pub fn requireRoster(self: Values, expected: []const Expected) !void {
        try self.validate();
        _ = try rosterDigest(expected);
        if (expected.len != self.children.len) return error.UntrustedMixedBatchRoster;
        for (self.children, expected) |child, pin| if (!std.meta.eql(Expected.from(child), pin)) return error.UntrustedMixedBatchRoster;
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        if (wire.child >= self.children.len) return error.InvalidMixedBatchSchedule;
        const child = self.children[wire.child];
        return switch (wire.kind) {
            .frame_cell => if (wire.coordinate < child.cells.len) child.cells[wire.coordinate] else error.InvalidMixedBatchSchedule,
            .child_supply_packed => if (wire.coordinate < child.terms.len) child.terms[wire.coordinate].coordinates else error.InvalidMixedBatchSchedule,
        };
    }
    pub fn mix(self: Values, channel: anytype) void {
        // All callers first validate. Scope.mix's only fallible condition was
        // independently checked in rosterDigest; keep this generic channel API.
        channel.mixU32s(&.{ 0x42375256, VERSION, @intCast(self.children.len) });
        for (self.children) |child| {
            Expected.from(child).mix(channel) catch unreachable;
            child.mix(channel);
        }
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > MAX_WIRES) return error.InvalidMixedBatchSchedule;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42375257, VERSION, @intCast(wires.len) });
    for (wires, 0..) |wire, i| {
        if (wire.child >= MAX_CHILDREN or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus or
            (wire.kind == .frame_cell and wire.negative) or (wire.kind == .child_supply_packed and !wire.negative)) return error.InvalidMixedBatchSchedule;
        if (i != 0 and (wires[i - 1].circuit > wire.circuit or (wires[i - 1].circuit == wire.circuit and wires[i - 1].wire >= wire.wire))) return error.InvalidMixedBatchSchedule;
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromBool(wire.negative), wire.child, @intFromEnum(wire.kind), wire.coordinate });
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: Universal.UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const element = try relations.getExact(.recursion_wire);
    var total = Q.zero();
    for (wires) |wire| {
        const denominator = try element.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
        if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
        const term = Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv());
        total = if (wire.negative) total.sub(term) else total.add(term);
    }
    return total;
}
