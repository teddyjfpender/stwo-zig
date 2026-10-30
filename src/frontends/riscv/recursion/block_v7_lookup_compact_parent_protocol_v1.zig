//! One complete verifier equation for the original v7 compact lookup proof. The
//! authenticated result remains OPEN until native/caller transition closure.
const std = @import("std");
const core = @import("stwo_core");
const Public = @import("block_v7_lookup_compact_public_v1.zig");
pub const Bus = struct {
    pub const VERSION: u32 = 1;
    pub const MAX_CHILDREN = 1;
    pub const Wire = Public.Wire;
    pub const Expected = struct { profile: [32]u8, epoch: [32]u8, roots: [2][32]u8 };
    pub const Values = struct {
        children: []const Public.Values,
        pub fn validate(self: Values) !void {
            if (self.children.len != 1) return error.InvalidCompactLookupParentRoster;
            try self.children[0].validate();
        }
        pub fn requireRoster(self: Values, expected: []const Expected) !void {
            try self.validate();
            if (expected.len != 1) return error.InvalidCompactLookupParentRoster;
            const v = self.children[0];
            if (v.roots_count != 2 or !std.meta.eql(v.template, expected[0].profile) or
                !std.meta.eql(try v.statement.digest(v.statement.sealed_offset), expected[0].epoch)) return error.UntrustedCompactLookupParentRoster;
            for (expected[0].roots, 0..) |root, i| if (!std.meta.eql(root, try v.statement.digest(v.statement.roots_offset[i]))) return error.UntrustedCompactLookupParentRoster;
        }
        pub fn at(self: Values, wire: Wire) ![4]core.fields.m31.M31 {
            try self.validate();
            return self.children[0].at(wire.source, wire.coordinate);
        }
        pub fn mix(self: Values, channel: anytype) void {
            channel.mixU32s(&.{ 0x42374c56, Bus.VERSION, @intCast(self.children.len) });
            for (self.children) |child| child.mix(channel);
        }
    };
    pub const scheduleDigest = Public.scheduleDigest;
    pub fn rosterDigest(expected: []const Expected) ![32]u8 {
        if (expected.len != 1) return error.InvalidCompactLookupParentRoster;
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42374c52, Bus.VERSION, 1 });
        ch.mixRoot(expected[0].profile);
        ch.mixRoot(expected[0].epoch);
        for (expected[0].roots) |root| ch.mixRoot(root);
        return ch.digestBytes();
    }
    pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !core.fields.qm31.QM31 {
        try values.validate();
        return Public.supply(wires, values.children[0], relations);
    }
};
const API = @import("block_v6_direct_batch_protocol_v1.zig").ForBus(Bus, .{ .key = 0x42374c4b, .public_input = 0x42374c49, .proof = 0x42374c50, .claims = 0x42374c43 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Key = API.Key;
pub const Admission = API.Admission;
