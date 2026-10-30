//! Exact native original verifier equation. Register, program, lookup and RAM
//! exports remain OPEN until the complete execution roster closes them.
const std = @import("std");
const core = @import("stwo_core");
const Public = @import("block_v7_native_public_v1.zig");
pub const Bus = struct {
    pub const VERSION: u32 = 1;
    pub const MAX_CHILDREN = 1;
    pub const Wire = Public.Wire;
    pub const Expected = struct { profile: [32]u8, epoch: [32]u8, roots: [3][32]u8, root_count: u32 };
    pub const Values = struct {
        children: []const Public.Values,
        pub fn validate(self: Values) !void {
            if (self.children.len != 1) return error.InvalidNativeParentRoster;
            try self.children[0].validate();
        }
        pub fn requireRoster(self: Values, expected: []const Expected) !void {
            try self.validate();
            if (expected.len != 1) return error.InvalidNativeParentRoster;
            const v = self.children[0];
            if ((expected[0].root_count != 2 and expected[0].root_count != 3) or v.roots_count != expected[0].root_count or !std.meta.eql(v.template, expected[0].profile) or
                !std.meta.eql(try v.statement.digest(v.statement.sealed_offset), expected[0].epoch)) return error.UntrustedNativeParentRoster;
            for (expected[0].roots[0..expected[0].root_count], 0..) |root, i| if (!std.meta.eql(root, try v.statement.digest(v.statement.roots_offset[i]))) return error.UntrustedNativeParentRoster;
        }
        pub fn at(self: Values, wire: Wire) ![4]core.fields.m31.M31 {
            try self.validate();
            return self.children[0].at(wire.source, wire.coordinate);
        }
        pub fn mix(self: Values, channel: anytype) void {
            channel.mixU32s(&.{ 0x42374e56, Bus.VERSION, @intCast(self.children.len) });
            for (self.children) |child| child.mix(channel);
        }
    };
    pub const scheduleDigest = Public.scheduleDigest;
    pub fn rosterDigest(expected: []const Expected) ![32]u8 {
        if (expected.len != 1) return error.InvalidNativeParentRoster;
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42374e52, Bus.VERSION, 1 });
        if (expected[0].root_count != 2 and expected[0].root_count != 3) return error.InvalidNativeParentRoster;
        if (expected[0].root_count == 2 and !std.mem.allEqual(u8, &expected[0].roots[2], 0)) return error.InvalidNativeParentRoster;
        ch.mixU32s(&.{expected[0].root_count});
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
const API = @import("block_v6_direct_batch_protocol_v1.zig").ForBus(Bus, .{ .key = 0x42374e4b, .public_input = 0x42374e49, .proof = 0x42374e50, .claims = 0x42374e43 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Key = API.Key;
pub const Admission = API.Admission;
