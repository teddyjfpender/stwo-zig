//! Distinct native-only joined verifier + in-proof global closure protocol.
//! Expected metadata and keys are independently reconstructed by the receiver.
const std = @import("std");
const core = @import("stwo_core");
const Public = @import("block_v8_union_closed_public_v1.zig");
pub const Bus = struct {
    pub const VERSION: u32 = 1;
    pub const MAX_CHILDREN = 1;
    pub const Wire = Public.Wire;
    pub const Expected = struct { profile: [32]u8, epoch: [32]u8, roots: u32, closure: [32]u8 };
    pub const Values = struct {
        children: []const Public.Values,
        pub fn validate(self: Values) !void {
            if (self.children.len != 1) return error.InvalidClosedUnionRoster;
            try self.children[0].validate();
        }
        pub fn requireRoster(self: Values, expected: []const Expected) !void {
            try self.validate();
            if (expected.len != 1) return error.InvalidClosedUnionRoster;
            const original = self.children[0].original;
            if (original.roots_count != expected[0].roots or !std.meta.eql(original.template, expected[0].profile) or !std.meta.eql(try original.statement.digest(original.statement.sealed_offset), expected[0].epoch)) return error.UntrustedClosedUnionRoster;
        }
        pub fn at(self: Values, wire: Wire) ![4]core.fields.m31.M31 {
            // Admission.validate already validates the complete immutable
            // operand vector before its wire walk; repeating it here makes
            // that walk quadratic. This accessor retains all local bounds.
            if (self.children.len != 1) return error.InvalidClosedUnionRoster;
            return self.children[0].at(wire);
        }
        pub fn mix(self: Values, channel: anytype) void {
            channel.mixU32s(&.{ 0x42384349, Bus.VERSION, @intCast(self.children.len) });
            for (self.children) |child| child.mix(channel);
        }
    };
    pub const scheduleDigest = Public.scheduleDigest;
    pub fn rosterDigest(expected: []const Expected) ![32]u8 {
        if (expected.len != 1 or expected[0].roots < 2 or expected[0].roots > 256 or std.mem.allEqual(u8, &expected[0].closure, 0)) return error.InvalidClosedUnionRoster;
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42384352, Bus.VERSION, expected[0].roots });
        ch.mixRoot(expected[0].profile);
        ch.mixRoot(expected[0].epoch);
        ch.mixRoot(expected[0].closure);
        return ch.digestBytes();
    }
    pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !core.fields.qm31.QM31 {
        try values.validate();
        return Public.supply(wires, values.children[0], relations);
    }
};
const API = @import("block_v6_direct_batch_protocol_v1.zig").ForBus(Bus, .{ .key = 0x4238434b, .public_input = 0x42384350, .proof = 0x42384354, .claims = 0x42384343 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Key = API.Key;
pub const Admission = API.Admission;
