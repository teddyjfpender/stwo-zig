const std = @import("std");
const core = @import("stwo_core");
const P = @import("block_v8_window_root_public_v1.zig");
pub const Bus = struct {
    pub const VERSION = 1;
    pub const MAX_CHILDREN = 64;
    pub const Wire = P.Wire;
    pub const Expected = struct { digest: [32]u8 };
    pub const Values = struct {
        children: []const P.Values,
        pub fn validate(v: Values) !void {
            if (v.children.len != 1) return error.InvalidEndpointJoinRoster;
            try v.children[0].validate();
        }
        pub fn requireRoster(v: Values, e: []const Expected) !void {
            try v.validate();
            if (e.len != 1 or !std.meta.eql(e[0].digest, digest(v.children[0]))) return error.UntrustedEndpointJoinRoster;
        }
        pub fn at(v: Values, w: Wire) ![4]core.fields.m31.M31 {
            return v.children[0].at(w);
        }
        pub fn mix(v: Values, ch: anytype) void {
            v.children[0].mix(ch);
        }
    };
    pub const scheduleDigest = P.scheduleDigest;
    pub fn rosterDigest(e: []const Expected) ![32]u8 {
        if (e.len != 1) return error.InvalidEndpointJoinRoster;
        return e[0].digest;
    }
    pub fn supply(w: []const Wire, v: Values, r: @import("air/universal_challenges.zig").UniversalRelations) !core.fields.qm31.QM31 {
        return P.supply(w, v.children[0], r);
    }
};
pub fn digest(v: P.Values) [32]u8 {
    var ch = core.proof_suites.Blake3.Channel{};
    v.mix(&ch);
    return ch.digestBytes();
}
const API = @import("block_v6_direct_batch_protocol_v1.zig").ForBus(Bus, .{ .key = 0x4238574b, .public_input = 0x42385749, .proof = 0x42385750, .claims = 0x42385743 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Key = API.Key;
pub const Admission = API.Admission;
