//! Strategy-based shared parent verifier; no original equations duplicated.
const Family = @import("block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return With(@import("block_v8_endpoint_recursive_adapter_v1.zig").For(family));
}
pub fn With(comptime Adapter: type) type {
    return struct {
        // Recursive verification of the endpoint original and its symbolic ledger.
        // The independent receiver reconstructs every boundary and physical claim port.
        const std = @import("std");
        const core = @import("stwo_core");
        const Public = Adapter.Public;
        const Profile = Adapter.Profile;
        pub const Bus = struct {
            pub const VERSION: u32 = 1;
            pub const MAX_CHILDREN = 1;
            pub const Wire = Public.Wire;
            pub const Expected = struct { profile: [32]u8, epoch: [32]u8, root_count: u32 };
            pub const Values = struct {
                children: []const Public.Values,
                pub fn validate(self: Values) !void {
                    if (self.children.len != 1) return error.InvalidEndpointParentRoster;
                    try self.children[0].validate();
                }
                pub fn requireRoster(self: Values, expected: []const Expected) !void {
                    try self.validate();
                    if (expected.len != 1) return error.InvalidEndpointParentRoster;
                    const v = self.children[0];
                    if (expected[0].root_count != v.roots_count or !std.meta.eql(v.template, expected[0].profile) or !std.meta.eql(try v.statement.digest(v.statement.sealed_offset), expected[0].epoch)) return error.UntrustedEndpointParentRoster;
                }
                pub fn at(self: Values, wire: Wire) ![4]core.fields.m31.M31 {
                    // Admission validates the entire immutable public vector once.
                    // Each row supplier checks only its selected coordinate and value.
                    if (self.children.len != 1 or !Adapter.rootsShape(self.children[0].roots_count)) return error.InvalidEndpointParentRoster;
                    const child = self.children[0];
                    if (wire.source == .public_input) {
                        if (wire.coordinate >= child.public.len) return error.InvalidEndpointParentOperand;
                        if (!@import("air/universal_provider_relations.zig").secureIsCanonical(&child.public[wire.coordinate])) return error.InvalidEndpointParentOperand;
                    } else if (wire.source == .felt_word) {
                        const field = wire.coordinate / 4;
                        if (field >= child.statement.felts.len) return error.InvalidEndpointParentOperand;
                        if (!@import("air/universal_provider_relations.zig").secureIsCanonical(&child.statement.felts[field])) return error.InvalidEndpointParentOperand;
                    }
                    const value = try child.at(wire.source, wire.coordinate);
                    for (value) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointParentOperand;
                    return value;
                }
                pub fn mix(self: Values, channel: anytype) void {
                    channel.mixU32s(&.{ Adapter.VALUES_TAG, Bus.VERSION, @intCast(self.children.len) });
                    for (self.children) |child| child.mix(channel);
                }
            };
            pub const scheduleDigest = Public.scheduleDigest;
            pub fn rosterDigest(expected: []const Expected) ![32]u8 {
                if (expected.len != 1 or expected[0].root_count < 2 or expected[0].root_count > 256) return error.InvalidEndpointParentRoster;
                var ch = core.proof_suites.Blake3.Channel{};
                ch.mixU32s(&.{ Adapter.ROSTER_TAG, Bus.VERSION, 1, expected[0].root_count });
                ch.mixRoot(expected[0].profile);
                ch.mixRoot(expected[0].epoch);
                return ch.digestBytes();
            }
            pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !core.fields.qm31.QM31 {
                try values.validate();
                return Public.supply(wires, values.children[0], relations);
            }
        };
        const API = @import("block_v6_direct_batch_protocol_v1.zig").ForBus(Bus, Adapter.tags);
        pub const VERSION = API.VERSION;
        pub const CLAIM_TAG = API.CLAIM_TAG;
        pub const Key = API.Key;
        pub const Admission = API.Admission;
    };
}
