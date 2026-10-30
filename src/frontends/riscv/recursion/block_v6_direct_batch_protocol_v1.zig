//! Direct base-provider batch protocol. Typed open claims are authenticated,
//! but source/requester closure must be supplied by the final block protocol.
const std = @import("std");
const core = @import("stwo_core");
const base = @import("blake3_execution_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const universal = @import("air/universal_challenges.zig");
pub const Domains = struct { key: u32, public_input: u32, proof: u32, claims: u32 };
/// Identical direct verifier equation with explicitly separated typed domains.
pub fn ForBus(comptime bus: type, comptime tags: Domains) type {
    return struct {
        pub const VERSION = bus.VERSION;
        pub const CLAIM_TAG: u32 = tags.claims;
        pub const Key = struct {
            profile: base.Profile,
            config: core.pcs.PcsConfig,
            context: base.Context,
            log_sizes: @FieldType(base.Key, "log_sizes"),
            preprocessed_root: [32]u8,
            public_schedule_digest: [32]u8,
            child_count: u32,
            roster_digest: [32]u8,
            pub fn fromGeometry(key: base.Key, wires: []const bus.Wire, roster: []const bus.Expected) !Key {
                const child_count = roster.len;
                if (child_count == 0 or child_count > bus.MAX_CHILDREN) return error.InvalidProviderBatchCount;
                const result = Key{ .profile = key.profile, .config = key.config, .context = key.context, .log_sizes = key.log_sizes, .preprocessed_root = key.preprocessed_root, .public_schedule_digest = try bus.scheduleDigest(wires), .child_count = @intCast(child_count), .roster_digest = try bus.rosterDigest(roster) };
                _ = try result.identity();
                return result;
            }
            pub fn identity(self: *const Key) ![32]u8 {
                if (self.child_count == 0 or self.child_count > bus.MAX_CHILDREN or
                    self.context.statement_identity != null or self.context.span_binding_id != null or
                    self.context.aggregation != null or self.context.exact_aggregation != null or self.context.quad_aggregation != null or
                    std.mem.allEqual(u8, &self.public_schedule_digest, 0) or std.mem.allEqual(u8, &self.roster_digest, 0)) return error.InvalidProviderBatchKey;
                const geometry = base.Key{ .profile = self.profile, .config = self.config, .context = self.context, .log_sizes = self.log_sizes, .preprocessed_root = self.preprocessed_root };
                var channel = core.channel.blake3.Channel{};
                channel.mixU32s(&.{ tags.key, VERSION, self.child_count });
                channel.mixRoot(try geometry.identity());
                channel.mixRoot(self.public_schedule_digest);
                channel.mixRoot(self.roster_digest);
                return channel.digestBytes();
            }
        };
        pub const Admission = struct {
            key: Key,
            expected_id: [32]u8,
            wires: []const bus.Wire,
            values: bus.Values,
            roster: []const bus.Expected,
            pub fn init(key: Key, expected: [32]u8, wires: []const bus.Wire, values: bus.Values, roster: []const bus.Expected) !Admission {
                const result = Admission{ .key = key, .expected_id = expected, .wires = wires, .values = values, .roster = roster };
                try result.validate();
                return result;
            }
            pub fn validate(self: *const Admission) !void {
                if (!std.meta.eql(self.key.config, self.key.context.child_config) or
                    self.values.children.len != self.key.child_count) return error.InvalidProviderBatchAdmission;
                if (!std.meta.eql(try self.key.identity(), self.expected_id) or
                    !std.meta.eql(try bus.scheduleDigest(self.wires), self.key.public_schedule_digest)) return error.UntrustedProviderBatchKey;
                try self.values.requireRoster(self.roster);
                if (!std.meta.eql(try bus.rosterDigest(self.roster), self.key.roster_digest)) return error.UntrustedProviderBatchRoster;
                for (self.wires) |wire| _ = try self.values.at(wire);
            }
            pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
                try self.validate();
                var channel = core.channel.blake3.Channel{};
                channel.mixU32s(&.{ tags.public_input, VERSION });
                channel.mixRoot(self.expected_id);
                self.values.mix(&channel);
                return channel.digestBytes();
            }
            pub fn config(self: *const Admission) !core.pcs.PcsConfig {
                try self.validate();
                return self.key.config;
            }
            pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
                try self.validate();
                if (!std.meta.eql(root, self.key.preprocessed_root)) return error.UntrustedBlake3ParentRoot;
            }
            pub fn mix(self: *const Admission, channel: anytype) !void {
                try self.validate();
                channel.mixU32s(&.{ tags.proof, VERSION, @intFromEnum(self.key.profile) });
                self.key.config.mixInto(channel);
                channel.mixRoot(self.expected_id);
                self.values.mix(channel);
            }
            pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const core.fields.qm31.QM31) !void {
                try self.validate();
                if (claims.len != artifact.CLAIM_COUNT) return error.InvalidBlake3ParentClaims;
                channel.mixU32s(&.{ CLAIM_TAG, VERSION, artifact.CLAIM_COUNT });
                channel.mixFelts(claims);
            }
            pub fn validateClaimsForRelations(self: *const Admission, claims: artifact.Claims, relations: universal.UniversalRelations) !void {
                try self.validate();
                var sum = try bus.supply(self.wires, self.values, relations);
                for (claims) |claim| {
                    for (claim.toM31Array()) |value| if (value.v >= core.fields.m31.Modulus) return error.InvalidBlake3ParentClaims;
                    sum = sum.add(claim);
                }
                if (!sum.isZero()) return error.InvalidProviderBatchPublicClosure;
            }
        };
    };
}
