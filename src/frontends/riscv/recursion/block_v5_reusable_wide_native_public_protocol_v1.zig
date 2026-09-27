//! Distinct B5WK setup/B5WP public input for a genuine original verifier PLUS
//! full-u64 same-parent graph. No old proof grammar/claim tag is relabeled.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("blake3_execution_parent_protocol.zig");
const Bus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Public = @import("block_v5_wide_native_public_values_v1.zig");
pub const VERSION: u32 = 1;
pub const Wire = Bus.Wire;
pub const scheduleDigest = Bus.scheduleDigest;
pub fn sourceAuthority() [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42355753, VERSION });
    inline for (.{ @embedFile("block_v5_wide_original_child_source_v1.zig"), @embedFile("block_v5_wide_native_public_values_v1.zig"), @embedFile("block_v5_reusable_wide_native_public_protocol_v1.zig"), @embedFile("air/block_v5_wide_native_public_graph_v1.zig"), @embedFile("air/block_v5_recursive_u64_span_v1.zig"), @embedFile("block_v5_global_public_fields_v1.zig") }) |source| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(source, &digest, .{});
        channel.mixRoot(digest);
    }
    return channel.digestBytes();
}
pub fn ForSubtype(comptime subtype: Coverage.Subtype) type {
    const P = Public.ForSubtype(subtype);
    return struct {
        pub const Profile = Base.Profile;
        pub const Context = Base.Context;
        pub const Values = struct {
            public: *const P.Values,
            pub fn validate(self: Values) !void {
                try self.public.validate();
            }
            pub fn at(self: Values, wire: Wire) ![4]core.fields.m31.M31 {
                var cell: [4]core.fields.m31.M31 = undefined;
                switch (wire.kind) {
                    .child_cell => {
                        cell = if (wire.child == 0) try self.public.source.cell(wire.coordinate) else if (wire.child == 1) try self.public.cell(wire.coordinate) else return error.InvalidWideNativeSchedule;
                    },
                    .child_term => {
                        if (wire.child != 0 or wire.part != null or wire.coordinate >= self.public.source.terms.len) return error.InvalidWideNativeSchedule;
                        return self.public.source.terms[wire.coordinate].coordinates;
                    },
                    .child_span, .output_span, .output_slot => return error.InvalidWideNativeSchedule,
                }
                return if (wire.part) |part| .{ cell[part], core.fields.m31.M31.zero(), core.fields.m31.M31.zero(), core.fields.m31.M31.zero() } else cell;
            }
            pub fn mix(self: Values, channel: anytype) !void {
                try self.public.mixParent(channel);
            }
        };
        pub const Key = struct {
            profile: Profile,
            config: core.pcs.PcsConfig,
            context: Context,
            log_sizes: @FieldType(Base.Key, "log_sizes"),
            preprocessed_root: [32]u8,
            public_schedule_digest: [32]u8,
            pub fn fromGeometry(key: Base.Key, wires: []const Wire) !Key {
                return .{ .profile = key.profile, .config = key.config, .context = key.context, .log_sizes = key.log_sizes, .preprocessed_root = key.preprocessed_root, .public_schedule_digest = try scheduleDigest(wires) };
            }
            pub fn identity(self: *const Key) ![32]u8 {
                if (self.context.statement_identity != null or self.context.span_binding_id != null or self.context.aggregation != null or self.context.exact_aggregation != null or self.context.quad_aggregation != null or std.mem.allEqual(u8, &self.public_schedule_digest, 0)) return error.InvalidWideNativeKey;
                const base = Base.Key{ .profile = self.profile, .config = self.config, .context = self.context, .log_sizes = self.log_sizes, .preprocessed_root = self.preprocessed_root };
                var channel = core.channel.blake3.Channel{};
                channel.mixU32s(&.{ 0x4235574b, VERSION, @intFromEnum(subtype) });
                channel.mixRoot(sourceAuthority());
                channel.mixRoot(try base.identity());
                channel.mixRoot(self.public_schedule_digest);
                return channel.digestBytes();
            }
        };
        pub const Admission = struct {
            pub const CLAIM_TAG = 0x42355751;
            key: Key,
            expected_id: [32]u8,
            wires: []const Wire,
            values: Values,
            pub fn init(key: Key, id: [32]u8, wires: []const Wire, public: *const P.Values) !Admission {
                const out = Admission{ .key = key, .expected_id = id, .wires = wires, .values = .{ .public = public } };
                try out.validate();
                return out;
            }
            pub fn validate(self: *const Admission) !void {
                try self.values.validate();
                if (!std.meta.eql(try self.key.identity(), self.expected_id) or !std.meta.eql(try scheduleDigest(self.wires), self.key.public_schedule_digest) or !std.meta.eql(self.key.config, self.key.context.child_config) or !std.meta.eql(self.key.config, self.values.public.source.policy.key.config)) return error.UntrustedWideNativeKey;
                for (self.wires) |wire| _ = try self.values.at(wire);
            }
            pub fn config(self: *const Admission) !core.pcs.PcsConfig {
                try self.validate();
                return self.key.config;
            }
            pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
                try self.validate();
                if (!std.meta.eql(root, self.key.preprocessed_root)) return error.UntrustedBlake3ParentRoot;
            }
            pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
                try self.validate();
                var channel = core.channel.blake3.Channel{};
                channel.mixU32s(&.{ 0x42355749, VERSION, @intFromEnum(subtype) });
                channel.mixRoot(self.expected_id);
                try self.values.mix(&channel);
                return channel.digestBytes();
            }
            pub fn mix(self: *const Admission, channel: anytype) !void {
                try self.validate();
                channel.mixU32s(&.{ 0x42355741, VERSION, @intFromEnum(subtype), @intFromEnum(self.key.profile) });
                self.key.config.mixInto(channel);
                channel.mixRoot(self.expected_id);
                try self.values.mix(channel);
            }
            pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const core.fields.qm31.QM31) !void {
                try self.validate();
                if (claims.len != @import("blake3_native_parent_artifact.zig").CLAIM_COUNT) return error.InvalidBlake3ParentClaims;
                channel.mixU32s(&.{ CLAIM_TAG, VERSION, @import("blake3_native_parent_artifact.zig").CLAIM_COUNT });
                channel.mixFelts(claims);
            }
            pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
                try self.validate();
                const relation = try relations.getExact(.recursion_wire);
                var total = core.fields.qm31.QM31.zero();
                for (self.wires) |wire| {
                    const tuple = .{ core.fields.m31.M31.fromCanonical(wire.circuit), core.fields.m31.M31.fromCanonical(wire.wire) } ++ try self.values.at(wire);
                    const denominator = try relation.combineBase(&tuple);
                    if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
                    const term = core.fields.qm31.QM31.fromBase(core.fields.m31.M31.fromCanonical(wire.uses)).mul(try denominator.inv());
                    total = if (wire.negative) total.sub(term) else total.add(term);
                }
                for (claims) |claim| {
                    for (claim.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidBlake3ParentClaims;
                    total = total.add(claim);
                }
                if (!total.isZero()) return error.UnclosedWideNativeSupply;
            }
        };
    };
}
