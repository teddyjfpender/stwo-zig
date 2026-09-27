//! Distinct genuine compact/public-root parent grammar. Register/program and
//! exact signed accounting equations close; complete source authority is OPEN.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("blake3_execution_parent_protocol.zig");
const Bus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Values = @import("block_v5_heterogeneous_scoped_public_values_v1.zig").Values;
pub const VERSION: u32 = 1;
pub const Profile = Base.Profile;
pub const Context = Base.Context;
pub const Key = struct {
    profile: Profile,
    config: core.pcs.PcsConfig,
    context: Context,
    log_sizes: @FieldType(Base.Key, "log_sizes"),
    preprocessed_root: [32]u8,
    public_schedule_digest: [32]u8,
    pub fn fromGeometry(key: Base.Key, wires: []const Bus.Wire) !Key {
        return .{ .profile = key.profile, .config = key.config, .context = key.context, .log_sizes = key.log_sizes, .preprocessed_root = key.preprocessed_root, .public_schedule_digest = try Bus.scheduleDigest(wires) };
    }
    pub fn identity(self: *const Key) ![32]u8 {
        if (self.context.statement_identity != null or self.context.span_binding_id != null or self.context.aggregation != null or self.context.exact_aggregation != null or self.context.quad_aggregation != null or std.mem.allEqual(u8, &self.public_schedule_digest, 0)) return error.InvalidReusableScopedPublicKey;
        const geometry = Base.Key{ .profile = self.profile, .config = self.config, .context = self.context, .log_sizes = self.log_sizes, .preprocessed_root = self.preprocessed_root };
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42354743, 0x4d50314b, VERSION });
        channel.mixRoot(try geometry.identity());
        channel.mixRoot(self.public_schedule_digest);
        return channel.digestBytes();
    }
};
pub const Admission = struct {
    pub const CLAIM_TAG: u32 = 0x42354743;
    key: Key,
    expected_id: [32]u8,
    wires: []const Bus.Wire,
    values: Values,
    pub fn validate(self: *const Admission) !void {
        try self.values.validate();
        if (!std.meta.eql(try self.key.identity(), self.expected_id) or !std.meta.eql(try Bus.scheduleDigest(self.wires), self.key.public_schedule_digest) or !std.meta.eql(self.key.config, self.key.context.child_config) or !std.meta.eql(self.key.config, self.values.owner.coverage.meta.security.recursive)) return error.UntrustedReusableScopedPublicKey;
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
        channel.mixU32s(&.{ 0x42354743, 0x4d503149, VERSION });
        channel.mixRoot(self.expected_id);
        self.values.mix(&channel);
        return channel.digestBytes();
    }
    pub fn mix(self: *const Admission, channel: anytype) !void {
        try self.validate();
        channel.mixU32s(&.{ 0x42354743, 0x4d503141, VERSION, @intFromEnum(self.key.profile) });
        self.key.config.mixInto(channel);
        channel.mixRoot(self.expected_id);
        self.values.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const core.fields.qm31.QM31) !void {
        try self.validate();
        if (claims.len != @import("blake3_native_parent_artifact.zig").CLAIM_COUNT) return error.InvalidBlake3ParentClaims;
        channel.mixU32s(&.{ CLAIM_TAG, 0x4d503151, VERSION, @import("blake3_native_parent_artifact.zig").CLAIM_COUNT });
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
        if (!total.isZero()) return error.UnclosedScopedPublicSupply;
    }
};
