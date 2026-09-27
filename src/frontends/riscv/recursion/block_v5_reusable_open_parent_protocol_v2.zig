//! Bounded open v3 fold setup identity contains geometry/routing only. Public
//! instance values are independently admitted and absorbed before commitments.
const std = @import("std");
const core = @import("stwo_core");
const base = @import("blake3_execution_parent_protocol.zig");
const bus = @import("block_v5_open_parent_public_bus_v2.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const universal = @import("air/universal_challenges.zig");
pub const VERSION: u32 = 2;
pub const Profile = base.Profile;
pub const Context = base.Context;
pub const Key = struct {
    profile: Profile,
    config: core.pcs.PcsConfig,
    context: Context,
    log_sizes: @FieldType(base.Key, "log_sizes"),
    preprocessed_root: [32]u8,
    public_schedule_digest: [32]u8,
    pub fn fromGeometry(key: base.Key, wires: []const bus.Wire) !Key {
        return .{ .profile = key.profile, .config = key.config, .context = key.context, .log_sizes = key.log_sizes, .preprocessed_root = key.preprocessed_root, .public_schedule_digest = try bus.scheduleDigest(wires) };
    }
    pub fn identity(self: *const Key) ![32]u8 {
        if (self.context.statement_identity != null or self.context.span_binding_id != null or
            self.context.aggregation != null or self.context.exact_aggregation != null or self.context.quad_aggregation != null or
            std.mem.allEqual(u8, &self.public_schedule_digest, 0)) return error.InvalidReusableOpenParentKey;
        const geometry = base.Key{ .profile = self.profile, .config = self.config, .context = self.context, .log_sizes = self.log_sizes, .preprocessed_root = self.preprocessed_root };
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42354f4b, VERSION });
        channel.mixRoot(try geometry.identity());
        channel.mixRoot(self.public_schedule_digest);
        return channel.digestBytes();
    }
};
pub const Admission = struct {
    key: Key,
    expected_id: [32]u8,
    /// Both schedules and values belong to independent public verifier policy.
    /// Proof envelopes cannot select either one.
    wires: []const bus.Wire,
    values: bus.Values,
    pub fn init(key: Key, expected_id: [32]u8, wires: []const bus.Wire, values: bus.Values) !Admission {
        const result = Admission{ .key = key, .expected_id = expected_id, .wires = wires, .values = values };
        try result.validate();
        return result;
    }
    pub fn validate(self: *const Admission) !void {
        if (!std.meta.eql(self.key.config, self.key.context.child_config)) return error.V5OpenParentSecurityMismatch;
        for (self.values.children) |child| {
            if (!std.meta.eql(self.key.config, child.key.config) or
                !std.meta.eql(self.key.config, child.key.context.child_config)) return error.V5OpenParentSecurityMismatch;
        }
        if (!std.meta.eql(try self.key.identity(), self.expected_id) or
            !std.meta.eql(try bus.scheduleDigest(self.wires), self.key.public_schedule_digest)) return error.UntrustedReusableOpenParentKey;
        try self.values.validate();
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42354f49, VERSION });
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
        channel.mixU32s(&.{ 0x42354f50, VERSION, @intFromEnum(self.key.profile) });
        self.key.config.mixInto(channel);
        channel.mixRoot(self.expected_id);
        self.values.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const core.fields.qm31.QM31) !void {
        try self.validate();
        if (claims.len != artifact.CLAIM_COUNT) return error.InvalidBlake3ParentClaims;
        channel.mixU32s(&.{ 0x42354f43, VERSION, artifact.CLAIM_COUNT });
        channel.mixFelts(claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: artifact.Claims, relations: universal.UniversalRelations) !void {
        try self.validate();
        var total = try bus.supply(self.wires, self.values, relations);
        for (claims) |claim| {
            for (claim.toM31Array()) |value| if (value.v >= core.fields.m31.Modulus) return error.InvalidBlake3ParentClaims;
            total = total.add(claim);
        }
        if (!total.isZero()) return error.InvalidReusableOpenParentPublicClosure;
    }
};
