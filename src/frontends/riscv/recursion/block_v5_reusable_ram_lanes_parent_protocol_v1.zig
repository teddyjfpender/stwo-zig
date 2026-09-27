//! Distinct RAM lane recursive verifier authority. All changing provider
//! statement values are supplied publicly, including exact counts and bus sums.
const std = @import("std");
const core = @import("stwo_core");
const base = @import("blake3_execution_parent_protocol.zig");
const bus = @import("block_v5_ram_lanes_recursive_public_bus_v1.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const universal = @import("air/universal_challenges.zig");
pub const VERSION: u32 = 1;
pub const CLAIM_TAG: u32 = 0x42354c51; // B5LQ RAM recursive claims.
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
            std.mem.allEqual(u8, &self.public_schedule_digest, 0)) return error.InvalidReusableRamParentKey;
        const geometry = base.Key{ .profile = self.profile, .config = self.config, .context = self.context, .log_sizes = self.log_sizes, .preprocessed_root = self.preprocessed_root };
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42354c4b, VERSION });
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
        if (!std.meta.eql(self.key.config, self.key.context.child_config) or
            !std.meta.eql(self.key.config, self.values.pin.config)) return error.RamRecursiveSecurityMismatch;
        if (!std.meta.eql(try self.key.identity(), self.expected_id) or
            !std.meta.eql(try bus.scheduleDigest(self.wires), self.key.public_schedule_digest)) return error.UntrustedReusableRamParentKey;
        try self.values.validate();
        if (!std.meta.eql(self.key.context.child_key_id, self.values.template)) return error.UntrustedRamRecursiveTemplate;
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42354c41, VERSION });
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
        channel.mixU32s(&.{ 0x42354c50, VERSION, @intFromEnum(self.key.profile) });
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
        var total = try bus.supply(self.wires, self.values, relations);
        for (claims) |claim| {
            for (claim.toM31Array()) |value| if (value.v >= core.fields.m31.Modulus) return error.InvalidBlake3ParentClaims;
            total = total.add(claim);
        }
        if (!total.isZero()) return error.InvalidReusableRamParentPublicClosure;
    }
};
