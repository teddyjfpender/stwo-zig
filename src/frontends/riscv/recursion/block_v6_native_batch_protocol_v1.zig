//! Explicit experimental native-batch proof protocol. Not an authorized closed
//! block root and not compatible with the wrapper-only forest receiver.
const std = @import("std");
const core = @import("stwo_core");
const base = @import("blake3_execution_parent_protocol.zig");
const bus = @import("block_v6_native_batch_public_v1.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const universal = @import("air/universal_challenges.zig");
pub const VERSION = bus.VERSION;
pub const CLAIM_TAG: u32 = 0x42364e43;
pub const Key = struct {
    profile: base.Profile,
    config: core.pcs.PcsConfig,
    context: base.Context,
    log_sizes: @FieldType(base.Key, "log_sizes"),
    preprocessed_root: [32]u8,
    public_schedule_digest: [32]u8,
    child_count: u32,
    pub fn fromGeometry(key: base.Key, wires: []const bus.Wire, child_count: usize) !Key {
        if (child_count == 0 or child_count > bus.MAX_CHILDREN) return error.InvalidNativeBatchCount;
        const result = Key{ .profile = key.profile, .config = key.config, .context = key.context, .log_sizes = key.log_sizes, .preprocessed_root = key.preprocessed_root, .public_schedule_digest = try bus.scheduleDigest(wires), .child_count = @intCast(child_count) };
        _ = try result.identity();
        return result;
    }
    pub fn identity(self: *const Key) ![32]u8 {
        if (self.child_count == 0 or self.child_count > bus.MAX_CHILDREN or
            self.context.statement_identity != null or self.context.span_binding_id != null or
            self.context.aggregation != null or self.context.exact_aggregation != null or self.context.quad_aggregation != null or
            std.mem.allEqual(u8, &self.public_schedule_digest, 0)) return error.InvalidNativeBatchKey;
        const geometry = base.Key{ .profile = self.profile, .config = self.config, .context = self.context, .log_sizes = self.log_sizes, .preprocessed_root = self.preprocessed_root };
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42364e4b, VERSION, self.child_count });
        channel.mixRoot(try geometry.identity());
        channel.mixRoot(self.public_schedule_digest);
        return channel.digestBytes();
    }
};
pub const Admission = struct {
    key: Key,
    expected_id: [32]u8,
    wires: []const bus.Wire,
    values: bus.Values,
    pub fn init(key: Key, expected: [32]u8, wires: []const bus.Wire, values: bus.Values) !Admission {
        const result = Admission{ .key = key, .expected_id = expected, .wires = wires, .values = values };
        try result.validate();
        return result;
    }
    pub fn validate(self: *const Admission) !void {
        if (!std.meta.eql(self.key.config, self.key.context.child_config) or
            self.values.children.len != self.key.child_count) return error.InvalidNativeBatchAdmission;
        if (!std.meta.eql(try self.key.identity(), self.expected_id) or
            !std.meta.eql(try bus.scheduleDigest(self.wires), self.key.public_schedule_digest)) return error.UntrustedNativeBatchKey;
        try self.values.validate();
        for (self.wires) |wire| _ = try self.values.at(wire);
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42364e49, VERSION });
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
        channel.mixU32s(&.{ 0x42364e50, VERSION, @intFromEnum(self.key.profile) });
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
        if (!sum.isZero()) return error.InvalidNativeBatchPublicClosure;
    }
};
