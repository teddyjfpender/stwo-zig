//! Distinct actual parent protocol for one authenticated input-tail provider.
//! No execution/source/global completeness authority is implied by this proof.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("blake3_execution_parent_protocol.zig");
const Public = @import("block_v5_input_tail_public_v1.zig");
const Artifact = @import("blake3_native_parent_artifact.zig");
pub const VERSION: u32 = 1;
pub const Profile = Base.Profile;
pub const Key = struct {
    profile: Profile,
    config: core.pcs.PcsConfig,
    context: Base.Context,
    log_sizes: @FieldType(Base.Key, "log_sizes"),
    preprocessed_root: [32]u8,
    pub fn fromGeometry(original: Base.Key) Key {
        return .{ .profile = original.profile, .config = original.config, .context = original.context, .log_sizes = original.log_sizes, .preprocessed_root = original.preprocessed_root };
    }
    pub fn geometry(self: *const Key) Base.Key {
        return .{ .profile = self.profile, .config = self.config, .context = self.context, .log_sizes = self.log_sizes, .preprocessed_root = self.preprocessed_root };
    }
    pub fn identity(self: *const Key) ![32]u8 {
        if (self.context.statement_identity != null or self.context.span_binding_id != null or self.context.aggregation != null or self.context.exact_aggregation != null or self.context.quad_aggregation != null or !std.meta.eql(self.config, self.context.child_config)) return error.InvalidInputTailKey;
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x4235544b, VERSION });
        channel.mixRoot(sourceAuthority());
        const original_geometry = self.geometry();
        channel.mixRoot(try original_geometry.identity());
        return channel.digestBytes();
    }
};
pub const Admission = struct {
    key: Key,
    expected_id: [32]u8,
    public: *const Public.Owned,
    expected_input: Public.Pin,
    pub fn init(key: Key, expected_id: [32]u8, public: *const Public.Owned, expected_input: Public.Pin) !Admission {
        const admitted = Admission{ .key = key, .expected_id = expected_id, .public = public, .expected_input = expected_input };
        try admitted.validate();
        return admitted;
    }
    pub fn validate(self: *const Admission) !void {
        try self.public.require(self.expected_input);
        if (!std.meta.eql(try self.key.identity(), self.expected_id) or !std.meta.eql(self.key.context.child_key_id, self.public.statement_id)) return error.UntrustedInputTailKey;
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42355449, VERSION });
        channel.mixRoot(self.expected_id);
        self.public.mix(&channel);
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
        channel.mixU32s(&.{ 0x42355443, VERSION, @intFromEnum(self.key.profile) });
        self.key.config.mixInto(channel);
        channel.mixRoot(self.expected_id);
        self.public.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const core.fields.qm31.QM31) !void {
        try self.validate();
        if (claims.len != Artifact.CLAIM_COUNT) return error.InvalidBlake3ParentClaims;
        channel.mixU32s(&.{ 0x42355451, VERSION, Artifact.CLAIM_COUNT });
        channel.mixFelts(claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: Artifact.Claims, _: @import("air/universal_challenges.zig").UniversalRelations) !void {
        try self.validate();
        var sum = core.fields.qm31.QM31.zero();
        for (claims) |claim| {
            for (claim.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidBlake3ParentClaims;
            sum = sum.add(claim);
        }
        if (!sum.isZero()) return error.InvalidInputTailPublicClosure;
    }
};
pub fn sourceAuthority() [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42355453, VERSION });
    inline for (.{ @embedFile("block_v5_input_tail_public_v1.zig"), @embedFile("block_v5_input_tail_protocol_v1.zig"), @embedFile("block_v5_input_tail_receiver_v1.zig"), @embedFile("block_v5_input_tail_source_v1.zig"), @embedFile("../prover/block_v5_input_tail_stage_v1.zig"), @embedFile("air/block_v5_input_tail_rows_v1.zig"), @embedFile("blake3_words_tail_v1.zig"), @embedFile("air/blake3_hash_plan.zig"), @embedFile("air/blake3_frame_witness.zig"), @embedFile("air/blake3_frame_route.zig"), @embedFile("air/blake3_g_call.zig"), @embedFile("air/blake3_xor_call.zig"), @embedFile("air/blake3_byte_route.zig"), @embedFile("air/blake3_boundary.zig"), @embedFile("air/blake3_private_word.zig") }) |source| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(source, &digest, .{});
        channel.mixRoot(digest);
    }
    return channel.digestBytes();
}
