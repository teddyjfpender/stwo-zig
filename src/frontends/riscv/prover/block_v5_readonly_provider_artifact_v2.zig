//! Bounded V2 provider envelope. Original postcard owns all STARK bytes; this
//! module owns only independently scoped canonical metadata, never acceptance.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const Wire = @import("guest_precompile/proof_artifact_wire.zig");
const Counting = @import("block_v5_cpu_counting_writer_v1.zig").Counting;
const Codec = @import("block_v5_cpu_stark_codec_v1.zig");
const Provider = @import("block_v5_readonly_input_provider_proof_v2.zig");
const Table = @import("block_v5_readonly_input_provider_v2.zig");
const Air = @import("block_v5_readonly_input_provider_component_v2.zig");
const Range = @import("block_v5_range16_v1.zig");
const RangeAir = @import("block_v5_range16_component_v1.zig");
const Roster = @import("block_v5_readonly_input_global_roster_v2.zig");
const Global = @import("block_v5_readonly_input_global_protocol_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const suite = core.proof_suites.Blake3;
pub const MAGIC = "B5PV2P01";
pub const CLAIM_BYTES = 16 * (2 + Table.RANGE_PLANES) + 3 * 8;
pub const HEADER_BYTES = MAGIC.len + 32 + 4 + 4 + 8 + CLAIM_BYTES;
pub const Limits = struct {
    max_artifact_bytes: usize = 65 << 20,
    max_proof_bytes: usize = 64 << 20,
    pub fn validate(self: Limits) !void {
        if (self.max_proof_bytes == 0 or self.max_artifact_bytes < HEADER_BYTES or self.max_proof_bytes > self.max_artifact_bytes - HEADER_BYTES) return error.InvalidReadonlyProviderArtifactLimits;
    }
};
pub const Expected = struct {
    provider: Roster.ProviderPin,
    range: Roster.RangePin,
    epoch: Global.Epoch,
    sealed_digest: [32]u8,
    pub fn fromAuthority(authority: *const Roster.Authority, index: u32, sealed: Seal.Sealed) !Expected {
        try authority.requireEpoch(sealed);
        const pin = try authority.provider(index);
        const result = Expected{ .provider = pin, .range = try authority.range(pin.range_index), .epoch = authority.epoch(), .sealed_digest = sealed.digest };
        try result.requireAuthority(authority, sealed);
        return result;
    }
    pub fn validate(self: Expected) !void {
        try self.provider.shape.require();
        try @import("blake3_execution_protocol.zig").validateConfig(self.provider.config);
        if (!std.meta.eql(self.provider.config, self.range.config) or self.range.index != self.provider.range_index or self.range.provider_index != self.provider.shape.index or
            self.range.group_id != self.provider.shape.group_id or self.range.shard.index != self.range.index or self.range.shard.first_instance != self.provider.shape.index or
            self.range.shard.instance_count != 1 or self.range.shard.request_count != self.provider.shape.counts.range_requests or self.range.shard.request_count > Range.MAX_REQUESTS or
            !std.meta.eql(self.provider.plan_digest, self.epoch.plan_digest) or !std.meta.eql(self.range.plan_digest, Roster.rangePlanDigest(self.epoch.plan_digest, self.provider.shape))) return error.UntrustedReadonlyProviderArtifactScope;
        for ([_][32]u8{ self.epoch.plan_digest, self.epoch.roster_digest, self.sealed_digest, self.provider.ordinal_digest, self.range.counter_digest } ++ self.provider.roots ++ self.range.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedReadonlyProviderArtifactScope;
    }
    pub fn requireAuthority(self: Expected, authority: *const Roster.Authority, sealed: Seal.Sealed) !void {
        try self.validate();
        try authority.requireEpoch(sealed);
        try authority.requireProvider(self.provider);
        try authority.requireRange(self.range);
        if (!std.meta.eql(self.epoch, authority.epoch()) or !std.meta.eql(self.sealed_digest, sealed.digest) or !std.meta.eql(self.provider.config, authority.config())) return error.UntrustedReadonlyProviderArtifactScope;
    }
    pub fn scopeDigest(self: Expected) ![32]u8 {
        try self.validate();
        var channel = suite.Channel{};
        channel.mixU32s(&.{ 0x42355056, 2, self.provider.shape.index, self.provider.shape.group_id, self.provider.shape.fragment_count, self.provider.shape.row_log, self.provider.range_index });
        channel.mixU64(self.provider.shape.first_fragment);
        channel.mixU64(self.provider.shape.counts.events);
        channel.mixU64(self.provider.shape.counts.readonly);
        channel.mixU64(self.provider.shape.counts.range_requests);
        channel.mixRoot(self.epoch.plan_digest);
        channel.mixRoot(self.epoch.roster_digest);
        channel.mixRoot(self.sealed_digest);
        channel.mixRoot(self.provider.ordinal_digest);
        for (self.provider.roots) |root| channel.mixRoot(root);
        channel.mixU32s(&.{ self.range.index, self.range.group_id, self.range.provider_index, self.range.shard.index, self.range.shard.first_instance, self.range.shard.instance_count });
        channel.mixU64(self.range.shard.request_count);
        channel.mixRoot(self.range.plan_digest);
        channel.mixRoot(self.range.counter_digest);
        for (self.range.roots) |root| channel.mixRoot(root);
        self.provider.config.mixInto(&channel);
        return channel.digestBytes();
    }
    pub fn rangeExpected(self: Expected) !Codec.Expected {
        try self.validate();
        return .{ .family = .range16, .index = self.range.index, .policy_digest = try self.scopeDigest(), .config = self.range.config, .roots = self.range.roots ++ .{@as([32]u8, @splat(0))}, .root_count = 2, .claim_count = 1, .geometry = .{ .tree_count = 4, .tree_columns = .{ RangeAir.Spec.FIXED_COUNT, RangeAir.Spec.MAIN_COUNT, RangeAir.Spec.INTERACTION_COUNT, @intCast(core.verifier_types.compositionColumnCount(RangeAir.Spec.EXPANSION_BITS, core.fields.qm31.SECURE_EXTENSION_DEGREE).?), 0 }, .max_column_log = try maximum(Range.TABLE_LOG, self.range.config), .max_merkle_log = try maximum(Range.TABLE_LOG, self.range.config), .sample_width_limits = .{ 1, 1, 2, 1, 1 } } };
    }
};
fn maximum(log: u32, config: core.pcs.PcsConfig) !u32 {
    if (config.lifting_log_size) |lifting| {
        if (lifting < log or lifting > 30) return error.UntrustedReadonlyProviderArtifactGeometry;
        return lifting;
    }
    return log;
}
pub fn requireClaim(expected: Expected, claim: Air.Claim) !void {
    if (!std.meta.eql(claim.counts, expected.provider.shape.counts)) return error.InvalidReadonlyProviderClaim;
    for ([_]core.fields.qm31.QM31{ claim.classification_sum, claim.read_sum } ++ claim.range_sums) |sum| if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidReadonlyProviderClaim;
}
fn writeClaim(writer: *std.Io.Writer, claim: Air.Claim) !void {
    for ([_]core.fields.qm31.QM31{ claim.classification_sum, claim.read_sum } ++ claim.range_sums) |sum| try Wire.writeQm31(writer, sum);
    inline for (.{ "events", "readonly", "range_requests" }) |name| try Wire.writeInt(writer, u64, @field(claim.counts, name));
}
fn readClaim(cursor: *Wire.Cursor) !Air.Claim {
    var result: Air.Claim = undefined;
    result.classification_sum = try cursor.readQm31();
    result.read_sum = try cursor.readQm31();
    for (&result.range_sums) |*sum| sum.* = try cursor.readQm31();
    inline for (.{ "events", "readonly", "range_requests" }) |name| @field(result.counts, name) = try cursor.readInt(u64);
    return result;
}
/// Envelope framing also used by corruption fixtures with NON-proof bytes.
/// Passing this split is not structural proof admission or cryptographic proof.
pub fn writeHeader(writer: *std.Io.Writer, expected: Expected, claim: Air.Claim, proof_bytes: usize) !void {
    try requireClaim(expected, claim);
    try writer.writeAll(MAGIC);
    const scope = try expected.scopeDigest();
    try writer.writeAll(&scope);
    try Wire.writeInt(writer, u32, expected.provider.shape.index);
    try Wire.writeInt(writer, u32, expected.provider.shape.group_id);
    try Wire.writeInt(writer, u64, proof_bytes);
    try writeClaim(writer, claim);
}
pub const Split = struct { claim: Air.Claim, proof: []const u8 };
pub fn split(raw: []const u8, expected: Expected, limits: Limits) !Split {
    try limits.validate();
    try expected.validate();
    if (raw.len > limits.max_artifact_bytes) return error.ReadonlyProviderArtifactTooLarge;
    const scope = try expected.scopeDigest();
    var cursor = Wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(MAGIC.len), MAGIC) or !std.mem.eql(u8, try cursor.take(32), &scope) or
        try cursor.readInt(u32) != expected.provider.shape.index or try cursor.readInt(u32) != expected.provider.shape.group_id) return error.UntrustedReadonlyProviderArtifactScope;
    const proof_bytes = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.Overflow;
    if (proof_bytes == 0 or proof_bytes > limits.max_proof_bytes) return error.ReadonlyProviderProofTooLarge;
    const claim = try readClaim(&cursor);
    try requireClaim(expected, claim);
    const proof = try cursor.take(proof_bytes);
    try cursor.requireDone();
    return .{ .claim = claim, .proof = proof };
}
fn requireProof(proof: *const Provider.Proof, expected: Expected) !void {
    try requireClaim(expected, proof.claim);
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, expected.provider.config) or roots.len != 4 or !std.meta.eql(roots[0..2].*, expected.provider.roots)) return error.UntrustedReadonlyProviderProof;
}
pub fn encode(a: std.mem.Allocator, proof: *const Provider.Proof, expected: Expected, limits: Limits) ![]u8 {
    try limits.validate();
    try expected.validate();
    try requireProof(proof, expected);
    var count = Counting.init(limits.max_proof_bytes);
    postcard.serializeProof(suite.Hasher, &count.writer, proof.stark) catch |err| {
        if (count.exceeded) return error.ReadonlyProviderProofTooLarge;
        return err;
    };
    const total = try std.math.add(usize, HEADER_BYTES, count.count);
    if (total > limits.max_artifact_bytes) return error.ReadonlyProviderArtifactTooLarge;
    const raw = try a.alloc(u8, total);
    errdefer a.free(raw);
    var writer = std.Io.Writer.fixed(raw);
    try writeHeader(&writer, expected, proof.claim, count.count);
    try postcard.serializeProof(suite.Hasher, &writer, proof.stark);
    if (writer.buffered().len != total) return error.ChangedReadonlyProviderSerialization;
    return raw;
}
pub fn preflight(proof_raw: []const u8, expected: Expected, limits: Limits) !void {
    try limits.validate();
    try expected.validate();
    const config = expected.provider.config;
    try postcard.proof_preflight.validate(proof_raw, .{ .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size }, .tree_columns = .{ Air.Spec.FIXED_COUNT, Air.Spec.MAIN_COUNT, Air.Spec.INTERACTION_COUNT, @intCast(core.verifier_types.compositionColumnCount(Air.Spec.EXPANSION_BITS, core.fields.qm31.SECURE_EXTENSION_DEGREE).?) }, .max_column_log_size = try maximum(expected.provider.shape.row_log, config), .max_merkle_column_log_size = try maximum(expected.provider.shape.row_log, config), .sample_width_limits = .{ 1, 2, 2, 1 }, .allow_zero_samples = true, .hash_size = 32, .max_wire_bytes = limits.max_proof_bytes });
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, expected: Expected, limits: Limits) !Provider.Proof {
    const framed = try split(raw, expected, limits);
    try preflight(framed.proof, expected, limits); // before ALL parser allocations
    var stream = std.io.fixedBufferStream(framed.proof);
    var result = Provider.Proof{ .claim = framed.claim, .stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader()) };
    errdefer result.deinit(a);
    if (stream.pos != framed.proof.len) return error.TrailingReadonlyProviderProof;
    try requireProof(&result, expected);
    return result;
}
pub fn encodeRange(a: std.mem.Allocator, proof: *const @import("block_v5_range16_proof_v1.zig").Proof, expected: Expected, limits: Limits) ![]u8 {
    try limits.validate();
    if (proof.claim.count != expected.range.shard.request_count) return error.InvalidReadonlyProviderRangeCount;
    return Codec.encode(.range16, a, proof, try expected.rangeExpected(), .{ .artifact_bytes = limits.max_artifact_bytes, .proof_bytes = limits.max_proof_bytes, .max_claims = 1 });
}
pub fn decodeRange(a: std.mem.Allocator, raw: []const u8, expected: Expected, limits: Limits) !@import("block_v5_range16_proof_v1.zig").Proof {
    try limits.validate();
    var proof = try Codec.decode(.range16, a, raw, try expected.rangeExpected(), .{ .artifact_bytes = limits.max_artifact_bytes, .proof_bytes = limits.max_proof_bytes, .max_claims = 1 });
    errdefer proof.deinit(a);
    if (proof.claim.count != expected.range.shard.request_count) return error.InvalidReadonlyProviderRangeCount;
    return proof;
}
