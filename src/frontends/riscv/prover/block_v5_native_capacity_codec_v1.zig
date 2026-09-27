//! Distinct B5CT artifact with independently supplied capacity/count geometry.
//! Claims and postcard arrays are bounded before allocating; one encode buffer.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const suite = core.proof_suites.Blake3;
const native = @import("block_v5_native_capacity_proof_v1.zig");
const template = @import("block_v5_native_capacity_protocol_v1.zig");
const statement = @import("../air/statement.zig");
const ArtifactWriter = @import("bounded_artifact_writer_v1.zig").Writer;
const wire = @import("guest_precompile/proof_artifact_wire.zig");
pub const MAGIC = "B5CTART1";
pub const HEADER_BYTES = MAGIC.len + 4 + 96 + 8 + 4;
pub const Expected = struct {
    shape: *const statement.Blake3ExecutionStatement,
    external_retirements: u32,
    template_id: [32]u8,
    instance_id: [32]u8,
    config: core.pcs.PcsConfig,
    capacity_digest: [32]u8,
    native_limits: native.Limits = .{},
    pub fn validate(self: Expected) !void {
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        const plan = try template.Plan.fromShape(self.shape, self.external_retirements);
        try self.native_limits.require(&plan, self.shape);
        if (std.mem.allEqual(u8, &self.template_id, 0) or std.mem.allEqual(u8, &self.instance_id, 0) or
            !std.meta.eql(self.capacity_digest, try template.capacityDigest(self.shape, self.external_retirements))) return error.UntrustedNativeCapacityWireIdentity;
        // Only native clock helpers may accompany ordinary opcode columns.
        for (self.shape.infra_descs[0..self.shape.n_infra]) |desc|
            if (desc.kind != .clock_update) return error.InvalidNativeCapacityWireShape;
    }
};
pub const Limits = struct {
    proof_bytes: usize = 32 * 1024 * 1024,
    artifact_bytes: usize = 64 * 1024 * 1024,
    max_claims: usize = 1 << 16,
    max_claim_bytes: usize = 4 << 20,
    pub fn validate(self: Limits) !void {
        if (self.proof_bytes == 0 or self.proof_bytes > self.artifact_bytes or self.max_claims == 0 or self.max_claim_bytes < @sizeOf(statement.RiscVInteractionClaim))
            return error.InvalidNativeCapacityWireLimits;
    }
};
fn claimCount(shape: *const statement.Blake3ExecutionStatement) usize {
    var count: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc|
        count += @import("../air/lookups/opcode_entries.zig").batchCount(desc.family);
    for (shape.infra_descs[0..shape.n_infra]) |desc| count += statement.nClaimedSumsForInfra(desc.kind);
    return count;
}
pub fn encode(a: std.mem.Allocator, proof: *const native.Proof, expected: Expected, limits: Limits) ![]u8 {
    try expected.validate();
    try limits.validate();
    if (claimCount(expected.shape) > limits.max_claims) return error.NativeCapacityWireClaimLimit;
    try native.requireProtocol(proof.protocol_version);
    if (!std.meta.eql(proof.template_id, expected.template_id) or !std.meta.eql(proof.instance_id, expected.instance_id) or
        !std.meta.eql(proof.stark.commitment_scheme_proof.config, expected.config)) return error.UntrustedNativeCapacityWireIdentity;
    if (proof.claims.interaction_pow != 0) return error.InvalidNativeCapacityWireClaims;
    var check = suite.Channel{};
    try template.mixClaims(&check, expected.shape, proof.claims);
    const body_at = try std.math.add(usize, HEADER_BYTES, try std.math.mul(usize, 16, claimCount(expected.shape)));
    if (body_at > limits.artifact_bytes) return error.NativeCapacityWireArtifactTooLarge;
    const proof_cap = try std.math.add(usize, body_at, limits.proof_bytes);
    var output = ArtifactWriter.init(a, @min(proof_cap, limits.artifact_bytes));
    defer output.deinit();
    try output.writeAll(MAGIC);
    try wire.writeInt(&output, u32, template.VERSION);
    try output.writeAll(&proof.template_id);
    try output.writeAll(&proof.instance_id);
    try output.writeAll(&expected.capacity_digest);
    try wire.writeInt(&output, u64, 0); // Backpatched after bounded serialization.
    try wire.writeInt(&output, u32, @intCast(claimCount(expected.shape)));
    for (expected.shape.component_descs[0..expected.shape.n_components], 0..) |desc, index|
        for (try proof.claims.opcodeClaims(desc.family, index)) |claim| try output.writeClaim(claim);
    for (expected.shape.infra_descs[0..expected.shape.n_infra], 0..) |desc, index|
        for (try proof.claims.infraClaims(desc.kind, index)) |claim| try output.writeClaim(claim);
    if (output.bytes.items.len != body_at) return error.InvalidNativeCapacityWireClaims;
    postcard.serializeProof(suite.Hasher, &output, proof.stark) catch |err| switch (err) {
        error.ArtifactTooLarge => return if (proof_cap <= limits.artifact_bytes) error.NativeCapacityWireProofTooLarge else error.NativeCapacityWireArtifactTooLarge,
        else => return err,
    };
    std.mem.writeInt(u64, output.bytes.items[108..116], output.bytes.items.len - body_at, .little);
    return output.toOwnedSlice();
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, expected: Expected, limits: Limits) !native.Proof {
    try expected.validate();
    try limits.validate();
    if (claimCount(expected.shape) > limits.max_claims) return error.NativeCapacityWireClaimLimit;
    if (raw.len > limits.artifact_bytes) return error.NativeCapacityWireArtifactTooLarge;
    var cursor = wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(8), MAGIC)) return error.InvalidNativeCapacityWireMagic;
    try native.requireProtocol(try cursor.readInt(u32));
    if (!std.mem.eql(u8, try cursor.take(32), &expected.template_id) or !std.mem.eql(u8, try cursor.take(32), &expected.instance_id) or !std.mem.eql(u8, try cursor.take(32), &expected.capacity_digest))
        return error.UntrustedNativeCapacityWireIdentity;
    const length = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.Overflow;
    if (length == 0 or length > limits.proof_bytes) return error.NativeCapacityWireProofTooLarge;
    if (try cursor.readInt(u32) != claimCount(expected.shape)) return error.InvalidNativeCapacityWireClaims;
    const claims_raw = try cursor.take(try std.math.mul(usize, 16, claimCount(expected.shape)));
    var claim_cursor = wire.Cursor.init(claims_raw);
    for (0..claimCount(expected.shape)) |_| _ = try claim_cursor.readQm31();
    const proof_raw = try cursor.take(length);
    try cursor.requireDone();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    const fixed = try template.columnLogs(scratch, expected.shape, expected.external_retirements, .fixed);
    const main = try template.columnLogs(scratch, expected.shape, expected.external_retirements, .main);
    const interaction = try template.columnLogs(scratch, expected.shape, expected.external_retirements, .interaction);
    const max_log = try maximumProofColumnLog(expected);
    try postcard.proof_preflight.validate(proof_raw, .{
        .config = .{ .pow_bits = expected.config.pow_bits, .log_blowup_factor = expected.config.fri_config.log_blowup_factor, .n_queries = expected.config.fri_config.n_queries, .log_last_layer_degree_bound = expected.config.fri_config.log_last_layer_degree_bound, .fold_step = expected.config.fri_config.fold_step, .lifting_log_size = expected.config.lifting_log_size },
        .tree_columns = .{ @intCast(fixed.len), @intCast(main.len), @intCast(interaction.len), @intCast(core.verifier_types.compositionColumnCount(core.verifier_types.COMPOSITION_LOG_SPLIT, core.fields.qm31.SECURE_EXTENSION_DEGREE).?) },
        .max_column_log_size = max_log,
        .sample_width_limits = .{ 2, 2, 2, 1 },
        .allow_zero_samples = true,
        .hash_size = 32,
        .max_wire_bytes = limits.proof_bytes,
    });
    const claims = try a.create(statement.RiscVInteractionClaim);
    errdefer a.destroy(claims);
    claims.initZeroInto();
    claims.n_components = expected.shape.n_components;
    claims.n_infra = expected.shape.n_infra;
    claim_cursor = wire.Cursor.init(claims_raw);
    for (expected.shape.component_descs[0..expected.shape.n_components], 0..) |desc, index| {
        for (claims.opcode_claims[index][0..@import("../air/lookups/opcode_entries.zig").batchCount(desc.family)]) |*claim| claim.* = try claim_cursor.readQm31();
    }
    for (expected.shape.infra_descs[0..expected.shape.n_infra], 0..) |desc, index| {
        for (0..statement.nClaimedSumsForInfra(desc.kind)) |sum_index| try claims.setInfraClaim(desc.kind, index, sum_index, try claim_cursor.readQm31());
    }
    try claim_cursor.requireDone();
    var stream = std.io.fixedBufferStream(proof_raw);
    var stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    if (stream.pos != length) return error.InvalidNativeCapacityWireProofLength;
    return .{ .stark = stark, .claims = claims, .template_id = expected.template_id, .instance_id = expected.instance_id };
}

/// The degree-three prefix constraint expands to N+2. Splitting by one makes
/// the composition columns N+1, even when original native equations are quadratic.
pub fn maximumProofColumnLog(expected: Expected) !u32 {
    var result = try @import("block_v5_native_template_protocol_v3.zig").maximumProofColumnLog(expected.shape, expected.external_retirements);
    const plan = try template.Plan.fromShape(expected.shape, expected.external_retirements);
    for (plan.active()) |shard| result = @max(result, shard.log_size + 1);
    return result;
}
