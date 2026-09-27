//! Bounded native-v3 artifact; admission/geometry are supplied independently.
//! No old commitment Plan, hash-custody claims or proof-selected key enters it.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const suite = core.proof_suites.Blake3;
const native = @import("block_v5_native_execution_proof_v3.zig");
const template = @import("block_v5_native_template_protocol_v3.zig");
const statement = @import("../air/statement.zig");
const ArtifactWriter = @import("bounded_artifact_writer_v1.zig").Writer;
const wire = @import("guest_precompile/proof_artifact_wire.zig");
const MAGIC = "B5NEART3";
const HEADER_BYTES = MAGIC.len + 64 + 8;
pub const Expected = struct {
    shape: *const statement.Blake3ExecutionStatement,
    external_retirements: u32,
    template_id: [32]u8,
    instance_id: [32]u8,
    config: core.pcs.PcsConfig,
    fn validate(self: Expected) !void {
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        try self.shape.validateBlake3ExecutionWithExternal(self.external_retirements);
        // Only native clock helpers may accompany ordinary opcode columns.
        for (self.shape.infra_descs[0..self.shape.n_infra]) |desc|
            if (desc.kind != .clock_update) return error.InvalidNativeV3WireShape;
    }
};
pub const Limits = struct {
    proof_bytes: usize = 32 * 1024 * 1024,
    artifact_bytes: usize = 64 * 1024 * 1024,
    fn validate(self: Limits) !void {
        if (self.proof_bytes == 0 or self.proof_bytes > self.artifact_bytes)
            return error.InvalidNativeV3WireLimits;
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
    if (!std.meta.eql(proof.template_id, expected.template_id) or !std.meta.eql(proof.instance_id, expected.instance_id) or
        !std.meta.eql(proof.stark.commitment_scheme_proof.config, expected.config)) return error.UntrustedNativeV3WireIdentity;
    if (proof.claims.interaction_pow != 0) return error.InvalidNativeV3WireClaims;
    var check = suite.Channel{};
    try template.mixClaims(&check, expected.shape, proof.claims);
    const body_at = try std.math.add(usize, HEADER_BYTES, try std.math.mul(usize, 16, claimCount(expected.shape)));
    if (body_at > limits.artifact_bytes) return error.NativeV3WireArtifactTooLarge;
    const proof_cap = try std.math.add(usize, body_at, limits.proof_bytes);
    var output = ArtifactWriter.init(a, @min(proof_cap, limits.artifact_bytes));
    defer output.deinit();
    try output.writeAll(MAGIC);
    try output.writeAll(&proof.template_id);
    try output.writeAll(&proof.instance_id);
    try wire.writeInt(&output, u64, 0); // Backpatched after bounded serialization.
    for (expected.shape.component_descs[0..expected.shape.n_components], 0..) |desc, index|
        for (try proof.claims.opcodeClaims(desc.family, index)) |claim| try output.writeClaim(claim);
    for (expected.shape.infra_descs[0..expected.shape.n_infra], 0..) |desc, index|
        for (try proof.claims.infraClaims(desc.kind, index)) |claim| try output.writeClaim(claim);
    if (output.bytes.items.len != body_at) return error.InvalidNativeV3WireClaims;
    postcard.serializeProof(suite.Hasher, &output, proof.stark) catch |err| switch (err) {
        error.ArtifactTooLarge => return if (proof_cap <= limits.artifact_bytes) error.NativeV3WireProofTooLarge else error.NativeV3WireArtifactTooLarge,
        else => return err,
    };
    std.mem.writeInt(u64, output.bytes.items[72..80], output.bytes.items.len - body_at, .little);
    return output.toOwnedSlice();
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, expected: Expected, limits: Limits) !native.Proof {
    try expected.validate();
    try limits.validate();
    if (raw.len > limits.artifact_bytes) return error.NativeV3WireArtifactTooLarge;
    var cursor = wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(8), MAGIC)) return error.InvalidNativeV3WireMagic;
    if (!std.mem.eql(u8, try cursor.take(32), &expected.template_id) or !std.mem.eql(u8, try cursor.take(32), &expected.instance_id))
        return error.UntrustedNativeV3WireIdentity;
    const length = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.Overflow;
    if (length == 0 or length > limits.proof_bytes) return error.NativeV3WireProofTooLarge;
    const claims_raw = try cursor.take(16 * claimCount(expected.shape));
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
    const max_log = try template.maximumProofColumnLog(expected.shape, expected.external_retirements);
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
    if (stream.pos != length) return error.InvalidNativeV3WireProofLength;
    return .{ .stark = stark, .claims = claims, .template_id = expected.template_id, .instance_id = expected.instance_id };
}
