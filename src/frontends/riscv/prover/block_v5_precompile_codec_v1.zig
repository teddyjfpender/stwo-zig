//! Strict staged arithmetic envelope. Geometry and security are supplied by
//! independent receiver policy; no proof-carried statement selects its key.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const postcard = @import("interop_postcard");
const profile = @import("blake3_ethereum_sha_profile.zig");
const family = @import("block_v5_precompile_family_proof_v1.zig");
const wire = @import("guest_precompile/proof_artifact_wire.zig");
const protocol = @import("block_v5_precompile_protocol_v1.zig");
const Statement = profile.admission.Statement;
const MAGIC = "B5PFART1";
pub const Limits = struct {
    artifact_bytes: usize = 64 * 1024 * 1024,
    proof_bytes: usize = 32 * 1024 * 1024,
    fn validate(self: Limits) !void {
        if (self.proof_bytes == 0 or self.proof_bytes > self.artifact_bytes)
            return error.InvalidBlockV5PrecompileWireLimits;
    }
};

pub fn encode(a: std.mem.Allocator, proof: *const family.Proof, statement: *const Statement, limits: Limits) ![]u8 {
    try limits.validate();
    try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, statement);
    var claims = std.Io.Writer.Allocating.init(a);
    defer claims.deinit();
    try profile.ClaimWire.encodeExtensionClaim(&claims.writer, statement, &proof.claims);
    var stark = std.Io.Writer.Allocating.init(a);
    defer stark.deinit();
    try postcard.serializeProof(suite.Hasher, &stark.writer, proof.stark);
    if (stark.written().len > limits.proof_bytes) return error.BlockV5PrecompileProofTooLarge;
    var output = std.Io.Writer.Allocating.init(a);
    errdefer output.deinit();
    try output.writer.writeAll(MAGIC);
    try output.writer.writeAll(&proof.key_id);
    try output.writer.writeAll(&proof.instance_id);
    try wire.writeInt(&output.writer, u32, std.math.cast(u32, claims.written().len) orelse return error.Overflow);
    try wire.writeInt(&output.writer, u64, stark.written().len);
    try output.writer.writeAll(claims.written());
    try output.writer.writeAll(stark.written());
    if (output.written().len > limits.artifact_bytes) return error.BlockV5PrecompileArtifactTooLarge;
    return output.toOwnedSlice();
}

pub fn decode(a: std.mem.Allocator, raw: []const u8, statement: *const Statement, config: core.pcs.PcsConfig, limits: Limits) !family.Proof {
    try limits.validate();
    try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, statement);
    if (raw.len > limits.artifact_bytes) return error.BlockV5PrecompileArtifactTooLarge;
    var cursor = wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(MAGIC.len), MAGIC)) return error.InvalidBlockV5PrecompileMagic;
    const key_id = (try cursor.take(32))[0..32].*;
    const instance_id = (try cursor.take(32))[0..32].*;
    const claim_len = try cursor.readInt(u32);
    const proof_len = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.Overflow;
    if (proof_len > limits.proof_bytes) return error.BlockV5PrecompileProofTooLarge;
    var claim_cursor = wire.Cursor.init(try cursor.take(claim_len));
    const claims = try profile.ClaimWire.decodeExtensionClaim(&claim_cursor, statement);
    try claim_cursor.requireDone();
    const proof_raw = try cursor.take(proof_len);
    try cursor.requireDone();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    const fixed = try protocol.columnLogs(scratch, statement, .fixed);
    const main = try protocol.columnLogs(scratch, statement, .main);
    const interaction = try protocol.columnLogs(scratch, statement, .interaction);
    var max_log: u32 = 0;
    for (profile.descriptors(statement)) |desc| max_log = @max(max_log, desc.log_size);
    try postcard.proof_preflight.validate(proof_raw, .{
        .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size },
        .tree_columns = .{ @intCast(fixed.len), @intCast(main.len), @intCast(interaction.len), @intCast(core.verifier_types.compositionColumnCount(core.verifier_types.COMPOSITION_LOG_SPLIT, core.fields.qm31.SECURE_EXTENSION_DEGREE).?) },
        .max_column_log_size = max_log,
        // Keccak's authenticated rotation masks open up to six main points;
        // the SHA suffix stays within that existing typed-profile bound.
        .sample_width_limits = .{ 2, 6, 2, 1 },
        .hash_size = 32,
        .allow_zero_samples = true,
        .max_wire_bytes = limits.proof_bytes,
    });
    var stream = std.io.fixedBufferStream(proof_raw);
    var stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    if (stream.pos != proof_raw.len) return error.TrailingBlockV5PrecompileProof;
    return .{ .stark = stark, .claims = claims, .key_id = key_id, .instance_id = instance_id };
}
