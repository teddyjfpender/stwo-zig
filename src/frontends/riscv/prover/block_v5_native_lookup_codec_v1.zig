//! Bounded canonical six-table artifact. Independently admitted plans and PCS
//! security determine decoding; artifact metadata cannot choose either.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const postcard = @import("interop_postcard");
const family = @import("block_v5_native_lookup_proof_v1.zig");
const assembly = @import("block_v5_native_lookup_assembly_v1.zig");
const wire = @import("guest_precompile/proof_artifact_wire.zig");
const MAGIC = "B5LTART1";
pub const Limits = struct {
    artifact_bytes: usize = 64 * 1024 * 1024,
    proof_bytes: usize = 32 * 1024 * 1024,
    fn validate(self: Limits) !void {
        if (self.proof_bytes == 0 or self.proof_bytes > self.artifact_bytes)
            return error.InvalidBlockV5LookupWireLimits;
    }
};
pub fn encode(a: std.mem.Allocator, proof: *const family.Proof, plan: family.Plan, limits: Limits) ![]u8 {
    try limits.validate();
    const id = try plan.identity();
    var stark = std.Io.Writer.Allocating.init(a);
    defer stark.deinit();
    try postcard.serializeProof(suite.Hasher, &stark.writer, proof.stark);
    if (stark.written().len > limits.proof_bytes) return error.BlockV5LookupProofTooLarge;
    var output = std.Io.Writer.Allocating.init(a);
    errdefer output.deinit();
    try output.writer.writeAll(MAGIC);
    try output.writer.writeAll(&id);
    for (proof.claims) |claim| try wire.writeQm31(&output.writer, claim);
    try wire.writeInt(&output.writer, u64, stark.written().len);
    try output.writer.writeAll(stark.written());
    if (output.written().len > limits.artifact_bytes) return error.BlockV5LookupArtifactTooLarge;
    return output.toOwnedSlice();
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, plan: family.Plan, config: core.pcs.PcsConfig, limits: Limits) !family.Proof {
    try limits.validate();
    try @import("blake3_execution_protocol.zig").validateConfig(config);
    if (raw.len > limits.artifact_bytes) return error.BlockV5LookupArtifactTooLarge;
    var cursor = wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(MAGIC.len), MAGIC)) return error.InvalidBlockV5LookupMagic;
    if (!std.mem.eql(u8, try cursor.take(32), &try plan.identity())) return error.UntrustedBlockV5LookupWirePlan;
    var claims: [assembly.Count]core.fields.qm31.QM31 = undefined;
    for (&claims) |*claim| claim.* = try cursor.readQm31();
    const length = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.Overflow;
    if (length > limits.proof_bytes) return error.BlockV5LookupProofTooLarge;
    const proof_raw = try cursor.take(length);
    try cursor.requireDone();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    const fixed = try assembly.logs(scratch, .fixed);
    const main = try assembly.logs(scratch, .main);
    const interaction = try assembly.logs(scratch, .interaction);
    var max_log: u32 = 0;
    for (main) |log| max_log = @max(max_log, log);
    try postcard.proof_preflight.validate(proof_raw, .{
        .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size },
        .tree_columns = .{ @intCast(fixed.len), @intCast(main.len), @intCast(interaction.len), @intCast(core.verifier_types.compositionColumnCount(core.verifier_types.COMPOSITION_LOG_SPLIT, core.fields.qm31.SECURE_EXTENSION_DEGREE).?) },
        .max_column_log_size = max_log,
        .sample_width_limits = .{ 2, 2, 2, 1 },
        .hash_size = 32,
        .allow_zero_samples = true,
        .max_wire_bytes = limits.proof_bytes,
    });
    var stream = std.io.fixedBufferStream(proof_raw);
    var stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    if (stream.pos != proof_raw.len) return error.TrailingBlockV5LookupProof;
    return .{ .stark = stark, .claims = claims };
}
