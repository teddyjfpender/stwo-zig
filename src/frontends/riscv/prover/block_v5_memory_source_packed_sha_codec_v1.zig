//! Owned strict PAGE kernel artifact. SHA/file pins provide transport integrity
//! only; callers must invoke the actual fresh kernel receiver after decoding.
//! Full SOURCE authority additionally requires the remaining semantic/fold joins.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const suite = core.proof_suites.Blake3;
const Kernel = @import("block_v5_memory_source_packed_sha_proof_v1.zig");
const Operand = @import("block_v5_memory_source_packed_sha_replay_v1.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Wire = @import("guest_precompile/proof_artifact_wire.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
const Q = core.fields.qm31.QM31;
pub const MAGIC = "B5SKART1";
pub const HEADER_BYTES = MAGIC.len + 4 + 96 + 8 + 8 + 16 * 38;
pub const Limits = struct {
    max_proof_bytes: usize = 32 << 20,
    max_artifact_bytes: usize = 33 << 20,
    pub fn require(self: Limits) !void {
        if (self.max_proof_bytes == 0 or self.max_artifact_bytes < HEADER_BYTES or self.max_proof_bytes > self.max_artifact_bytes - HEADER_BYTES) return error.InvalidSourceShaKernelCodecLimits;
    }
};
pub fn maximumColumnLog(pin: Operand.Pin) !u32 {
    var maximum = pin.raw.page.row_log;
    for (pin.geometry.logs) |log| maximum = @max(maximum, log);
    maximum = @max(maximum, @import("../air/lookups/tables/schema.zig").logSize(.bitwise));
    maximum = @max(maximum, @import("../air/lookups/tables/schema.zig").logSize(.range_check_8_8));
    if (pin.raw.config.lifting_log_size) |lifting| {
        if (lifting < maximum or lifting > 30) return error.InvalidSourceShaKernelGeometry;
        maximum = lifting;
    }
    return maximum;
}
pub fn preflight(raw: []const u8, expected: Operand.Pin, limits: Limits) !void {
    try limits.require();
    var counts: [8]u32 = undefined;
    // Exact derived inventories, not sizes read from a payload.
    // Scratch headers are unnecessary for this pure count calculation.
    counts[0] = Schema.FIXED_COUNT;
    counts[1] = Schema.MAIN_COUNT;
    var fixed: u32 = 0;
    var main: u32 = 2;
    var interaction: u32 = 8;
    inline for (@import("block_v5_memory_source_packed_sha_columns_v1.zig").Airs) |Air| {
        fixed += Air.PREPROCESSED_COLUMN_COUNT;
        main += Air.PHYSICAL_MAIN_COLUMN_COUNT;
        interaction += Air.INTERACTION_COLUMN_COUNT;
    }
    const Tables = @import("../air/lookups/tables/schema.zig");
    fixed += @intCast(Tables.arity(.bitwise) + Tables.arity(.range_check_8_8) + 2);
    counts[2] = fixed;
    counts[3] = main;
    const Air = @import("block_v5_memory_source_sha_connector_air_v1.zig");
    counts[4] = Air.EXPANDED_FIXED_COUNT;
    counts[5] = Air.CAPTURE_MAIN_COUNT;
    counts[6] = try std.math.add(u32, interaction, std.math.cast(u32, Air.INTERACTION_COUNT) orelse return error.InvalidSourceShaKernelGeometry);
    counts[7] = @intCast(core.verifier_types.compositionColumnCount(Kernel.COMPOSITION_SPLIT, core.fields.qm31.SECURE_EXTENSION_DEGREE).?);
    const config = expected.raw.config;
    try postcard.proof_preflight.validateFor(8, raw, .{
        .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size },
        .tree_columns = counts,
        .max_column_log_size = try maximumColumnLog(expected),
        .sample_width_limits = .{ 1, 1, 1, 1, 1, 1, 2, 1 },
        .allow_zero_samples = true,
        .hash_size = 32,
        .max_wire_bytes = limits.max_proof_bytes,
    });
}
pub fn encode(a: std.mem.Allocator, proof: *const Kernel.Proof, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Operand.Pin, kernel_limits: Kernel.Limits, limits: Limits) ![]u8 {
    try limits.require();
    try Kernel.admit(proof, admitted, plan, expected, kernel_limits);
    var writer = Writer.init(a, limits.max_artifact_bytes);
    defer writer.deinit();
    try writer.writeAll(MAGIC);
    try Wire.writeInt(&writer, u32, Kernel.VERSION);
    try writer.writeAll(&Kernel.abiId());
    try writer.writeAll(&admitted.identity);
    try writer.writeAll(&(try expected.identity(admitted, plan, kernel_limits.operands)));
    const length_at = writer.bytes.items.len;
    try Wire.writeInt(&writer, u64, 0);
    try Wire.writeInt(&writer, u64, proof.connector_claim.wire_requests);
    for (proof.core_claims) |claim| try writer.writeClaim(claim);
    for (proof.connector_claim.sums) |claim| try writer.writeClaim(claim);
    if (writer.bytes.items.len != HEADER_BYTES) return error.InvalidSourceShaKernelArtifact;
    try postcard.serializeProof(suite.Hasher, &writer, proof.stark);
    const bytes = writer.bytes.items.len - HEADER_BYTES;
    if (bytes == 0 or bytes > limits.max_proof_bytes) return error.SourceShaKernelArtifactLimit;
    try preflight(writer.bytes.items[HEADER_BYTES..], expected, limits);
    std.mem.writeInt(u64, writer.bytes.items[length_at..][0..8], bytes, .little);
    return writer.toOwnedSlice();
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, admitted: *const Source.Admitted, plan: Schema.Protocol.Plan, expected: Operand.Pin, kernel_limits: Kernel.Limits, limits: Limits) !Kernel.Proof {
    try limits.require();
    try expected.require(admitted, plan, kernel_limits.operands);
    if (raw.len > limits.max_artifact_bytes) return error.SourceShaKernelArtifactLimit;
    var cursor = Wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(MAGIC.len), MAGIC) or try cursor.readInt(u32) != Kernel.VERSION or !std.mem.eql(u8, try cursor.take(32), &Kernel.abiId()) or !std.mem.eql(u8, try cursor.take(32), &admitted.identity) or !std.mem.eql(u8, try cursor.take(32), &(try expected.identity(admitted, plan, kernel_limits.operands)))) return error.UntrustedSourceShaKernelArtifact;
    const bytes = try cursor.readInt(u64);
    if (bytes == 0 or bytes > limits.max_proof_bytes) return error.SourceShaKernelArtifactLimit;
    const requests = try cursor.readInt(u64);
    var claims: [6]Q = undefined;
    var connector: [32]Q = undefined;
    for (&claims) |*claim| claim.* = try cursor.readQm31();
    for (&connector) |*claim| claim.* = try cursor.readQm31();
    const wire_claim = @import("block_v5_memory_source_sha_connector_interaction_v1.zig").Claim{ .sums = connector, .wire_requests = requests };
    try Kernel.requireClaims(expected, claims, wire_claim, kernel_limits);
    const body = try cursor.take(@intCast(bytes));
    try cursor.requireDone();
    // Every nested length/canonical scalar/FRI/hash path is checked BEFORE the
    // ordinary decoder's first allocation. No file SHA authorizes a proof.
    try preflight(body, expected, limits);
    var stream = std.io.fixedBufferStream(body);
    var stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    const proof = Kernel.Proof{ .pin = expected, .core_claims = claims, .connector_claim = wire_claim, .stark = stark };
    try Kernel.admit(&proof, admitted, plan, expected, kernel_limits);
    if (stream.pos != body.len) return error.InvalidSourceShaKernelArtifact;
    return proof;
}
