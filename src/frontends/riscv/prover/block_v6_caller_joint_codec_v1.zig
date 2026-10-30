//! B6CJ1 detached wire. Counts, geometry, roots and security come from original
//! independent admission; allocation-free postcard preflight precedes decoding.
//! Decoding is transport validation and never a successful proof receipt.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const wire = @import("guest_precompile/proof_artifact_wire.zig");
const ClaimWire = @import("guest_precompile/ethereum_sha_claim_wire.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
const Joint = @import("block_v6_caller_joint_proof_v1.zig");
const Admission = @import("block_v6_caller_joint_admission_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const suite = core.proof_suites.Blake3;
pub const MAGIC = "B6CALLR1";
const HEADER: usize = 8 + 32 + 32 + 4 + 8;
pub const Limits = struct {
    artifact_bytes: usize = 128 << 20,
    proof_bytes: usize = 64 << 20,
    claim_bytes: usize = 4 << 20,
    max_claims: usize = 32768,
    pub fn validate(self: Limits) !void {
        if (self.artifact_bytes <= HEADER or self.proof_bytes == 0 or self.proof_bytes > self.artifact_bytes or self.claim_bytes == 0 or self.claim_bytes > self.artifact_bytes or self.max_claims == 0) return error.InvalidJointCallerWireLimits;
    }
};
fn policyDigest(admitted: *const Admission.Prepared) [32]u8 {
    const policy = admitted.policy();
    var channel = suite.Channel{};
    channel.mixRoot(admitted.template_id);
    channel.mixRoot(policy.sealed.digest);
    @import("block_v5_precompile_family_proof_v1.zig").mixBinding(&channel, policy.binding);
    Fused.mixFirst(&channel, policy.binding, policy.witness_root, policy.frame, policy.sealed.register_custody_mode, &admitted.relations.schedule);
    return channel.digestBytes();
}
fn preflightAdmission(admitted: *const Admission.Prepared, limits: Limits) !void {
    try limits.validate();
    try admitted.validate();
    const schedule = &admitted.relations.schedule;
    const count = try std.math.add(usize, try std.math.mul(usize, schedule.program.len, 2), try std.math.add(usize, schedule.tables.len, schedule.memory.len));
    if (count > limits.max_claims) return error.JointCallerWireClaimLimit;
}
fn requireProof(proof: *const Joint.Proof, admitted: *const Admission.Prepared) !void {
    const policy = admitted.policy();
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    if (roots.len != 6 or !std.meta.eql(proof.stark.commitment_scheme_proof.config, policy.pins.config) or !std.meta.eql(roots[0..3].*, .{ policy.binding.first_roots[0], policy.binding.first_roots[1], policy.witness_root })) return error.UntrustedJointCallerWireRoots;
    _ = try Joint.proofChannel(admitted.allocator, policy, &admitted.relations.schedule, &proof.arithmetic, &proof.relations);
}
pub fn encode(a: std.mem.Allocator, proof: *const Joint.Proof, admitted: *const Admission.Prepared, limits: Limits) ![]u8 {
    try preflightAdmission(admitted, limits);
    try requireProof(proof, admitted);
    var out = Writer.init(a, limits.artifact_bytes);
    defer out.deinit();
    try out.writeAll(MAGIC);
    try out.writeAll(&admitted.template_id);
    try out.writeAll(&policyDigest(admitted));
    try wire.writeInt(&out, u32, 0);
    try wire.writeInt(&out, u64, 0);
    try ClaimWire.encodeExtensionClaim(&out, &admitted.arithmetic.statement, &proof.arithmetic);
    inline for (.{ proof.relations.program_claims, proof.relations.state_claims }) |partition| for (partition) |claim| {
        try out.writeClaim(claim.sum);
        try wire.writeInt(&out, u64, claim.fetch_count);
    };
    for (proof.relations.table_claims) |claim| {
        try out.writeClaim(claim.sum);
        try wire.writeInt(&out, u64, claim.row_count);
    }
    for (proof.relations.memory_claims) |claim| {
        try out.writeClaim(claim.transition_sum);
        try out.writeClaim(claim.universal_sum);
        for (claim.range_claims) |value| try out.writeClaim(value);
        try wire.writeInt(&out, u64, claim.active_count);
    }
    const claim_len = out.bytes.items.len - HEADER;
    if (claim_len > limits.claim_bytes) return error.JointCallerWireClaimLimit;
    const start = out.bytes.items.len;
    out.limit = @min(limits.artifact_bytes, try std.math.add(usize, start, limits.proof_bytes));
    try postcard.serializeProof(suite.Hasher, &out, proof.stark);
    std.mem.writeInt(u32, out.bytes.items[HEADER - 12 ..][0..4], std.math.cast(u32, claim_len) orelse return error.Overflow, .little);
    std.mem.writeInt(u64, out.bytes.items[HEADER - 8 ..][0..8], out.bytes.items.len - start, .little);
    return out.toOwnedSlice();
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, admitted: *const Admission.Prepared, limits: Limits) !Joint.Proof {
    try preflightAdmission(admitted, limits);
    if (raw.len > limits.artifact_bytes) return error.JointCallerWireArtifactLimit;
    var cursor = wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(8), MAGIC) or !std.mem.eql(u8, try cursor.take(32), &admitted.template_id) or !std.mem.eql(u8, try cursor.take(32), &policyDigest(admitted))) return error.UntrustedJointCallerEnvelope;
    const claim_len = try cursor.readInt(u32);
    const proof_len = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.Overflow;
    if (claim_len == 0 or claim_len > limits.claim_bytes or proof_len == 0 or proof_len > limits.proof_bytes) return error.JointCallerWireSizeLimit;
    const claim_span = try cursor.take(claim_len);
    const proof_span = try cursor.take(proof_len);
    try cursor.requireDone();
    try preflightStark(proof_span, admitted, limits);
    var claims_cursor = wire.Cursor.init(claim_span);
    const arithmetic = try ClaimWire.decodeExtensionClaim(&claims_cursor, &admitted.arithmetic.statement);
    const schedule = &admitted.relations.schedule;
    // All lengths come from independent source geometry; none from the wire.
    const Program = @import("block_v5_program_extension_proof_v1.zig").Claim;
    const Table = @import("block_v5_precompile_lookup_algebra_v1.zig").Claim;
    const Memory = @import("block_v5_external_memory_sidecar_proof_v1.zig").Claim;
    var relations = Fused.ClaimFrames{ .program_claims = try a.alloc(Program, schedule.program.len), .state_claims = &.{}, .table_claims = &.{}, .memory_claims = &.{} };
    errdefer relations.deinit(a);
    relations.state_claims = try a.alloc(Program, schedule.program.len);
    relations.table_claims = try a.alloc(Table, schedule.tables.len);
    relations.memory_claims = try a.alloc(Memory, schedule.memory.len);
    inline for (.{ relations.program_claims, relations.state_claims }) |partition| {
        for (partition) |*claim| claim.* = .{ .sum = try claims_cursor.readQm31(), .fetch_count = try claims_cursor.readInt(u64) };
    }
    for (relations.table_claims) |*claim| claim.* = .{ .sum = try claims_cursor.readQm31(), .row_count = try claims_cursor.readInt(u64) };
    for (relations.memory_claims) |*claim| {
        claim.transition_sum = try claims_cursor.readQm31();
        claim.universal_sum = try claims_cursor.readQm31();
        for (&claim.range_claims) |*value| value.* = try claims_cursor.readQm31();
        claim.active_count = try claims_cursor.readInt(u64);
    }
    try claims_cursor.requireDone();
    _ = try Joint.proofChannel(a, admitted.policy(), schedule, &arithmetic, &relations);
    var stream = std.io.fixedBufferStream(proof_span);
    var stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    if (stream.pos != proof_span.len) return error.TrailingJointCallerProof;
    const result = Joint.Proof{ .stark = stark, .arithmetic = arithmetic, .relations = relations };
    try requireProof(&result, admitted);
    return result;
}
fn preflightStark(raw: []const u8, admitted: *const Admission.Prepared, limits: Limits) !void {
    const config = admitted.arithmetic.config;
    var counts: [6]u32 = undefined;
    var max_merkle: u32 = admitted.mask_log;
    for (admitted.logs(), 0..) |tree, i| {
        counts[i] = std.math.cast(u32, tree.len) orelse return error.Overflow;
        for (tree) |log| max_merkle = @max(max_merkle, log);
    }
    counts[5] = @intCast(core.verifier_types.compositionColumnCount(admitted.composition_split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidJointCallerGeometry);
    try postcard.proof_preflight.validateFor(6, raw, .{
        .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size },
        .tree_columns = counts,
        .max_column_log_size = admitted.mask_log,
        .max_merkle_column_log_size = max_merkle,
        .allow_zero_samples = true,
        // Allocation envelopes only. Fresh original AIR union checks exact
        // points and widths; a union can require both physical/common shifts.
        .sample_width_limits = .{ 1, 6, 1, 2, 2, 1 },
        .hash_size = 32,
        .max_wire_bytes = limits.proof_bytes,
    });
}
