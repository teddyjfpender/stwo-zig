//! Distinct B5CF wire grammar. Independently supplied capacity/source policy
//! determines both claim arrays and every PCS inventory before allocation.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const wire = @import("guest_precompile/proof_artifact_wire.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
const Fused = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Capacity = @import("block_v5_native_capacity_protocol_v1.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Range = @import("block_execution_byte_range_v2.zig");
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Eval = @import("block_v5_opcode_sidecar_eval_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const suite = core.proof_suites.Blake3;
pub const MAGIC = "B5CFART1";
pub const HEADER_BYTES: usize = 8 + 4 + 4 + 7 * 32 + 4 + 4 + 4 + 8;
const PROOF_LENGTH_OFFSET = HEADER_BYTES - 8;
pub const PROJECTION_BYTES: usize = 16 + 8;
pub const MEMORY_BYTES: usize = 16 * (2 + Range.BATCH_COUNT) + 8;
pub const Limits = struct {
    proof_bytes: usize = 64 << 20,
    artifact_bytes: usize = 128 << 20,
    max_claims: usize = 1 << 16,
    max_claim_bytes: usize = 16 << 20,
    pub fn validate(self: Limits) !void {
        if (self.proof_bytes == 0 or self.proof_bytes > self.artifact_bytes or
            self.artifact_bytes < HEADER_BYTES or self.max_claims == 0 or self.max_claim_bytes == 0)
            return error.InvalidCapacityFusedWireLimits;
    }
};
pub const Expected = struct {
    shape: *const @import("../air/statement.zig").Blake3ExecutionStatement,
    external_retirements: u32,
    template_id: [32]u8,
    native_instance_id: [32]u8,
    fused_instance_id: [32]u8,
    native_roots: [2][32]u8,
    witness_root: [32]u8,
    sealed_digest: [32]u8,
    index: u32,
    frame: @import("../air/block/memory_event.zig").Frame,
    register_custody_mode: u32,
    config: core.pcs.PcsConfig,
    fused_limits: Fused.Limits = .{},
    pub fn validate(self: Expected) !void {
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        try self.fused_limits.requireShape(self.shape, self.external_retirements);
        if (self.register_custody_mode > 1 or self.frame.clock_frame != .leaf_local or
            self.frame.global_first_cycle == 0 or self.frame.cycle_count != self.shape.public_data.clock)
            return error.UntrustedCapacityFusedWirePolicy;
        for ([_][32]u8{ self.template_id, self.native_instance_id, self.fused_instance_id, self.native_roots[0], self.native_roots[1], self.witness_root, self.sealed_digest }) |digest|
            if (std.mem.allEqual(u8, &digest, 0)) return error.UntrustedCapacityFusedWirePolicy;
    }
};
/// Temporary canonical inventories. Transport never publishes these as proof
/// authority, and owns no public shape or source roster.
pub const Inventory = struct {
    a: std.mem.Allocator,
    projections: []Source.Slot,
    memory: []Memory.Slot,
    capacity_digest: [32]u8,
    geometry_digest: [32]u8,
    claim_bytes: usize,
    pub fn init(a: std.mem.Allocator, expected: Expected, limits: Limits) !Inventory {
        try expected.validate();
        try limits.validate();
        const projections = try Source.slotsFromShapeForMode(a, expected.shape, expected.external_retirements, expected.register_custody_mode);
        errdefer a.free(projections);
        const memory = try Source.memorySlots(a, expected.shape, expected.external_retirements, expected.frame, expected.register_custody_mode);
        errdefer a.free(memory);
        try expected.fused_limits.require(expected.shape, expected.external_retirements, projections, memory);
        if (memory.len == 0 and !std.meta.eql(expected.witness_root, try Source.emptyWitnessRoot(expected.register_custody_mode)))
            return error.UntrustedCapacityFusedWirePolicy;
        if (projections.len == 0 or try std.math.add(usize, projections.len, memory.len) > limits.max_claims)
            return error.CapacityFusedWireClaimLimit;
        const bytes = try std.math.add(usize, try std.math.mul(usize, projections.len, PROJECTION_BYTES), try std.math.mul(usize, memory.len, MEMORY_BYTES));
        if (bytes > limits.max_claim_bytes or try std.math.add(usize, HEADER_BYTES, bytes) > limits.artifact_bytes)
            return error.CapacityFusedWireClaimLimit;
        if (!std.meta.eql(expected.fused_instance_id, Fused.instanceId(expected.template_id, expected.native_instance_id, expected.native_roots, expected.witness_root, expected.index, expected.frame, projections, memory)))
            return error.UntrustedCapacityFusedWirePolicy;
        return .{ .a = a, .projections = projections, .memory = memory, .claim_bytes = bytes, .capacity_digest = try Capacity.capacityDigest(expected.shape, expected.external_retirements), .geometry_digest = try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(expected.shape, expected.external_retirements) };
    }
    pub fn deinit(self: *Inventory) void {
        self.a.free(self.projections);
        self.a.free(self.memory);
        self.* = undefined;
    }
};
fn requireProof(proof: *const Fused.Proof, expected: Expected, inventory: *const Inventory) !void {
    try Fused.requireProtocol(proof.protocol_version);
    const commitments = proof.stark.commitment_scheme_proof.commitments.items;
    const tree_count: usize = if (inventory.memory.len == 0) 4 else 5;
    if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, expected.config) or
        commitments.len != tree_count or !std.meta.eql(commitments[0..2].*, expected.native_roots) or
        (inventory.memory.len != 0 and !std.meta.eql(commitments[2], expected.witness_root)))
        return error.UntrustedCapacityFusedWireRoots;
    var channel = suite.Channel{};
    try Fused.mixClaims(&channel, expected.template_id, expected.native_instance_id, expected.index, inventory.projections, inventory.memory, proof.claims, proof.memory_claims);
}
pub fn encode(a: std.mem.Allocator, proof: *const Fused.Proof, expected: Expected, limits: Limits) ![]u8 {
    var inventory = try Inventory.init(a, expected, limits);
    defer inventory.deinit();
    try requireProof(proof, expected, &inventory);
    const body = try std.math.add(usize, HEADER_BYTES, inventory.claim_bytes);
    const proof_cap = try std.math.add(usize, body, limits.proof_bytes);
    var output = Writer.init(a, @min(proof_cap, limits.artifact_bytes));
    defer output.deinit();
    try output.writeAll(MAGIC);
    try wire.writeInt(&output, u32, Fused.VERSION);
    try wire.writeInt(&output, u32, expected.index);
    for ([_][32]u8{ expected.template_id, expected.native_instance_id, expected.fused_instance_id, inventory.capacity_digest, inventory.geometry_digest, expected.sealed_digest, Word.abiId() }) |digest| try output.writeAll(&digest);
    try wire.writeInt(&output, u32, expected.register_custody_mode);
    try wire.writeInt(&output, u32, @intCast(inventory.projections.len));
    try wire.writeInt(&output, u32, @intCast(inventory.memory.len));
    try wire.writeInt(&output, u64, 0);
    for (proof.claims) |claim| {
        try output.writeClaim(claim.sum);
        try wire.writeInt(&output, u64, claim.row_count);
    }
    for (proof.memory_claims) |claim| {
        try output.writeClaim(claim.transition_sum);
        try output.writeClaim(claim.universal_sum);
        for (claim.range_claims) |part| try output.writeClaim(part);
        try wire.writeInt(&output, u64, claim.active_count);
    }
    if (output.bytes.items.len != body) return error.ChangedCapacityFusedSerialization;
    postcard.serializeProof(suite.Hasher, &output, proof.stark) catch |err| switch (err) {
        error.ArtifactTooLarge => return if (proof_cap <= limits.artifact_bytes) error.CapacityFusedWireProofLimit else error.CapacityFusedWireArtifactLimit,
        else => return err,
    };
    std.mem.writeInt(u64, output.bytes.items[PROOF_LENGTH_OFFSET..][0..8], output.bytes.items.len - body, .little);
    return output.toOwnedSlice();
}
/// Canonical envelope/claim preflight, without allocating received claim arrays.
/// Exposed for negative fixtures and called by decode before postcard allocation.
pub fn preflightEnvelope(raw: []const u8, expected: Expected, inventory: *const Inventory, limits: Limits) !struct { claims: []const u8, stark: []const u8 } {
    try limits.validate();
    if (raw.len > limits.artifact_bytes) return error.CapacityFusedWireArtifactLimit;
    var cursor = wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(8), MAGIC)) return error.InvalidCapacityFusedWireMagic;
    try Fused.requireProtocol(try cursor.readInt(u32));
    if (try cursor.readInt(u32) != expected.index) return error.UntrustedCapacityFusedWirePolicy;
    for ([_][32]u8{ expected.template_id, expected.native_instance_id, expected.fused_instance_id, inventory.capacity_digest, inventory.geometry_digest, expected.sealed_digest, Word.abiId() }) |digest|
        if (!std.mem.eql(u8, try cursor.take(32), &digest)) return error.UntrustedCapacityFusedWirePolicy;
    if (try cursor.readInt(u32) != expected.register_custody_mode or
        try cursor.readInt(u32) != inventory.projections.len or try cursor.readInt(u32) != inventory.memory.len)
        return error.UntrustedCapacityFusedWireCensus;
    const length = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.Overflow;
    if (length == 0 or length > limits.proof_bytes) return error.CapacityFusedWireProofLimit;
    const claims = try cursor.take(inventory.claim_bytes);
    var claim_cursor = wire.Cursor.init(claims);
    for (inventory.projections) |slot| {
        _ = try claim_cursor.readQm31();
        if (try claim_cursor.readInt(u64) != slot.n_rows) return error.InvalidV5FullFusedClaims;
    }
    for (inventory.memory) |slot| {
        for (0..2 + Range.BATCH_COUNT) |_| _ = try claim_cursor.readQm31();
        if (try claim_cursor.readInt(u64) > (@as(u64, 1) << @intCast(slot.log_size))) return error.InvalidV5FullFusedClaims;
    }
    try claim_cursor.requireDone();
    const stark = try cursor.take(length);
    try cursor.requireDone();
    return .{ .claims = claims, .stark = stark };
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, expected: Expected, limits: Limits) !Fused.Proof {
    var inventory = try Inventory.init(a, expected, limits);
    defer inventory.deinit();
    const spans = try preflightEnvelope(raw, expected, &inventory, limits);
    try preflightStark(spans.stark, expected, &inventory, limits);
    const claims = try a.alloc(Fused.Claim, inventory.projections.len);
    errdefer a.free(claims);
    const memory = try a.alloc(Memory.Claim, inventory.memory.len);
    errdefer a.free(memory);
    var cursor = wire.Cursor.init(spans.claims);
    for (claims) |*claim| claim.* = .{ .sum = try cursor.readQm31(), .row_count = try cursor.readInt(u64) };
    for (memory) |*claim| {
        claim.transition_sum = try cursor.readQm31();
        claim.universal_sum = try cursor.readQm31();
        for (&claim.range_claims) |*part| part.* = try cursor.readQm31();
        claim.active_count = try cursor.readInt(u64);
    }
    try cursor.requireDone();
    var stream = std.io.fixedBufferStream(spans.stark);
    var stark = try postcard.deserializeProof(suite.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    if (stream.pos != spans.stark.len) return error.TrailingCapacityFusedWireProof;
    const result = Fused.Proof{ .stark = stark, .claims = claims, .memory_claims = memory };
    try requireProof(&result, expected, &inventory);
    return result;
}
pub const Geometry = struct { tree_count: usize, tree_columns: [5]u32, max_log: u32, max_merkle_log: u32 };
pub fn geometry(expected: Expected, inventory: *const Inventory) !Geometry {
    const plan = try Capacity.Plan.fromShape(expected.shape, expected.external_retirements);
    const split = Fused.compositionSplit(inventory.projections);
    const composition = core.verifier_types.compositionColumnCount(split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidCapacityFusedWireGeometry;
    var log: u32 = 0;
    for (inventory.projections) |slot| log = @max(log, slot.log_size);
    for (inventory.memory) |slot| log = @max(log, slot.log_size);
    var merkle_log = log;
    for (plan.active()) |shard| merkle_log = @max(merkle_log, shard.log_size);
    const interaction = try std.math.add(usize, try std.math.mul(usize, inventory.projections.len, 4), try std.math.mul(usize, inventory.memory.len, Eval.INTERACTION_COUNT));
    if (inventory.memory.len == 0) return .{ .tree_count = 4, .tree_columns = .{ @intCast(plan.fixed_count), @intCast(plan.mainCount()), @intCast(interaction), @intCast(composition), 0 }, .max_log = log, .max_merkle_log = merkle_log };
    return .{ .tree_count = 5, .tree_columns = .{ @intCast(plan.fixed_count), @intCast(plan.mainCount()), @intCast(try std.math.mul(usize, inventory.memory.len, Integer.COLUMN_COUNT)), @intCast(interaction), @intCast(composition) }, .max_log = log, .max_merkle_log = merkle_log };
}
fn preflightStark(raw: []const u8, expected: Expected, inventory: *const Inventory, limits: Limits) !void {
    const g = try geometry(expected, inventory);
    const config = expected.config;
    const pc = postcard.proof_preflight.Config{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size };
    if (g.tree_count == 4) return postcard.proof_preflight.validate(raw, .{
        .config = pc,
        .tree_columns = g.tree_columns[0..4].*,
        .max_column_log_size = g.max_log,
        .max_merkle_column_log_size = g.max_merkle_log,
        .sample_width_limits = .{ 1, 1, 2, 1 },
        .allow_zero_samples = true,
        .hash_size = 32,
        .max_wire_bytes = limits.proof_bytes,
    });
    return postcard.proof_preflight.validateFive(raw, .{
        .config = pc,
        .tree_columns = g.tree_columns,
        .max_column_log_size = g.max_log,
        .max_merkle_column_log_size = g.max_merkle_log,
        .sample_width_limits = .{ 1, 1, 1, 2, 1 },
        .hash_size = 32,
        .max_wire_bytes = limits.proof_bytes,
    });
}
