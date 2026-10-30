//! B8EPW001: bounded physical claims and original STARK, under independently
//! reconstructed metadata/ELF/snapshot/security policy. Transport alone is
//! never proof authority. Runtime inventory is checked before deserialization.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Proof = @import("block_v8_endpoint_whole_proof_v1.zig");
const Scope = @import("block_v8_endpoint_whole_scope_v1.zig");
const Shape = @import("block_v8_endpoint_whole_shape_v1.zig");
const Ledger = @import("block_v8_endpoint_whole_ledger_v1.zig");
const NativeLayout = @import("block_v8_native_endpoint_layout_v1.zig");
const Placement = @import("block_v8_endpoint_whole_placement_v1.zig");
const Fields = @import("block_v7_union_claim_wire_v1.zig");
const Wire = @import("guest_precompile/proof_artifact_wire.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
const Trusted = @import("block_v7_execution_receiver_v1.zig").Trusted;
pub const MAGIC = "B8EPW001";
pub const HEADER_BYTES: usize = 84;
pub const Limits = struct {
    original: Proof.Limits = .{},
    artifact_bytes: usize = 128 << 20,
    proof_bytes: usize = 112 << 20,
    claim_bytes: usize = 16 << 20,
    claim_items: usize = 1 << 20,
    decode_bytes: usize = 256 << 20,
    verification_bytes: usize = 8 << 30,
    fn validate(self: Limits) !void {
        if (self.artifact_bytes <= HEADER_BYTES or self.proof_bytes == 0 or self.proof_bytes > self.artifact_bytes or
            self.claim_bytes == 0 or self.claim_bytes > self.artifact_bytes or self.claim_items == 0 or
            self.decode_bytes == 0 or self.verification_bytes == 0) return error.InvalidEndpointWireLimits;
    }
};
pub const Owned = struct {
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    stark: core.proof_suites.Blake3.Proof,
    claims: Ledger.Claims,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn encode(a: std.mem.Allocator, proof: *const Proof.Proof, trusted: Trusted, input: Scope.Input, limits: Limits) ![]u8 {
    try limits.validate();
    if (trusted.config.lifting_log_size != null) return error.UnsupportedEndpointWireLifting;
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, trusted.config) or roots.len != Placement.TRACE_TREES + 1 or
        !std.meta.eql(input.native_roots, proof.native_roots)) return error.UntrustedEndpointWireProof;
    const scope = try Scope.Owned.init(a, trusted, input, limits.original.scope);
    defer scope.deinit();
    var out = Writer.init(a, limits.artifact_bytes);
    defer out.deinit();
    try out.writeAll(MAGIC);
    try out.writeAll(&Fields.schemaId(Ledger.Claims));
    try out.writeAll(&scope.epoch.digest);
    try Wire.writeInt(&out, u32, 0);
    try Wire.writeInt(&out, u64, 0);
    out.limit = @min(limits.artifact_bytes, try std.math.add(usize, HEADER_BYTES, limits.claim_bytes));
    var remaining = limits.claim_items;
    try Fields.encode(Ledger.Claims, &out, proof.claims, &remaining);
    const claim_length = out.bytes.items.len - HEADER_BYTES;
    const start = out.bytes.items.len;
    out.limit = @min(limits.artifact_bytes, try std.math.add(usize, start, limits.proof_bytes));
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &out, proof.stark);
    std.mem.writeInt(u32, out.bytes.items[HEADER_BYTES - 12 ..][0..4], std.math.cast(u32, claim_length) orelse return error.Overflow, .little);
    std.mem.writeInt(u64, out.bytes.items[HEADER_BYTES - 8 ..][0..8], out.bytes.items.len - start, .little);
    return out.toOwnedSlice();
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, trusted: Trusted, input: Scope.Input, limits: Limits) !Owned {
    try limits.validate();
    if (trusted.config.lifting_log_size != null) return error.UnsupportedEndpointWireLifting;
    if (raw.len > limits.artifact_bytes) return error.EndpointArtifactSizeLimit;
    var cursor = Wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(8), MAGIC) or !std.mem.eql(u8, try cursor.take(32), &Fields.schemaId(Ledger.Claims)))
        return error.UntrustedEndpointEnvelope;
    const epoch = try cursor.take(32);
    const claim_length = try cursor.readInt(u32);
    const proof_length = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.Overflow;
    if (claim_length > limits.claim_bytes or proof_length > limits.proof_bytes) return error.EndpointSectionSizeLimit;
    const claim_bytes = try cursor.take(claim_length);
    const proof_bytes = try cursor.take(proof_length);
    try cursor.requireDone();
    const budget = try Budget.createRetainingParent(a, limits.decode_bytes);
    errdefer budget.destroy();
    var arena = std.heap.ArenaAllocator.init(budget.allocator());
    errdefer arena.deinit();
    const t = arena.allocator();
    const scope = try Scope.Owned.init(t, trusted, input, limits.original.scope);
    defer scope.deinit();
    if (!std.mem.eql(u8, epoch, &scope.epoch.digest)) return error.UntrustedEndpointEnvelope;
    var payload = Wire.Cursor.init(claim_bytes);
    var remaining = limits.claim_items;
    const claims = try Fields.decode(Ledger.Claims, t, &payload, &remaining);
    try payload.requireDone();
    try preflight(t, proof_bytes, scope, input, claims, trusted.config, limits);
    var stream = std.io.fixedBufferStream(proof_bytes);
    const stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, t, stream.reader());
    if (stream.pos != proof_bytes.len) return error.TrailingEndpointProof;
    return .{ .budget = budget, .arena = arena, .stark = stark, .claims = claims };
}
pub fn verifyBytes(a: std.mem.Allocator, raw: []const u8, trusted: Trusted, input: Scope.Input, limits: Limits) !Ledger.Summary {
    try limits.validate();
    const budget = try Budget.createRetainingParent(a, limits.verification_bytes);
    defer budget.destroy();
    var decoded = try decode(budget.allocator(), raw, trusted, input, limits);
    defer decoded.deinit();
    return Proof.verify(budget.allocator(), trusted, input, &decoded.stark, decoded.claims, limits.original);
}
fn preflight(a: std.mem.Allocator, raw: []const u8, scope: *const Scope.Owned, input: Scope.Input, claims: Ledger.Claims, config: core.pcs.PcsConfig, limits: Limits) !void {
    if (claims.memory.ram.len != input.memory_geometry.len) return error.InvalidEndpointWireClaims;
    for (claims.memory.ram, input.memory_geometry) |got, expected| if (!std.meta.eql(got.geometry, expected))
        return error.UntrustedEndpointMemoryGeometry;
    var layout = try NativeLayout.Layout.init(a, input.shape, 0);
    defer layout.deinit();
    if (layout.slots.len != claims.native.len) return error.InvalidEndpointWireClaims;
    for (layout.slots, claims.native) |slot, claim| if (slot.n_rows != claim.row_count) return error.InvalidEndpointWireClaims;
    const shape = try Shape.Owned.init(a, scope, input);
    defer shape.deinit();
    var counts: [Placement.TRACE_TREES + 1]u32 = undefined;
    for (shape.logs, counts[0..Placement.TRACE_TREES]) |logs, *count| count.* = std.math.cast(u32, logs.len) orelse return error.Overflow;
    counts[Placement.TRACE_TREES] = @intCast(core.verifier_types.compositionColumnCount(shape.split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidEndpointWireGeometry);
    var empty: [Placement.TRACE_TREES + 1]bool = @splat(false);
    empty[4] = true; // Independently admitted ROM has no main columns.
    const widths: [Placement.TRACE_TREES + 1]u32 = @splat(6);
    try postcard.proof_preflight.validateRuntime(raw, .{
        .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size },
        .tree_columns = &counts,
        .empty_tree_flags = &empty,
        .sample_width_limits = &widths,
        .allow_zero_samples = true,
        .max_column_log_size = shape.max_log,
        .max_merkle_column_log_size = shape.max_log,
        .hash_size = 32,
        .max_wire_bytes = limits.proof_bytes,
    });
}
