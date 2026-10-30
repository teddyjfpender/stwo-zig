//! B7KUN001 carries physical claims and the bounded multiwindow original STARK.
//! Independent ELF/security/terminal policy and admitted source metadata remain
//! explicit receiver inputs. Transport parsing alone confers no proof authority.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const Multi = @import("block_v7_keccak_union_proof_v1.zig");
const Scope = @import("block_v7_keccak_union_scope_v1.zig");
const Receiver = @import("block_v7_execution_receiver_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Wire = @import("guest_precompile/proof_artifact_wire.zig");
const Fields = @import("block_v7_union_claim_wire_v1.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
pub const MAGIC = "B7KUN001";
pub const HEADER_BYTES = 84;
pub const Limits = struct {
    scope: Multi.Limits,
    artifact_bytes: usize = 128 << 20,
    proof_bytes: usize = 120 << 20,
    claim_bytes: usize = 8 << 20,
    claim_items: usize = 1 << 18,
    decode_bytes: usize = 256 << 20,
    verification_bytes: usize = 4 << 30,
    fn validate(self: Limits) !void {
        if (self.artifact_bytes <= HEADER_BYTES or self.proof_bytes == 0 or self.proof_bytes > self.artifact_bytes or self.claim_bytes == 0 or self.claim_bytes > self.artifact_bytes or self.claim_items == 0 or self.decode_bytes == 0 or self.verification_bytes == 0 or self.scope.max_retained_pcs_bytes == 0) return error.InvalidMultiUnionWireLimits;
    }
};
pub const Owned = struct {
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    proof: Multi.ProofView,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn encode(a: std.mem.Allocator, proof: Multi.ProofView, input: Multi.Input, limits: Limits) ![]u8 {
    try limits.validate();
    if (input.epoch.config.lifting_log_size != null) return error.UnsupportedMultiUnionWireLifting;
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, input.epoch.config) or roots.len < 2 or roots.len > postcard.proof_preflight.MAX_RUNTIME_TREES) return error.UntrustedMultiUnionWireProof;
    var out = Writer.init(a, limits.artifact_bytes);
    defer out.deinit();
    try out.writeAll(MAGIC);
    try out.writeAll(&Fields.schemaId(Multi.Claims));
    try out.writeAll(&input.epoch.digest);
    try Wire.writeInt(&out, u32, 0);
    try Wire.writeInt(&out, u64, 0);
    out.limit = @min(limits.artifact_bytes, try std.math.add(usize, HEADER_BYTES, limits.claim_bytes));
    var remaining = limits.claim_items;
    try Fields.encode(Multi.Claims, &out, proof.claims, &remaining);
    const claim_len = out.bytes.items.len - HEADER_BYTES;
    const start = out.bytes.items.len;
    out.limit = @min(limits.artifact_bytes, try std.math.add(usize, start, limits.proof_bytes));
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &out, proof.stark);
    std.mem.writeInt(u32, out.bytes.items[HEADER_BYTES - 12 ..][0..4], std.math.cast(u32, claim_len) orelse return error.Overflow, .little);
    std.mem.writeInt(u64, out.bytes.items[HEADER_BYTES - 8 ..][0..8], out.bytes.items.len - start, .little);
    return out.toOwnedSlice();
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, trusted: Receiver.Trusted, input: Multi.Input, limits: Limits) !Owned {
    try limits.validate();
    if (trusted.config.lifting_log_size != null or input.epoch.config.lifting_log_size != null) return error.UnsupportedMultiUnionWireLifting;
    if (raw.len > limits.artifact_bytes) return error.MultiUnionArtifactSizeLimit;
    var cursor = Wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(8), MAGIC) or !std.mem.eql(u8, try cursor.take(32), &Fields.schemaId(Multi.Claims)) or !std.mem.eql(u8, try cursor.take(32), &input.epoch.digest)) return error.UntrustedMultiUnionEnvelope;
    const claim_len = try cursor.readInt(u32);
    const proof_len = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.Overflow;
    if (claim_len < Fields.minimum(Multi.Claims) or claim_len > limits.claim_bytes or proof_len == 0 or proof_len > limits.proof_bytes) return error.MultiUnionWireSizeLimit;
    const claim_span = try cursor.take(claim_len);
    const proof_span = try cursor.take(proof_len);
    try cursor.requireDone();
    const budget = try Budget.createRetainingParent(a, limits.decode_bytes);
    errdefer budget.destroy();
    var arena = std.heap.ArenaAllocator.init(budget.allocator());
    errdefer arena.deinit();
    const temp = arena.allocator();
    var payload = Wire.Cursor.init(claim_span);
    var remaining = limits.claim_items;
    const claims = try Fields.decode(Multi.Claims, temp, &payload, &remaining);
    try payload.requireDone();
    try preflight(temp, proof_span, trusted, input, claims, limits);
    var stream = std.io.fixedBufferStream(proof_span);
    const stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, temp, stream.reader());
    if (stream.pos != proof_span.len) return error.TrailingMultiUnionProof;
    return .{ .budget = budget, .arena = arena, .proof = .{ .stark = stark, .claims = claims } };
}
pub fn verifyBytes(a: std.mem.Allocator, raw: []const u8, trusted: Receiver.Trusted, input: Multi.Input, limits: Limits) !Receiver.Verified {
    try limits.validate();
    const budget = try Budget.createRetainingParent(a, limits.verification_bytes);
    defer budget.destroy();
    var decoded = try decode(budget.allocator(), raw, trusted, input, limits);
    defer decoded.deinit();
    return Multi.verifyView(budget.allocator(), trusted, input, &decoded.proof, limits.scope);
}
fn preflight(a: std.mem.Allocator, raw: []const u8, trusted: Receiver.Trusted, input: Multi.Input, claims: Multi.Claims, limits: Limits) !void {
    if (claims.native.len != input.natives.len or claims.batches.len != input.batches.len or claims.ram.len != input.memory_geometry.len) return error.InvalidMultiUnionWireClaims;
    for (claims.ram, input.memory_geometry) |claim, geometry| if (!std.meta.eql(claim.geometry, geometry)) return error.UntrustedMultiUnionMemoryGeometry;
    const scope = try Scope.Owned.init(a, trusted, input, limits.scope);
    defer scope.deinit();
    const n = scope.placement.trace_trees + 1;
    const counts = try a.alloc(u32, n);
    const empty = try a.alloc(bool, n);
    const widths = try a.alloc(u32, n);
    @memset(counts, 0);
    @memset(empty, false);
    @memset(widths, 6);
    var max_log: u32 = 0;
    for (scope.sources, scope.placement.parts) |source, part| for (source.logs[0..source.tree_count], part.mapping()) |logs, tree| {
        counts[tree] = try std.math.add(u32, counts[tree], std.math.cast(u32, logs.len) orelse return error.Overflow);
        for (logs) |log| max_log = @max(max_log, log);
    };
    // The independently admitted ROM has no main columns. No artifact chooses
    // the empty tree or supplies a zero-width inventory to bypass preflight.
    empty[scope.placement.parts[input.natives.len + input.batches.len].map[1]] = true;
    var split: u32 = 2; // Original ROM, lookup and joint-memory union geometry.
    for (input.natives) |pin| {
        var layout = try pin.layout(a);
        defer layout.deinit();
        split = @max(split, @import("block_v5_native_projection_fused_proof_v2.zig").compositionSplit(layout.slots));
    }
    // Every independently admitted batch uses the qualified split2 original
    // arithmetic/control/shared-memory union. No proof chooses this degree.
    for (input.batches) |pin| {
        var geometry = try @import("block_v7_keccak_batch_geometry_v1.zig").Owned.init(a, pin, limits.scope.batch.owners);
        defer geometry.deinit();
        split = @max(split, 2);
    }
    counts[n - 1] = @intCast(core.verifier_types.compositionColumnCount(split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidMultiUnionWireGeometry);
    const config = trusted.config;
    try postcard.proof_preflight.validateRuntime(raw, .{
        .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size },
        .tree_columns = counts,
        .empty_tree_flags = empty,
        .sample_width_limits = widths,
        .allow_zero_samples = true,
        .max_column_log_size = max_log,
        .max_merkle_column_log_size = max_log,
        .hash_size = 32,
        .max_wire_bytes = limits.proof_bytes,
    });
}
