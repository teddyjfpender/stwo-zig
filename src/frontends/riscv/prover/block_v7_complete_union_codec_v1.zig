//! B7CUN001 transports the complete finite union's claims and original STARK.
//! Independent ELF/config/terminal policy and proposed source metadata remain
//! explicit verifier inputs. Decoding alone never grants proof authority.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const Union = @import("block_v7_complete_union_proof_v1.zig");
const Receiver = @import("block_v7_execution_receiver_v1.zig");
const Scope = @import("block_v7_multi_union_scope_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Wire = @import("guest_precompile/proof_artifact_wire.zig");
const Fields = @import("block_v7_union_claim_wire_v1.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
pub const MAGIC = "B7CUN001";
pub const HEADER_BYTES = 8 + 32 + 32 + 4 + 8;
pub const Payload = struct {
    native: @FieldType(Union.Proof, "native"),
    access: @FieldType(Union.Proof, "access"),
    arithmetic: @FieldType(Union.Proof, "arithmetic"),
    relations: @FieldType(Union.Proof, "relations"),
    program: @FieldType(Union.Proof, "program"),
    lookup: @FieldType(Union.Proof, "lookup"),
    ram: @FieldType(Union.Proof, "ram"),
    interval: @FieldType(Union.Proof, "interval"),
    range16: @FieldType(Union.Proof, "range16"),
    terminal: @FieldType(Union.Proof, "terminal"),
    fn from(proof: *const Union.Proof) Payload {
        var out: Payload = undefined;
        inline for (std.meta.fields(Payload)) |field| @field(out, field.name) = @field(proof, field.name);
        return out;
    }
};
pub const Limits = struct {
    artifact_bytes: usize = 68 << 20,
    proof_bytes: usize = 64 << 20,
    claim_bytes: usize = 4 << 20,
    claim_items: usize = 1 << 16,
    decode_bytes: usize = 128 << 20,
    /// Total charged decode + fixed reconstruction + verification allocation.
    /// This does not include caller-owned input bytes or process overhead.
    verification_bytes: usize = 4 << 30,
    admitted_trace_pcs_bytes: usize = 32 << 30,
    receiver: Receiver.Limits = .{},
    fn validate(self: Limits) !void {
        if (self.artifact_bytes <= HEADER_BYTES or self.proof_bytes == 0 or self.proof_bytes > self.artifact_bytes or self.claim_bytes == 0 or self.claim_bytes > self.artifact_bytes or self.claim_items == 0 or self.decode_bytes == 0 or self.verification_bytes == 0 or self.admitted_trace_pcs_bytes == 0) return error.InvalidUnionWireLimits;
    }
};
pub const Owned = struct {
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    stark: core.proof_suites.Blake3.Proof,
    payload: Payload,
    /// Borrowed view valid only while this owner lives. Do not deinitialize it.
    pub fn view(self: *const Owned) Union.Proof {
        var out: Union.Proof = undefined;
        out.stark = self.stark;
        inline for (std.meta.fields(Payload)) |field| @field(out, field.name) = @field(self.payload, field.name);
        return out;
    }
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn encode(a: std.mem.Allocator, proof: *const Union.Proof, input: Union.Input, limits: Limits) ![]u8 {
    try limits.validate();
    if (input.epoch.config.lifting_log_size != null) return error.UnsupportedUnionWireLifting;
    if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, input.epoch.config) or proof.stark.commitment_scheme_proof.commitments.items.len != 15) return error.UntrustedUnionWireProof;
    var out = Writer.init(a, limits.artifact_bytes);
    defer out.deinit();
    try out.writeAll(MAGIC);
    try out.writeAll(&Fields.schemaId(Payload));
    try out.writeAll(&input.epoch.digest);
    try Wire.writeInt(&out, u32, 0);
    try Wire.writeInt(&out, u64, 0);
    out.limit = @min(limits.artifact_bytes, try std.math.add(usize, HEADER_BYTES, limits.claim_bytes));
    var remaining = limits.claim_items;
    try Fields.encode(Payload, &out, Payload.from(proof), &remaining);
    const claim_len = out.bytes.items.len - HEADER_BYTES;
    const start = out.bytes.items.len;
    out.limit = @min(limits.artifact_bytes, try std.math.add(usize, start, limits.proof_bytes));
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &out, proof.stark);
    std.mem.writeInt(u32, out.bytes.items[HEADER_BYTES - 12 ..][0..4], std.math.cast(u32, claim_len) orelse return error.Overflow, .little);
    std.mem.writeInt(u64, out.bytes.items[HEADER_BYTES - 8 ..][0..8], out.bytes.items.len - start, .little);
    return out.toOwnedSlice();
}
pub fn decode(a: std.mem.Allocator, raw: []const u8, trusted: Receiver.Trusted, input: Union.Input, limits: Limits) !Owned {
    try limits.validate();
    // This finite transport is qualified for the original implicit-height PCS.
    // Never guess FRI bounds for an explicit lifting configuration.
    if (trusted.config.lifting_log_size != null or input.epoch.config.lifting_log_size != null) return error.UnsupportedUnionWireLifting;
    if (raw.len > limits.artifact_bytes) return error.UnionArtifactSizeLimit;
    var cursor = Wire.Cursor.init(raw);
    if (!std.mem.eql(u8, try cursor.take(8), MAGIC) or !std.mem.eql(u8, try cursor.take(32), &Fields.schemaId(Payload)) or !std.mem.eql(u8, try cursor.take(32), &input.epoch.digest)) return error.UntrustedUnionEnvelope;
    const claim_len = try cursor.readInt(u32);
    const proof_len = std.math.cast(usize, try cursor.readInt(u64)) orelse return error.Overflow;
    if (claim_len < Fields.minimum(Payload) or claim_len > limits.claim_bytes or proof_len == 0 or proof_len > limits.proof_bytes) return error.UnionWireSizeLimit;
    const claim_span = try cursor.take(claim_len);
    const proof_span = try cursor.take(proof_len);
    try cursor.requireDone();
    const budget = try Budget.createRetainingParent(a, limits.decode_bytes);
    errdefer budget.destroy();
    var arena = std.heap.ArenaAllocator.init(budget.allocator());
    errdefer arena.deinit();
    const temp = arena.allocator();
    var claims = Wire.Cursor.init(claim_span);
    var remaining = limits.claim_items;
    const payload = try Fields.decode(Payload, temp, &claims, &remaining);
    try claims.requireDone();
    try preflight(temp, proof_span, trusted, input, payload, limits);
    var stream = std.io.fixedBufferStream(proof_span);
    const stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, temp, stream.reader());
    if (stream.pos != proof_span.len) return error.TrailingUnionProof;
    return .{ .budget = budget, .arena = arena, .stark = stark, .payload = payload };
}
pub fn verifyBytes(a: std.mem.Allocator, raw: []const u8, trusted: Receiver.Trusted, input: Union.Input, limits: Limits) !Receiver.Verified {
    try limits.validate();
    const budget = try Budget.createRetainingParent(a, limits.verification_bytes);
    defer budget.destroy();
    var decoded = try decode(budget.allocator(), raw, trusted, input, limits);
    defer decoded.deinit();
    const proof = decoded.view();
    return Union.verify(budget.allocator(), trusted, input, &proof, limits.receiver);
}
fn preflight(a: std.mem.Allocator, raw: []const u8, trusted: Receiver.Trusted, input: Union.Input, claims: Payload, limits: Limits) !void {
    const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig").Claim;
    if (claims.ram.len == 0 or claims.ram.len > limits.receiver.joint_memory.memory.max_shards) return error.InvalidUnionRamClaims;
    const geometries = try a.alloc(Geometry, claims.ram.len);
    for (geometries, claims.ram) |*g, claim| g.* = claim.geometry;
    const admitted = try Scope.Owned.init(a, trusted, .{ .epoch = input.epoch, .entries = input.entries, .natives = &.{input.native}, .callers = &.{input.caller}, .program_plan = input.program_plan, .program_roots = input.program_roots, .lookup_plan = input.lookup_plan, .lookup_layout = input.lookup_layout, .lookup_roots = input.lookup_roots, .memory_roots = input.memory_roots, .memory_geometry = geometries, .interval_log = input.interval_log }, .{ .max_retained_pcs_bytes = limits.admitted_trace_pcs_bytes, .max_windows = 1, .max_trace_trees = 14, .receiver = limits.receiver });
    defer admitted.deinit();
    if (admitted.placement.trace_trees != 14) return error.UnsupportedUnionWireTrees;
    var counts: [15]u32 = @splat(0);
    var max_log: u32 = 0;
    for (admitted.sources, admitted.placement.parts) |source, part| for (source.logs[0..source.tree_count], part.mapping()) |logs, tree| {
        counts[tree] = try std.math.add(u32, counts[tree], std.math.cast(u32, logs.len) orelse return error.Overflow);
        for (logs) |log| max_log = @max(max_log, log);
    };
    var native_layout = try input.native.layout(a);
    defer native_layout.deinit();
    const split = @import("block_v5_native_projection_fused_proof_v2.zig").compositionSplit(native_layout.slots);
    counts[14] = @intCast(core.verifier_types.compositionColumnCount(split, core.fields.qm31.SECURE_EXTENSION_DEGREE) orelse return error.InvalidUnionWireGeometry);
    const config = trusted.config;
    try postcard.proof_preflight.validateFor(15, raw, .{
        .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size },
        .tree_columns = counts,
        .empty_tree_mask = 1 << 5, // Original ROM's empty main commitment.
        .max_column_log_size = max_log,
        .max_merkle_column_log_size = max_log,
        .allow_zero_samples = true,
        .sample_width_limits = @splat(6), // Envelope only; original AIR checks exact masks.
        .hash_size = 32,
        .max_wire_bytes = limits.proof_bytes,
    });
}
