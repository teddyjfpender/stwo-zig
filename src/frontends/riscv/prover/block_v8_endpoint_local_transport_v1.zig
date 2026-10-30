//! Bounded decoding of the durable bridge/global original envelopes. Claimed
//! geometry bounds allocation only; the bundle receiver independently rebuilds
//! all scopes/keys and freshly verifies every original after decoding.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const postcard = @import("interop_postcard");
const Fields = @import("block_v7_union_claim_wire_v1.zig");
const Cursor = @import("guest_precompile/proof_artifact_wire.zig").Cursor;
const Compact = @import("block_v8_compact_ram_proof_v1.zig");
const LegacyClaims = @import("block_v7_window_memory_joint_air_v1.zig").Claims;
const Layout = @import("block_v7_window_memory_joint_layout_v1.zig");
const Q = core.fields.qm31.QM31;
pub const Limits = struct { artifact_bytes: usize = 128 << 20, decode_bytes: usize = 512 << 20, claim_items: usize = 1 << 20, max_row_log: u32 = 24 };
pub fn Owned(comptime Claims: type) type {
    return struct {
        budget: *engine.host_budget_allocator.SharedHostBudget,
        arena: std.heap.ArenaAllocator,
        claims: Claims,
        stark: core.proof_suites.Blake3.Proof,
        pub fn deinit(self: *@This()) void {
            self.arena.deinit();
            self.budget.destroy();
            self.* = undefined;
        }
    };
}
fn Parsed(comptime Claims: type) type {
    return struct {
        budget: *engine.host_budget_allocator.SharedHostBudget,
        arena: std.heap.ArenaAllocator,
        claims: Claims,
        proof_bytes: []const u8,
        fn init(a: std.mem.Allocator, bytes: []const u8, magic: *const [8]u8, limits: Limits) !@This() {
            if (limits.artifact_bytes == 0 or limits.decode_bytes == 0 or bytes.len > limits.artifact_bytes) return error.EndpointTransportSizeLimit;
            var cursor = Cursor.init(bytes);
            if (!std.mem.eql(u8, try cursor.take(8), magic) or !std.mem.eql(u8, try cursor.take(32), &Fields.schemaId(Claims))) return error.UntrustedEndpointTransport;
            const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(a, limits.decode_bytes);
            errdefer budget.destroy();
            var arena = std.heap.ArenaAllocator.init(budget.allocator());
            errdefer arena.deinit();
            var remaining = limits.claim_items;
            const claims = try Fields.decode(Claims, arena.allocator(), &cursor, &remaining);
            if (cursor.position >= bytes.len) return error.TruncatedEndpointTransport;
            return .{ .budget = budget, .arena = arena, .claims = claims, .proof_bytes = bytes[cursor.position..] };
        }
        fn deinit(self: *@This()) void {
            self.arena.deinit();
            self.budget.destroy();
        }
        fn finish(self: *@This(), config: core.pcs.PcsConfig, columns: []const u32, max_log: u32, limits: Limits) !Owned(Claims) {
            if (columns.len < 2 or columns.len > 256 or max_log > limits.max_row_log or config.lifting_log_size != null) return error.InvalidEndpointTransportGeometry;
            const a = self.arena.allocator();
            const empty = try a.alloc(bool, columns.len);
            @memset(empty, false);
            const widths = try a.alloc(u32, columns.len);
            @memset(widths, 6);
            try postcard.proof_preflight.validateRuntime(self.proof_bytes, .{
                .config = .{ .pow_bits = config.pow_bits, .log_blowup_factor = config.fri_config.log_blowup_factor, .n_queries = config.fri_config.n_queries, .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound, .fold_step = config.fri_config.fold_step, .lifting_log_size = config.lifting_log_size },
                .tree_columns = columns,
                .empty_tree_flags = empty,
                .sample_width_limits = widths,
                .allow_zero_samples = true,
                .max_column_log_size = max_log,
                .max_merkle_column_log_size = max_log,
                .hash_size = 32,
                .max_wire_bytes = limits.artifact_bytes,
            });
            var stream = std.io.fixedBufferStream(self.proof_bytes);
            const proof = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, stream.reader());
            if (stream.pos != self.proof_bytes.len) return error.TrailingEndpointTransport;
            return .{ .budget = self.budget, .arena = self.arena, .claims = self.claims, .stark = proof };
        }
    };
}
pub fn bridge(a: std.mem.Allocator, bytes: []const u8, count: u32, max_log: u32, config: core.pcs.PcsConfig, limits: Limits) !Owned([]Q) {
    if (count == 0 or count > 127 or max_log < 4 or max_log > limits.max_row_log) return error.InvalidEndpointTransportGeometry;
    var parsed = try Parsed([]Q).init(a, bytes, "B8GBR001", limits);
    errdefer parsed.deinit();
    if (parsed.claims.len != count) return error.InvalidEndpointTransportGeometry;
    const columns = try parsed.arena.allocator().alloc(u32, 2 * count + 2);
    columns[0] = count;
    @memset(columns[1..][0..count], 23);
    @memset(columns[1 + count ..][0..count], 4);
    columns[columns.len - 1] = @intCast(core.verifier_types.compositionColumnCount(1, 4) orelse return error.InvalidEndpointTransportGeometry);
    return parsed.finish(config, columns, max_log, limits);
}
pub fn legacy(a: std.mem.Allocator, bytes: []const u8, interval_log: u32, config: core.pcs.PcsConfig, limits: Limits) !Owned(LegacyClaims) {
    var parsed = try Parsed(LegacyClaims).init(a, bytes, "B8GMR001", limits);
    errdefer parsed.deinit();
    const t = parsed.arena.allocator();
    const geometry = try t.alloc(@import("block_v5_ram_lanes_protocol_v1.zig").Claim, parsed.claims.ram.len);
    for (geometry, parsed.claims.ram) |*value, claim| value.* = claim.geometry;
    var layout = try Layout.Layout.init(t, geometry, interval_log, .{});
    defer layout.deinit();
    var max_log: u32 = 16;
    for (layout.parts) |part| max_log = @max(max_log, part.log);
    var columns: [4]u32 = undefined;
    for (layout.columns, columns[0..3]) |count, *value| value.* = std.math.cast(u32, count) orelse return error.InvalidEndpointTransportGeometry;
    columns[3] = @intCast(core.verifier_types.compositionColumnCount(Layout.SPLIT, 4) orelse return error.InvalidEndpointTransportGeometry);
    return parsed.finish(config, &columns, max_log, limits);
}
pub fn compact(a: std.mem.Allocator, bytes: []const u8, event_count: u32, boundary_log: u32, config: core.pcs.PcsConfig, limits: Limits) !Owned(Compact.Claims) {
    if (event_count == 0 or event_count > 1 << 24 or boundary_log < 4 or boundary_log > limits.max_row_log) return error.InvalidEndpointTransportGeometry;
    var parsed = try Parsed(Compact.Claims).init(a, bytes, "B8CMR001", limits);
    errdefer parsed.deinit();
    const max_log = @max(16, @max(boundary_log, std.math.log2_int_ceil(u32, event_count)));
    const composition: u32 = @intCast(core.verifier_types.compositionColumnCount(2, 4) orelse return error.InvalidEndpointTransportGeometry);
    return parsed.finish(config, &.{ 13, 12, 1, 1, 24, 8, 8, composition }, max_log, limits);
}
