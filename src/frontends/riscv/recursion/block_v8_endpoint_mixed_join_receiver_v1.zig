//! Byte-only fresh receiver for the canonical two-cohort closed-window root.
//! No original proofs, producer keys, proof captures or successful receipts.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Local = @import("block_v8_endpoint_mixed_recursive_v1.zig");
const Bridge = @import("block_v8_endpoint_bridge_recursive_v1.zig");
const Global = @import("block_v8_compact_ram_recursive_v1.zig");
const Scope = @import("../prover/block_v8_endpoint_mixed_scope_v1.zig");
const Metadata = @import("../prover/block_v8_endpoint_mixed_statement_wire_v1.zig");
const Window = @import("../prover/block_v7_real_window_policy_v2.zig");
const BridgeScope = @import("../prover/block_v8_endpoint_global_bridge_scope_v1.zig");
const Source = @import("block_v8_endpoint_join_source_v1.zig");
pub const External = @import("../prover/block_v8_endpoint_local_bundle_v1.zig").External;
pub const Claims = struct { mixed: Local.Ledger.Claims, bridge: []const Q, global: Global.Original.Claims };
pub const Input = struct { global_g_repartition: bool = false, root: []const u8, physical_claims: []const u8, mixed_metadata: []const u8, global_roots: [4][32]u8, cohort_policy: Window.CohortPolicy, selected_addresses: []const u32 };
pub const Verified = @import("blake3_native_parent_verifier.zig").Verified;
/// Independently admitted metadata only. No original proof, proof capture or
/// producer key is accepted. Heap-owned statements keep every admission valid
/// while an upper receiver independently compiles the exact child fixed key.
pub const MetadataOwned = struct {
    arena: std.heap.ArenaAllocator,
    mixed: *Local.Statement.Owned,
    bridge: *Bridge.Statement.Owned,
    global: *Global.Statement.Owned,
    admissions: [3]Source.Admission,
    extra: [264]Q,
    pub fn deinit(self: *@This()) void {
        self.global.deinit();
        self.bridge.deinit();
        self.mixed.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn admitMetadata(a: std.mem.Allocator, external: External, input: Input) !MetadataOwned {
    if (input.cohort_policy.cohort_count != 1 or input.physical_claims.len > 16 << 20 or input.root.len > 16 << 20 or !std.meta.eql(external.config, @import("blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config())) return error.UnsupportedEndpointJoinReceiving;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    var cursor = @import("../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = input.physical_claims };
    var remaining: usize = 1 << 20;
    const claims = try @import("../prover/block_v7_union_claim_wire_v1.zig").decode(Claims, arena.allocator(), &cursor, &remaining);
    if (cursor.position != input.physical_claims.len or claims.bridge.len != input.cohort_policy.cohort_count) return error.NonCanonicalEndpointJoinClaims;
    var window = try Window.Owned.deriveCohortsForAddressesWithBoundary(a, external.elf, external.incoming, external.outgoing, external.trusted, input.cohort_policy, input.selected_addresses, external.boundary, .{});
    defer window.deinit();
    const trusted = Scope.Trusted{ .elf = external.elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .cohort_count = input.cohort_policy.cohort_count, .terminal_cycle = if (external.boundary.terminal != null) external.trusted.window.cycles else null, .boundary_policy_id = if (external.boundary.terminal) |last| last.policy_id else @splat(0) };
    const mixed = try Metadata.decode(a, input.mixed_metadata, trusted, .{});
    errdefer mixed.deinit();
    const scope = try Scope.Owned.init(a, trusted, mixed.input, .{});
    defer scope.deinit();
    const source = scope.source();
    const pins = try a.alloc(BridgeScope.Source, 1);
    defer a.free(pins);
    for (pins) |*pin| pin.* = .{ .local_identity = source.local_identity, .local_epoch = source.local_epoch, .endpoint_root = source.endpoint_root, .endpoint_count = source.endpoint_count, .policy = source.policy };
    const policy = Global.Original.Policy{ .window = &window, .config = external.config, .event_count = source.endpoint_count };
    const bridge = try Bridge.Statement.Owned.init(a, .{ .config = external.config, .block_statement = try policy.digest() }, .{ .sources = pins, .global_memory = try policy.entry(input.global_roots), .batch_first = 0, .batch_count = input.cohort_policy.cohort_count });
    errdefer bridge.deinit();
    const global = try Global.Statement.Owned.init(a, .{ .config = external.config, .policy = policy }, .{ .epoch = bridge.scope.epoch, .entries = bridge.scope.entries, .roots = input.global_roots });
    errdefer global.deinit();
    const admitted = [_]Source.Admission{ .{ .mixed = .{ .statement = mixed, .claims = claims.mixed } }, .{ .bridge = .{ .statement = bridge, .claims = claims.bridge } }, .{ .global = .{ .statement = global, .claims = claims.global } } };
    var extra: [264]Q = undefined;
    var words: [66]u32 = undefined;
    words[0] = window.boundary.initial_cpu.pc;
    @memcpy(words[1..33], &window.boundary.initial_cpu.regs);
    words[33] = window.boundary.final_cpu.pc;
    @memcpy(words[34..66], &window.boundary.final_cpu.regs);
    for (words, 0..) |word, i| for (0..4) |byte| {
        extra[4 * i + byte] = Q.fromBase(core.fields.m31.M31.fromCanonical((word >> @as(u5, @intCast(8 * byte))) & 255));
    };
    return .{ .arena = arena, .mixed = mixed, .bridge = bridge, .global = global, .admissions = admitted, .extra = extra };
}

pub fn verify(a: std.mem.Allocator, external: External, input: Input) !Verified {
    var metadata = try admitMetadata(a, external, input);
    defer metadata.deinit();
    return @import("block_v8_endpoint_join_pipeline_v1.zig").verifyAdmittedWithOptions(a, input.root, &metadata.admissions, &metadata.extra, .csp_q70_pow26, .{ .global_g_repartition = input.global_g_repartition });
}
