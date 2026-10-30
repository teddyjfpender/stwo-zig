//! Byte-only fresh receiver for the bounded many-cohort closed-window root.
//! No original proofs, producer keys, proof captures or successful receipts.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Local = @import("block_v8_endpoint_recursive_adapter_v1.zig").For(.local_open);
const Bridge = @import("block_v8_endpoint_bridge_recursive_v1.zig");
const Global = @import("block_v8_compact_ram_recursive_v1.zig");
const Scope = @import("../prover/block_v8_endpoint_local_scope_v1.zig");
const Metadata = @import("../prover/block_v8_endpoint_local_statement_wire_v1.zig");
const Window = @import("../prover/block_v7_real_window_policy_v2.zig");
const BridgeScope = @import("../prover/block_v8_endpoint_global_bridge_scope_v1.zig");
const Source = @import("block_v8_endpoint_join_source_v1.zig");
pub const External = @import("../prover/block_v8_endpoint_local_bundle_v1.zig").External;
pub const Claims = struct { locals: []Local.Ledger.Claims, bridge: []const Q, global: Global.Original.Claims };
pub const Input = struct { global_g_repartition: bool = false, root: []const u8, physical_claims: []const u8, local_metadata: []const []const u8, global_roots: [4][32]u8, cohort_policy: Window.CohortPolicy, selected_addresses: []const u32 };
pub const Verified = @import("blake3_native_parent_verifier.zig").Verified;
pub fn verify(a: std.mem.Allocator, external: External, input: Input) !Verified {
    const n = input.local_metadata.len;
    if (n == 0 or n > 62 or n != input.cohort_policy.cohort_count or input.physical_claims.len > 8 << 20 or input.root.len > 32 << 20 or !std.meta.eql(external.config, @import("blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config())) return error.UnsupportedEndpointJoinReceiving;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var cursor = @import("../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = input.physical_claims };
    var remaining: usize = 1 << 20;
    const claims = try @import("../prover/block_v7_union_claim_wire_v1.zig").decode(Claims, arena.allocator(), &cursor, &remaining);
    if (cursor.position != input.physical_claims.len or claims.locals.len != n or claims.bridge.len != n) return error.NonCanonicalEndpointJoinClaims;
    var window = try Window.Owned.deriveCohortsForAddressesWithBoundary(a, external.elf, external.incoming, external.outgoing, external.trusted, input.cohort_policy, input.selected_addresses, external.boundary, .{});
    defer window.deinit();
    const trusted = Scope.Trusted{ .elf = external.elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .cohort_count = @intCast(n), .terminal_cycle = if (external.boundary.terminal != null) external.trusted.window.cycles else null, .boundary_policy_id = if (external.boundary.terminal) |last| last.policy_id else @splat(0) };
    const statements = try a.alloc(*Local.Statement.Owned, n);
    defer a.free(statements);
    var count: usize = 0;
    defer for (statements[0..count]) |statement| statement.deinit();
    const pins = try a.alloc(BridgeScope.Source, n);
    defer a.free(pins);
    const admitted = try a.alloc(Source.Admission, n + 2);
    defer a.free(admitted);
    var events: u32 = 0;
    for (input.local_metadata, 0..) |bytes, i| {
        statements[i] = try Metadata.decode(a, bytes, trusted, .{});
        count += 1;
        const local = try Scope.Owned.init(a, trusted, statements[i].input, .{});
        defer local.deinit();
        const source = local.source();
        pins[i] = .{ .local_identity = source.local_identity, .local_epoch = source.local_epoch, .endpoint_root = source.endpoint_root, .endpoint_count = source.endpoint_count, .policy = source.policy };
        events = try std.math.add(u32, events, source.endpoint_count);
        admitted[i] = .{ .local = .{ .statement = statements[i], .claims = claims.locals[i] } };
    }
    const policy = Global.Original.Policy{ .window = &window, .config = external.config, .event_count = events };
    const bridge = try Bridge.Statement.Owned.init(a, .{ .config = external.config, .block_statement = try policy.digest() }, .{ .sources = pins, .global_memory = try policy.entry(input.global_roots), .batch_first = 0, .batch_count = @intCast(n) });
    defer bridge.deinit();
    const global = try Global.Statement.Owned.init(a, .{ .config = external.config, .policy = policy }, .{ .epoch = bridge.scope.epoch, .entries = bridge.scope.entries, .roots = input.global_roots });
    defer global.deinit();
    admitted[n] = .{ .bridge = .{ .statement = bridge, .claims = claims.bridge } };
    admitted[n + 1] = .{ .global = .{ .statement = global, .claims = claims.global } };
    const extra = boundaryBytes(&window);
    return @import("block_v8_endpoint_join_pipeline_v1.zig").verifyAdmittedWithOptions(a, input.root, admitted, &extra, .csp_q70_pow26, .{ .global_g_repartition = input.global_g_repartition });
}
pub fn boundaryBytes(window: *const Window.Owned) [264]Q {
    var extra: [264]Q = undefined;
    var words: [66]u32 = undefined;
    words[0] = window.boundary.initial_cpu.pc;
    @memcpy(words[1..33], &window.boundary.initial_cpu.regs);
    words[33] = window.boundary.final_cpu.pc;
    @memcpy(words[34..66], &window.boundary.final_cpu.regs);
    for (words, 0..) |word, i| for (0..4) |byte| {
        extra[4 * i + byte] = Q.fromBase(core.fields.m31.M31.fromCanonical((word >> @as(u5, @intCast(8 * byte))) & 255));
    };
    return extra;
}
