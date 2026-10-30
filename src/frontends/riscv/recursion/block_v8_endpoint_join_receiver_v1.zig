//! Byte-only fresh receiver for the canonical two-cohort closed-window root.
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
pub const Claims = struct { local0: Local.Ledger.Claims, local1: Local.Ledger.Claims, bridge: []const Q, global: Global.Original.Claims };
pub const Input = struct { root: []const u8, physical_claims: []const u8, local_metadata: [2][]const u8, global_roots: [4][32]u8, cohort_policy: Window.CohortPolicy, selected_addresses: []const u32 };
pub const Verified = @import("blake3_native_parent_verifier.zig").Verified;
pub fn verify(a: std.mem.Allocator, external: External, input: Input) !Verified {
    if (input.cohort_policy.cohort_count != 2 or input.physical_claims.len > 8 << 20 or input.root.len > 16 << 20 or !std.meta.eql(external.config, @import("blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config())) return error.UnsupportedEndpointJoinReceiving;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var cursor = @import("../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = input.physical_claims };
    var remaining: usize = 1 << 20;
    const claims = try @import("../prover/block_v7_union_claim_wire_v1.zig").decode(Claims, arena.allocator(), &cursor, &remaining);
    if (cursor.position != input.physical_claims.len) return error.NonCanonicalEndpointJoinClaims;
    var window = try Window.Owned.deriveCohortsForAddresses(a, external.elf, external.incoming, external.outgoing, external.trusted, input.cohort_policy, input.selected_addresses, .{});
    defer window.deinit();
    const trusted = Scope.Trusted{ .elf = external.elf, .elf_sha256 = external.trusted.elf_sha256, .profile = .rv32im_zkvm_ethereum_sha_v1, .config = external.config, .cohort_count = 2 };
    const first = try Metadata.decode(a, input.local_metadata[0], trusted, .{});
    defer first.deinit();
    const second = try Metadata.decode(a, input.local_metadata[1], trusted, .{});
    defer second.deinit();
    const scope0 = try Scope.Owned.init(a, trusted, first.input, .{});
    defer scope0.deinit();
    const scope1 = try Scope.Owned.init(a, trusted, second.input, .{});
    defer scope1.deinit();
    const s0 = scope0.source();
    const s1 = scope1.source();
    const pins = [_]BridgeScope.Source{ .{ .local_identity = s0.local_identity, .local_epoch = s0.local_epoch, .endpoint_root = s0.endpoint_root, .endpoint_count = s0.endpoint_count, .policy = s0.policy }, .{ .local_identity = s1.local_identity, .local_epoch = s1.local_epoch, .endpoint_root = s1.endpoint_root, .endpoint_count = s1.endpoint_count, .policy = s1.policy } };
    const policy = Global.Original.Policy{ .window = &window, .config = external.config, .event_count = try std.math.add(u32, s0.endpoint_count, s1.endpoint_count) };
    const bridge = try Bridge.Statement.Owned.init(a, .{ .config = external.config, .block_statement = try policy.digest() }, .{ .sources = &pins, .global_memory = try policy.entry(input.global_roots), .batch_first = 0, .batch_count = 2 });
    defer bridge.deinit();
    const global = try Global.Statement.Owned.init(a, .{ .config = external.config, .policy = policy }, .{ .epoch = bridge.scope.epoch, .entries = bridge.scope.entries, .roots = input.global_roots });
    defer global.deinit();
    const admitted = [_]Source.Admission{ .{ .local = .{ .statement = first, .claims = claims.local0 } }, .{ .local = .{ .statement = second, .claims = claims.local1 } }, .{ .bridge = .{ .statement = bridge, .claims = claims.bridge } }, .{ .global = .{ .statement = global, .claims = claims.global } } };
    var extra: [264]Q = undefined;
    var words: [66]u32 = undefined;
    words[0] = window.boundary.initial_cpu.pc;
    @memcpy(words[1..33], &window.boundary.initial_cpu.regs);
    words[33] = window.boundary.final_cpu.pc;
    @memcpy(words[34..66], &window.boundary.final_cpu.regs);
    for (words, 0..) |word, i| for (0..4) |byte| {
        extra[4 * i + byte] = Q.fromBase(core.fields.m31.M31.fromCanonical((word >> @as(u5, @intCast(8 * byte))) & 255));
    };
    return @import("block_v8_endpoint_join_pipeline_v1.zig").verifyAdmitted(a, input.root, &admitted, &extra, .csp_q70_pow26);
}
