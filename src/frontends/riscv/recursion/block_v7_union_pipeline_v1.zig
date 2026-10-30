//! Shared-original -> single recursive proof, with one independently compiled
//! fixed commitment reused for proving. All parent rows are consumed before
//! returning durable bytes. No source receipt substitutes for fresh receiving.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Profile = @import("block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Multi = @import("../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Statement = @import("../prover/block_v7_multi_union_statement_v1.zig").ForMode(true);
const ClaimWire = @import("../prover/block_v7_union_claim_wire_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Protocol = @import("block_v7_union_parent_protocol_v1.zig");
const Receiver = @import("block_v7_union_receiver_v1.zig");
pub const Limits = struct {
    capacity: u32 = 4,
    profile: @import("blake3_execution_parent_protocol.zig").Profile = .csp_q70_pow26,
    fixed: @import("block_v7_union_fixed_roster_v1.zig").Limits = .{},
    preparation: @import("block_v7_union_preparation_v1.zig").Limits = .{},
    max_claim_bytes: usize = 8 << 20,
    max_claim_items: usize = 1 << 18,
};
pub const Stats = struct {
    fixed_compile_ns: u64 = 0,
    fixed_commit_ns: u64 = 0,
    witness_prepare_ns: u64 = 0,
    fixed_parity_ns: u64 = 0,
    plan_ns: u64 = 0,
    proof_ns: u64 = 0,
    encoding_ns: u64 = 0,
    whole_ns: u64 = 0,
    retained_rows_bytes: usize = 0,
    fixed_commitment_reused: bool = false,
};
pub const Artifact = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    claims: []u8,
    stats: Stats,
    pub fn deinit(self: *Artifact) void {
        self.allocator.free(self.bytes);
        self.allocator.free(self.claims);
        self.* = undefined;
    }
};
pub fn produce(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture, limits: Limits) !Artifact {
    if (limits.capacity == 0 or limits.max_claim_bytes == 0 or limits.max_claim_items == 0 or !std.meta.eql(limits.profile.config(), profile.statement.input.epoch.config)) return error.InvalidUnionPipelinePolicy;
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var stats: Stats = .{};
    const capsule = try @import("block_v7_union_compiler_capsule_v1.zig").Capsule.derive(a, profile.statement, &capture.claims, profile.limits);
    defer capsule.deinit();
    if (!std.meta.eql(capsule.profile().seal, profile.seal)) return error.UntrustedUnionCompilerProfile;
    var cold = try @import("block_v7_union_fixed_roster_v1.zig").Owned.deriveFromCapsule(a, capsule, limits.capacity, limits.fixed);
    var cold_live = true;
    defer if (cold_live) cold.deinit();
    stats.fixed_compile_ns = phase.lap();
    const Fixed = @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu);
    var committed: ?Fixed.Committed = try Fixed.deriveCommitted(a, cold.fixed, cold.context, limits.profile);
    defer if (committed) |*owned| owned.deinit();
    const roster = [_]Protocol.Bus.Expected{try Receiver.expected(profile)};
    const key = try Protocol.Key.fromGeometry(committed.?.key, cold.wires, &roster);
    stats.fixed_commit_ns = phase.lap();
    var ready = try @import("block_v7_union_preparation_v1.zig").prepareFromCapsule(a, capsule, capture, limits.capacity, limits.preparation);
    defer ready.deinit();
    stats.witness_prepare_ns = phase.lap();
    try cold.validateLive(&ready);
    stats.retained_rows_bytes = try ready.recursive.rows.retainedBytes();
    cold.deinit();
    cold_live = false;
    stats.fixed_parity_ns = phase.lap();
    const admission = try Protocol.Admission.init(key, try key.identity(), ready.wires, .{ .children = &.{ready.values} }, &roster);
    const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const plan = try Plan.initFromFixedCommitment(a, &ready.recursive.rows, admission, &committed.?);
    // Plan owns its retained lease. It does not recommit these fixed columns.
    committed.?.deinit();
    committed = null;
    defer plan.deinit();
    stats.fixed_commitment_reused = true;
    stats.plan_ns = phase.lap();
    var proof = try plan.proveConsuming(a, &ready.recursive.rows);
    defer proof.deinit();
    stats.proof_ns = phase.lap();
    const bytes = try Parent.codec.encode(a, &proof, &admission);
    errdefer a.free(bytes);
    var writer = @import("../prover/bounded_artifact_writer_v1.zig").Writer.init(a, limits.max_claim_bytes);
    defer writer.deinit();
    var count = limits.max_claim_items;
    try ClaimWire.encode(Multi.Claims, &writer, capture.claims, &count);
    const claims = try writer.bytes.toOwnedSlice(a);
    stats.encoding_ns = phase.lap();
    stats.whole_ns = whole.read();
    return .{ .allocator = a, .bytes = bytes, .claims = claims, .stats = stats };
}
/// Finite claim decoding and independent key setup. Metadata must come from the
/// external ELF/endpoints admission path, never a producer-trusted pointer.
/// The returned equation owns its allocations independently of decode storage.
pub fn verify(a: std.mem.Allocator, root: []const u8, physical_claims: []const u8, metadata: *const Statement.Owned, original_limits: Multi.Limits, limits: Limits) !Receiver.Verified {
    if (limits.capacity == 0 or limits.max_claim_items == 0 or physical_claims.len > limits.max_claim_bytes or !std.meta.eql(limits.profile.config(), metadata.input.epoch.config)) return error.InvalidUnionPipelinePolicy;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var cursor = @import("../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = physical_claims };
    var count = limits.max_claim_items;
    const claims = try ClaimWire.decode(Multi.Claims, arena.allocator(), &cursor, &count);
    if (cursor.position != physical_claims.len) return error.NonCanonicalUnionClaimSuffix;
    return Receiver.verifyStatement(a, root, metadata, &claims, .{ .original = original_limits }, limits.capacity, limits.profile, limits.fixed);
}
