//! Opt-in native-only joined original -> ONE recursive STARK containing the
//! execution/global closure graph. V7 remains unchanged. Fresh verification
//! reconstructs expected metadata, rows and key; it performs no host closure.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Multi = @import("../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Profile = @import("block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Statement = @import("../prover/block_v7_multi_union_statement_v1.zig").ForMode(true);
const Capsule = @import("block_v7_union_compiler_capsule_v1.zig").Capsule;
const Public = @import("block_v8_union_closed_public_v1.zig");
const Graph = @import("air/block_v8_union_closed_graph_v1.zig");
const Roster = @import("block_v8_union_closed_roster_v1.zig");
const Protocol = @import("block_v8_union_closed_parent_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const ClaimWire = @import("../prover/block_v7_union_claim_wire_v1.zig");
pub const Limits = @import("block_v7_union_pipeline_v1.zig").Limits;
pub const Artifact = @import("block_v7_union_pipeline_v1.zig").Artifact;
pub const Stats = @import("block_v7_union_pipeline_v1.zig").Stats;
pub const Verified = @import("blake3_native_parent_verifier.zig").Verified;
fn expected(capsule: *const Capsule, graph: *const Graph.Prepared) !Protocol.Bus.Expected {
    return .{ .profile = capsule.profile().seal, .epoch = capsule.profile().statement.input.epoch.digest, .roots = @intCast(try @import("air/block_v7_union_transcript_v1.zig").firstInteraction(capsule.profile())), .closure = graph.circuit.identity_digest };
}
pub fn produce(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture, limits: Limits) !Artifact {
    if (limits.capacity == 0 or limits.max_claim_bytes == 0 or limits.max_claim_items == 0 or !std.meta.eql(limits.profile.config(), profile.statement.input.epoch.config)) return error.InvalidClosedUnionPipeline;
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var stats: Stats = .{};
    const capsule = try Capsule.derive(a, profile.statement, &capture.claims, profile.limits);
    defer capsule.deinit();
    try capsule.requireCapture(a, capture);
    if (!std.meta.eql(capsule.profile().seal, profile.seal)) return error.UntrustedClosedUnionProfile;
    var values = try Public.Values.derive(a, capsule);
    defer values.deinit();
    var graph = try Graph.prepare(a, capsule, values);
    defer graph.deinit();
    var cold = try Roster.Owned.derive(a, capsule, &graph, limits.capacity, limits.fixed);
    var cold_live = true;
    defer if (cold_live) cold.deinit();
    stats.fixed_compile_ns = phase.lap();
    const Fixed = @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu);
    var committed: ?Fixed.Committed = try Fixed.deriveCommitted(a, cold.fixed, cold.context, limits.profile);
    defer if (committed) |*owner| owner.deinit();
    const roster = [_]Protocol.Bus.Expected{try expected(capsule, &graph)};
    const key = try Protocol.Key.fromGeometry(committed.?.key, cold.wires, &roster);
    stats.fixed_commit_ns = phase.lap();
    var ready = try @import("block_v7_union_preparation_v1.zig").prepareFromCapsule(a, capsule, capture, limits.capacity, limits.preparation);
    defer ready.deinit();
    stats.witness_prepare_ns = phase.lap();
    const wires = try cold.attach(a, &ready, &graph, values);
    defer a.free(wires);
    stats.retained_rows_bytes = try ready.recursive.rows.retainedBytes();
    cold.deinit();
    cold_live = false;
    stats.fixed_parity_ns = phase.lap();
    const admission = try Protocol.Admission.init(key, try key.identity(), wires, .{ .children = &.{values} }, &roster);
    const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const plan = try Plan.initFromFixedCommitment(a, &ready.recursive.rows, admission, &committed.?);
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
/// No host Closure.close invocation. The independently reconstructed closure
/// equations are authenticated by this same single parent STARK.
pub fn verify(a: std.mem.Allocator, root: []const u8, physical_claims: []const u8, metadata: *const Statement.Owned, original_limits: Multi.Limits, limits: Limits) !Verified {
    if (limits.capacity == 0 or limits.max_claim_items == 0 or physical_claims.len > limits.max_claim_bytes or !std.meta.eql(limits.profile.config(), metadata.input.epoch.config)) return error.InvalidClosedUnionPipeline;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var cursor = @import("../prover/guest_precompile/proof_artifact_wire.zig").Cursor{ .bytes = physical_claims };
    var count = limits.max_claim_items;
    const claims = try ClaimWire.decode(Multi.Claims, arena.allocator(), &cursor, &count);
    if (cursor.position != physical_claims.len) return error.NonCanonicalClosedUnionClaims;
    const capsule = try Capsule.derive(a, metadata, &claims, .{ .original = original_limits });
    defer capsule.deinit();
    var values = try Public.Values.derive(a, capsule);
    defer values.deinit();
    var graph = try Graph.compile(a, capsule, values);
    defer graph.deinit();
    var cold = try Roster.Owned.derive(a, capsule, &graph, limits.capacity, limits.fixed);
    defer cold.deinit();
    const geometry = try @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu).derive(a, cold.fixed, cold.context, limits.profile);
    const roster = [_]Protocol.Bus.Expected{try expected(capsule, &graph)};
    const key = try Protocol.Key.fromGeometry(geometry, cold.wires, &roster);
    const admission = try Protocol.Admission.init(key, try key.identity(), cold.wires, .{ .children = &.{values} }, &roster);
    var decoded = try Parent.codec.decode(a, root, &admission);
    var verified = try Parent.verify(&decoded, &admission);
    errdefer verified.deinit();
    try verified.validate(&admission, try key.identity());
    return verified;
}
