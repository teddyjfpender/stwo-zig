//! One recursive STARK verifies all local, rebinding and compact-global bodies.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Parent = @import("blake3_execution_parent_proof.zig");
const Source = @import("block_v8_endpoint_group_join_source_v1.zig");
const Roster = @import("block_v8_endpoint_group_join_roster_v1.zig");
const Protocol = @import("block_v8_endpoint_group_join_protocol_v1.zig");
const Profile = @import("blake3_execution_parent_protocol.zig").Profile;
pub const Options = struct { source_workers: u8 = 1, global_g_repartition: bool = false };
pub const Stats = struct {
    source_workers: u8 = 1,
    global_g_repartition: bool = false,
    fixed_compile_ns: u64 = 0,
    fixed_commit_ns: u64 = 0,
    witness_ns: u64 = 0,
    plan_ns: u64 = 0,
    proof_ns: u64 = 0,
    encode_ns: u64 = 0,
    compiler_release_ns: u64 = 0,
    compiler_released_bytes: usize = 0,
    retained_rows_bytes: usize = 0,
};
pub const Artifact = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    whole_ns: u64,
    proof_ns: u64,
    stats: Stats = .{},
    pub fn deinit(v: *Artifact) void {
        v.allocator.free(v.bytes);
        v.* = undefined;
    }
};
pub fn produce(a: std.mem.Allocator, sources: []const Source.Source, captures: []const Source.Capture, extra: []const core.fields.qm31.QM31, profile: Profile) !Artifact {
    return produceWithOptions(a, sources, captures, extra, profile, .{});
}
pub fn produceWithOptions(a: std.mem.Allocator, sources: []const Source.Source, captures: []const Source.Capture, extra: []const core.fields.qm31.QM31, profile: Profile, options: Options) !Artifact {
    if (options.source_workers == 0 or options.source_workers > 4) return error.InvalidEndpointJoinWorkers;
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var stats: Stats = .{ .source_workers = options.source_workers, .global_g_repartition = options.global_g_repartition };
    var setup = try Roster.Owned.deriveWithOptions(a, sources, extra, .{ .global_g_repartition = options.global_g_repartition });
    defer setup.deinit();
    stats.fixed_compile_ns = phase.lap();
    std.debug.print("B8_GROUP_JOIN_STAGE fixed_compile_ns={d}\n", .{stats.fixed_compile_ns});
    if (!std.meta.eql(profile.config(), setup.context.child_config)) return error.EndpointJoinConfigMismatch;
    const Fixed = @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu);
    var committed: ?Fixed.Committed = try Fixed.deriveCommitted(a, setup.fixed, setup.context, profile);
    defer if (committed) |*c| c.deinit();
    const expected = [_]Protocol.Bus.Expected{.{ .digest = Protocol.digest(setup.values) }};
    const key = try Protocol.Key.fromGeometry(committed.?.key, setup.wires, &expected);
    const admission = try Protocol.Admission.init(key, try key.identity(), setup.wires, .{ .children = &.{setup.values} }, &expected);
    stats.fixed_commit_ns = phase.lap();
    std.debug.print("B8_GROUP_JOIN_STAGE fixed_commit_ns={d}\n", .{stats.fixed_commit_ns});
    var rows = try setup.liveWithWorkers(a, sources, captures, options.source_workers);
    defer rows.deinit();
    stats.witness_ns = phase.lap();
    stats.retained_rows_bytes = try rows.retainedBytes();
    std.debug.print("B8_GROUP_JOIN_STAGE witness_ns={d} retained_rows_bytes={d}\n", .{ stats.witness_ns, stats.retained_rows_bytes });
    const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const plan = try Plan.initFromFixedCommitment(a, &rows, admission, &committed.?);
    defer plan.deinit();
    committed.?.deinit();
    committed = null;
    const owner = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.fromAllocator(a);
    const before_release = if (owner) |b| b.snapshot().live_bytes else 0;
    var release_timer = try std.time.Timer.start();
    setup.releaseCompilerState();
    stats.compiler_release_ns = release_timer.read();
    stats.compiler_released_bytes = if (owner) |b| before_release - b.snapshot().live_bytes else 0;
    std.debug.print("B8_GROUP_JOIN_STAGE compiler_released_bytes={d} compiler_release_ns={d}\n", .{ stats.compiler_released_bytes, stats.compiler_release_ns });
    stats.plan_ns = phase.lap();
    std.debug.print("B8_GROUP_JOIN_STAGE plan_ns={d}\n", .{stats.plan_ns});
    var timer = try std.time.Timer.start();
    var proof = try plan.proveConsuming(a, &rows);
    defer proof.deinit();
    const proof_ns = timer.read();
    stats.proof_ns = proof_ns;
    phase.reset();
    const bytes = try Parent.codec.encode(a, &proof, &admission);
    stats.encode_ns = phase.lap();
    return .{ .allocator = a, .bytes = bytes, .whole_ns = whole.read(), .proof_ns = proof_ns, .stats = stats };
}
/// Receiver gets independently admitted metadata/physical claims and rebuilds
/// every fixed row. No original proof capture and no host ledger receipt.
fn verify(a: std.mem.Allocator, bytes: []const u8, sources: []const Source.Source, extra: []const core.fields.qm31.QM31, profile: Profile, options: Options) !@import("blake3_native_parent_verifier.zig").Verified {
    var setup = try Roster.Owned.deriveWithOptions(a, sources, extra, .{ .global_g_repartition = options.global_g_repartition });
    defer setup.deinit();
    const geometry = try @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu).derive(a, setup.fixed, setup.context, profile);
    const expected = [_]Protocol.Bus.Expected{.{ .digest = Protocol.digest(setup.values) }};
    const key = try Protocol.Key.fromGeometry(geometry, setup.wires, &expected);
    const admission = try Protocol.Admission.init(key, try key.identity(), setup.wires, .{ .children = &.{setup.values} }, &expected);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var verified = try Parent.verify(&decoded, &admission);
    errdefer verified.deinit();
    try verified.validate(&admission, try key.identity());
    return verified;
}
pub const production_active = false;
/// Complete receiving API: physical claims nominate operands; each key is
/// reconstructed from externally admitted metadata before the one root opens.
pub fn verifyAdmitted(a: std.mem.Allocator, bytes: []const u8, admissions: []const Source.Admission, extra: []const core.fields.qm31.QM31, profile: Profile) !@import("blake3_native_parent_verifier.zig").Verified {
    return verifyAdmittedWithOptions(a, bytes, admissions, extra, profile, .{});
}
pub fn verifyAdmittedWithOptions(a: std.mem.Allocator, bytes: []const u8, admissions: []const Source.Admission, extra: []const core.fields.qm31.QM31, profile: Profile, options: Options) !@import("blake3_native_parent_verifier.zig").Verified {
    const sources = try a.alloc(Source.Source, admissions.len);
    defer a.free(sources);
    var count: usize = 0;
    defer for (sources[0..count]) |source| Source.deinitProfile(source);
    for (admissions, 0..) |admission, i| {
        sources[i] = try admission.derive(a);
        count += 1;
    }
    return verify(a, bytes, sources, extra, profile, options);
}
