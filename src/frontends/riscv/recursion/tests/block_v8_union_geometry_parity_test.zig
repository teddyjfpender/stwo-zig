//! Two genuine executions with distinct complete endpoint snapshots test the
//! proposed geometry-key boundary. No key-family admission is enabled here.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Capture = @import("../../prover/block_v7_real_window_capture_v1.zig");
const Run = @import("../../prover/block_v7_real_window_execution_v2.zig");
const Driver = @import("../../prover/block_v7_streaming_execution_mode_v1.zig").ForMode(true);
const Producer = @import("../../prover/block_v7_window_union_producer_v1.zig");
const Multi = @import("../../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Capsule = @import("../block_v7_union_compiler_capsule_v1.zig").Capsule;
const Cold = @import("../block_v7_union_fixed_roster_v1.zig");
const Storage = @import("../air/blake3_parent_row_storage.zig");
const Base = @import("../blake3_execution_parent_protocol.zig");
const Digest = [32]u8;
const Evidence = struct {
    incoming: Digest,
    profile: Digest,
    policy: Digest,
    fixed_rows: Digest,
    public_schedule: Digest,
    namespace: Digest,
    context: Base.Context,
    closed_fixed_rows: Digest,
    closed_schedule: Digest,
    closed_graph: Digest,
    closed_context: Base.Context,
};
fn u64hash(h: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    h.update(&bytes);
}
fn fixedDigest(rows: Storage.FixedTuple(false)) Digest {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-v8-full-fixed-row-geometry-parity-v1");
    inline for (0..Storage.Airs.len) |air| {
        u64hash(&h, air);
        u64hash(&h, rows[air].len);
        for (rows[air]) |row| for (row) |value| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, value.toU32(), .little);
            h.update(&bytes);
        };
    }
    return h.finalResult();
}
const Consumer = struct {
    pub const Result = Evidence;
    pub const limits: Multi.Limits = .{ .max_retained_pcs_bytes = 8 << 30 };
    pub fn discardStagedResult(_: Evidence) void {}
    pub fn consumeStagedWindow(f: Driver.StagedWindowFixture) !Evidence {
        const artifact = try Producer.produce(f, .{ .limits = limits });
        defer artifact.deinit();
        _ = try artifact.verify(limits);
        const capsule = try Capsule.derive(f.allocator, artifact.statement, &artifact.proof.claims, .{ .original = limits });
        defer capsule.deinit();
        var cold = try Cold.Owned.deriveFromCapsule(f.allocator, capsule, 4, .{});
        defer cold.deinit();
        const p = capsule.profile();
        const ClosedPublic = @import("../block_v8_union_closed_public_v1.zig");
        var closed_values = try ClosedPublic.Values.derive(f.allocator, capsule);
        defer closed_values.deinit();
        var closed_graph = try @import("../air/block_v8_union_closed_graph_v1.zig").compile(f.allocator, capsule, closed_values);
        defer closed_graph.deinit();
        var closed = try @import("../block_v8_union_closed_roster_v1.zig").Owned.derive(f.allocator, capsule, &closed_graph, 4, .{});
        defer closed.deinit();
        return .{ .incoming = p.statement.trusted.window.?.boundary.incoming_sha256, .profile = p.seal, .policy = p.policy, .fixed_rows = fixedDigest(cold.fixed), .public_schedule = try @import("../block_v7_union_public_v1.zig").scheduleDigest(cold.wires), .namespace = try cold.namespace.identity(), .context = cold.context, .closed_fixed_rows = fixedDigest(closed.fixed), .closed_schedule = try ClosedPublic.scheduleDigest(closed.wires), .closed_graph = closed_graph.circuit.identity_digest, .closed_context = closed.context };
    }
};
fn run(a: std.mem.Allocator, budget: *Engine.host_budget_allocator.SharedHostBudget, pool: *Engine.work_pool.WorkPool, input: []const u8) !Evidence {
    const elf = @import("../../prover/tests/block_v7_keccak_execution_test_support.zig").elf();
    const span = Capture.Window{ .skip_cycles = 9, .cycles = 4 };
    var captured = try Capture.capture(a, &elf, input, .{ .elf = Capture.sha(&elf), .input = Capture.sha(input) }, span, .{});
    defer captured.deinit();
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    const result = try Run.run(budget, temporary.dir, .{ .elf = &elf, .elf_sha256 = Capture.sha(&elf), .input = input, .cycles = span.cycles, .config = Base.Profile.diagnostic_q8_pow0.config(), .state = .{ .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = .{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = span } } }, .{ .segment_cycles = 2, .active_callers = true, .sparse_window_initialization = true }, pool, Consumer);
    return result.value;
}
test "distinct admitted window statements have identical geometry fixed rows and routed public schedule" {
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 16 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const first = try run(a, budget, &pool, &.{1});
    const second = try run(a, budget, &pool, &.{2});
    try std.testing.expect(!std.meta.eql(first.incoming, second.incoming));
    try std.testing.expect(!std.meta.eql(first.policy, second.policy));
    try std.testing.expect(!std.meta.eql(first.profile, second.profile));
    try std.testing.expectEqualDeep(first.fixed_rows, second.fixed_rows);
    try std.testing.expectEqualDeep(first.public_schedule, second.public_schedule);
    try std.testing.expectEqualDeep(first.namespace, second.namespace);
    var normalized = first.context;
    normalized.child_key_id = second.context.child_key_id;
    try std.testing.expectEqualDeep(normalized, second.context);
    try std.testing.expectEqualDeep(first.closed_fixed_rows, second.closed_fixed_rows);
    try std.testing.expectEqualDeep(first.closed_schedule, second.closed_schedule);
    try std.testing.expectEqualDeep(first.closed_graph, second.closed_graph);
    var normalized_closed = first.closed_context;
    normalized_closed.child_key_id = second.closed_context.child_key_id;
    try std.testing.expectEqualDeep(normalized_closed, second.closed_context);
    std.debug.print("V8_GEOMETRY_PARITY distinct_policies=true full_fixed_rows_equal=true schedule_equal=true namespace_equal=true v8_closed_fixed_rows_equal=true\n", .{});
}
