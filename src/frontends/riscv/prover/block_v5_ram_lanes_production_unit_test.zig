//! Source replay, authority and real production body generation only. No
//! prover, verifier, guest/segment, CLI or benchmark is executed by these tests.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Planner = @import("block_v5_ram_lanes_replay_plan_v1.zig");
const Replay = @import("block_v5_ram_lanes_replay_v1.zig").ForBackend(Cpu);
const Sorted = @import("block_v5_sorted_memory_v1.zig");
const Spool = @import("../air/block/memory_spool.zig");
const Transitions = @import("../air/block/memory_transition.zig");
const Store = @import("block_v5_cpu_bundle_store_v1.zig");
const Proof = @import("block_v5_ram_lanes_proof_v1.zig");
const Fixture = struct {
    spool: *Spool.Spool,
    fn initial(_: *anyopaque, space: u1, address: u32) anyerror!u32 {
        if (space != 1 or address != 0x2000) return error.InvalidInitialWord;
        return 3;
    }
    fn open(raw: *anyopaque) anyerror!Transitions.Reader {
        const self: *@This() = @ptrCast(@alignCast(raw));
        return .{ .sorted = try self.spool.reopenSorted(), .initial = .{ .context = self, .load = initial } };
    }
};
test "block-v5 RAM production replay derives real odd lane traces with exact sequential ownership" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spool = try Spool.Spool.init(a, tmp.dir, 4);
    defer spool.deinit();
    const Clock = @import("../access_clock.zig");
    // Each instruction's first real access occupies subclock1 in a four-wide
    // bucket. Consecutive integers incorrectly include reserved clocks4/8.
    try std.testing.expectError(error.InvalidBlockAccessClock, spool.append(.{ .space = 1, .address = 0x2000, .clock = Clock.STRIDE, .value = 4 }));
    try std.testing.expectEqual(@as(u64, 0), spool.event_count);
    for (0..9) |i| try spool.append(.{ .space = 1, .address = 0x2000, .clock = Clock.encode(@intCast(i + 1), .first), .value = @intCast(i + 4) });
    var sorted = try spool.finish();
    sorted.deinit();
    var fixture = Fixture{ .spool = &spool };
    const source = @import("block_v5_ram_lanes_replay_v1.zig").SortedSource{ .context = &fixture, .open = Fixture.open };
    var reader = try source.open(source.context);
    defer reader.deinit();
    const limits = Planner.Limits{ .minimum_row_log = 1, .maximum_row_log = 2, .max_instances = 2 };
    var plan = try Planner.collect(a, &reader, 9, limits);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 2), plan.claims.len);
    try std.testing.expectEqual(@as(u32, 8), plan.claims[0].events);
    try std.testing.expectEqual(@as(u32, 1), plan.claims[1].events);
    try std.testing.expectEqual(@as(u32, 1), plan.claims[1].row_log);
    try Planner.require(a, plan.claims, 9, limits);
    var lease = try Replay.openClaims(a, source, plan.claims, .{ .max_trace_bytes = 4096 });
    defer lease.deinit();
    try std.testing.expectError(error.IncompleteV5RamReplay, lease.requireFinished());
    var first = try lease.source().load(lease.source().context, 0);
    defer first.deinit();
    try std.testing.expectEqualDeep(plan.claims[0], first.claim);
    try std.testing.expectEqual(@as(u32, 4), first.claim.rowCapacity());
    try std.testing.expectEqual(@as(u64, 1), first.claim.first.clock);
    try std.testing.expectEqual(@as(u64, 29), first.claim.last.clock);
    var last = try lease.source().load(lease.source().context, 1);
    defer last.deinit();
    try std.testing.expectEqual(@as(u32, 1), last.written);
    // The real padded lane1 remains inactive, not a virtual extra event.
    try std.testing.expect(last.fixedAt(0)[0].active.eql(core.fields.qm31.QM31.one()));
    try std.testing.expect(last.fixedAt(0)[1].active.isZero());
    try lease.requireFinished();
    try std.testing.expectError(error.InvalidV5RamReplayOrder, lease.source().load(lease.source().context, 2));
    var changed = try a.dupe(@import("block_v5_ram_lanes_protocol_v1.zig").Claim, plan.claims);
    defer a.free(changed);
    // A different admitted public first value fails before a trace escapes;
    // the partially consumed source stays poisoned and cannot be reused.
    changed[0].first.before += 1;
    var rejected = try Replay.openClaims(a, source, changed, .{ .max_trace_bytes = 4096 });
    defer rejected.deinit();
    try std.testing.expectError(error.MemoryFirstBoundaryMismatch, rejected.source().load(rejected.source().context, 0));
    try std.testing.expectError(error.InvalidV5RamReplayOrder, rejected.source().load(rejected.source().context, 0));
    try std.testing.expectError(error.IncompleteV5RamReplay, rejected.requireFinished());
    @memcpy(changed, plan.claims);
    changed[1].row_log = 2;
    try std.testing.expectError(error.InvalidV5RamReplayGeometry, Planner.require(a, changed, 9, limits));
    try std.testing.expectError(error.V5RamLanesResourceLimit, Replay.openClaims(a, source, plan.claims, .{ .max_trace_bytes = 1 }));
    var small_fixed = @import("block_v5_ram_lanes_replay_v1.zig").Resources{};
    small_fixed.stage.proof.max_fixed_bytes = 1;
    try std.testing.expectError(error.V5RamLanesResourceLimit, Replay.openClaims(a, source, plan.claims, small_fixed));
    var small_interaction = @import("block_v5_ram_lanes_replay_v1.zig").Resources{};
    small_interaction.stage.proof.max_interaction_bytes = 1;
    try std.testing.expectError(error.V5RamLanesResourceLimit, Replay.openClaims(a, source, plan.claims, small_interaction));
}
fn putLane(store: *Store.Store, index: u32, proof: *Proof.Proof) !void {
    return store.put(.ram_lanes, index, proof);
}
fn takeLane(store: *Store.Store, index: u32) !Proof.Proof {
    return store.take(.ram_lanes, index);
}
test "block-v5 RAM production planner driver fresh consumers codegen without proving" {
    const Global = @import("block_v5_global_receiver_v1.zig").ForBackend(Cpu);
    const Producer = @import("block_v5_block_producer_v1.zig").ForLightweightBackend(Cpu);
    inline for (.{ &putLane, &takeLane, &Global.verifyGlobals, &Producer.proveExecutionsWithMemoryPlanHooks, &@import("block_v5_cpu_driver_v1.zig").run, &@import("block_v5_cpu_assembly_v1.zig").assemble, &@import("block_v5_cpu_bundle_policy_v1.zig").collect, &@import("block_v5_cpu_global_plans_v1.zig").ForBackend(Cpu).collect }) |function| std.mem.doNotOptimizeAway(function);
    var store: Store.Store = undefined;
    _ = store.ramLanesSink();
    _ = store.packedMemoryLoader();
    try std.testing.expectEqual(@as(u32, 16), @intFromEnum(Store.Family.ram_lanes));
}
test {
    _ = @import("block_v5_ram_lanes_replay_plan_v1.zig");
}

fn independentPin() Proof.Pin {
    const claim = @import("block_v5_ram_lanes_protocol_v1.zig").Claim{
        .first_event = 0,
        .total_events = 5,
        .events = 5,
        .row_log = 2,
        .first = .{ .space = 1, .address = 0x2000, .clock = 1, .before = 3, .after = 4 },
        .last = .{ .space = 1, .address = 0x2000, .clock = 5, .before = 7, .after = 8 },
        .preceding = null,
    };
    return .{ .claim = claim, .index = 0, .roots = .{ @splat(2), @splat(3) }, .request_count = @import("../air/block/word_memory_v5.zig").rangeCountBounds(claim.legacy()).minimum, .counter_digest = @splat(4), .config = @import("../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config() };
}
test "block-v5 RAM production tagged authority rejects mixed custody geometry and absence" {
    const pin = independentPin();
    try pin.validate();
    var seal: @import("block_v5_source_seal_v1.zig").Pins = undefined;
    seal.register_custody_mode = 1;
    seal.config = pin.config;
    seal.counts = @splat(0);
    seal.counts[@intFromEnum(@import("block_v5_source_seal_v1.zig").Family.memory) - 1] = 1;
    const authority = Sorted.Pins{ .lanes = .{ .seal = seal, .expected_seal_digest = @splat(5), .first_round = &.{}, .pins = &.{pin}, .range_roots = &.{}, .expected_total_events = 5, .source = undefined } };
    try authority.requireCanonical(1);
    try std.testing.expectError(error.MixedV5SortedMemoryMode, authority.requireCanonical(0));
    var changed = authority;
    changed.lanes.seal.register_custody_mode = 0;
    try std.testing.expectError(error.NoncanonicalV5RamLanesProtocol, changed.requireCanonical(0));
    changed = authority;
    changed.lanes.expected_total_events = 0;
    try std.testing.expectError(error.InvalidV5SortedMemoryCorrespondence, changed.requireStructure());
    changed = authority;
    changed.lanes.pins = &.{};
    try std.testing.expectError(error.InvalidV5SortedMemoryCorrespondence, changed.requireStructure());
    changed.lanes.expected_total_events = 0;
    changed.lanes.seal.counts[@intFromEnum(@import("block_v5_source_seal_v1.zig").Family.memory) - 1] = 0;
    // Host absence metadata is admissible only with an exact zero census.
    // This is no proof receipt; fresh endpoint/source verification remains.
    try changed.requireCanonical(1);
    changed.lanes.range_roots = &.{.{ @splat(6), @splat(7) }};
    try std.testing.expectError(error.InvalidV5SortedMemoryCorrespondence, changed.requireStructure());
    var wrong_index = pin;
    wrong_index.index = 1;
    changed = authority;
    changed.lanes.pins = &.{wrong_index};
    try std.testing.expectError(error.InvalidV5SortedMemoryCorrespondence, changed.requireStructure());
    var wrong_config = pin;
    wrong_config.config.fri_config.n_queries = 9;
    changed.lanes.pins = &.{wrong_config};
    try std.testing.expectError(error.InvalidV5SortedMemoryCorrespondence, changed.requireStructure());
    var register_pin = pin;
    register_pin.claim.first.space = 0;
    register_pin.claim.last.space = 0;
    try std.testing.expectError(error.InvalidV5RamLanesSpace, register_pin.validate());
    var capacity = pin;
    capacity.claim.row_log = 1;
    try std.testing.expectError(error.InvalidV5RamLanesGeometry, capacity.validate());
    const legacy = Sorted.Pins.fromWord(.{ .seal = seal, .expected_seal_digest = @splat(5), .first_round = &.{}, .claims = &.{pin.claim.legacy()}, .request_counts = &.{pin.request_count}, .memory_roots = &.{pin.roots}, .range_roots = &.{}, .expected_total_events = 5, .source = undefined });
    try std.testing.expectError(error.NoncanonicalV5WordMemoryProtocol, legacy.requireCanonical(1));
    var word = legacy;
    word.word.seal.register_custody_mode = 0;
    try word.requireCanonical(0);
}
test "block-v5 RAM production artifact rejects legacy and security metadata before allocation" {
    const Artifact = @import("block_v5_ram_lanes_artifact_v1.zig");
    const pin = independentPin();
    const expected = Artifact.Expected{ .pin = pin, .expected_seal_digest = @splat(5) };
    const limits = Artifact.Limits{ .artifact_bytes = 4096, .proof_bytes = 2048, .max_row_log = 2, .max_queries = 8 };
    var storage: [0]u8 = .{};
    var empty = std.heap.FixedBufferAllocator.init(&storage);
    try std.testing.expectError(error.UntrustedV5RamLanesArtifact, Artifact.decode(empty.allocator(), "B5STOR01", expected, limits));
    var too_low = limits;
    too_low.max_row_log = 1;
    try std.testing.expectError(error.V5RamLanesArtifactResourceLimit, Artifact.decode(empty.allocator(), "B5RAM2A1", expected, too_low));
    var wrong = expected;
    wrong.expected_seal_digest = @splat(0);
    try std.testing.expectError(error.UntrustedV5RamLanesArtifact, Artifact.decode(empty.allocator(), "B5RAM2A1", wrong, limits));
    wrong = expected;
    wrong.pin.config.fri_config.n_queries = 9;
    try std.testing.expectError(error.V5RamLanesArtifactResourceLimit, Artifact.decode(empty.allocator(), "B5RAM2A1", wrong, limits));
}
