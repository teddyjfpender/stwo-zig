const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("block_v5_initial_source_test.zig");
const batch = @import("block_v5_memory_batch_receiver_v1.zig");
const artifact = @import("block_v5_memory_batch_artifact_v1.zig");
const v5 = @import("block_v5_source_seal_v1.zig");
const instance = @import("block_memory_shared_instance_proof_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
const shard = @import("block_memory_range_shard_v2.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const memory = @import("../air/block/memory_component.zig");
const trace_mod = @import("../air/block/memory_component_trace.zig");

const Loader = struct {
    memory_proofs: [2]instance.Proof,
    table_proof: table.Proof,
    memory_next: u32 = 0,
    table_taken: bool = false,
    fn takeMemory(context: *anyopaque, index: u32) anyerror!instance.Proof {
        const self: *Loader = @ptrCast(@alignCast(context));
        if (index != self.memory_next or index >= self.memory_proofs.len)
            return error.InvalidV5MemoryLoadOrder;
        self.memory_next += 1;
        return self.memory_proofs[index];
    }
    fn takeTable(context: *anyopaque, index: u32) anyerror!table.Proof {
        const self: *Loader = @ptrCast(@alignCast(context));
        if (index != 0 or self.table_taken or self.memory_next != self.memory_proofs.len)
            return error.InvalidV5TableLoadOrder;
        self.table_taken = true;
        return self.table_proof;
    }
    fn interface(self: *Loader) batch.ProofLoader {
        return .{ .context = self, .take_memory = takeMemory, .take_table = takeTable };
    }
};

test "block-v5 memory batch fresh two independently sized instances and one shard" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const input_record = fixture.recordWord(0x6000, fixture.input_value);
    const rw_record = fixture.recordWord(0x2000, 9);
    const touches = [_][9]u8{
        fixture.recordTouch(0, 1, 7),      fixture.recordTouch(1, 0x2000, 9),
        fixture.recordTouch(1, 0x2004, 0), fixture.recordTouch(1, 0x6000, fixture.input_value),
    };
    const touch_bytes = std.mem.sliceAsBytes(&touches);
    try fixture.writeFile(tmp.dir, "input.bin", &input_record);
    try fixture.writeFile(tmp.dir, "rw.bin", &rw_record);
    try fixture.writeFile(tmp.dir, "touches.bin", touch_bytes);
    var files = try fixture.OpenFiles.open(tmp.dir);
    defer files.deinit();
    const source_pins = try fixture.sourcePins(&input_record, &rw_record, touch_bytes);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const claims = [_]memory.Claim{
        try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 2, .first = fixture.initial[0], .last = fixture.initial[1] }, fixture.initial.len, 8, null),
        try memory.Claim.fromSummary(.{ .first_row = 2, .rows = 2, .first = fixture.initial[2], .last = fixture.initial[3] }, fixture.initial.len, 9, fixture.initial[1]),
    };
    var traces: [2]trace_mod.Trace = undefined;
    for (&traces, claims, 0..) |*trace, claim, index| {
        trace.* = try trace_mod.Trace.init(a, claim);
        for (fixture.initial[index * 2 ..][0..2]) |event| try trace.append(event);
        try trace.seal();
    }
    defer for (&traces) |*trace| trace.deinit();
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    var first: [2]instance.ForBackend(Cpu).FirstRound = undefined;
    for (&first, &traces, 0..) |*committed, *trace, index|
        committed.* = try instance.ForBackend(Cpu).commitFirstRound(a, trace, &counter, @intCast(index), config);
    defer for (&first) |*committed| committed.deinit(a);
    var range_plan = try shard.plan(a, &claims, fixture.initial.len);
    defer range_plan.deinit(a);
    try std.testing.expectEqual(@as(usize, 1), range_plan.shards.len);
    var table_first = try table.ForBackend(Cpu).commitFirstRound(a, &counter, range_plan.shards[0], config);
    defer table_first.deinit(a);
    const memory_roots = [_][2][32]u8{ first[0].roots, first[1].roots };
    const range_roots = [_][2][32]u8{table_first.roots};
    var v5_pins = try fixture.sealPins(source_pins, config);
    v5_pins.counts[@intFromEnum(v5.Family.memory) - 1] = 2;
    v5_pins.memory_plan_digest = try batch.memoryPlanDigest(&claims, &memory_roots, &range_roots, &range_plan);
    const entries = [_]v5.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(11), .roots = .{ @splat(12), @splat(13) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(14), .roots = .{ @splat(15), @splat(16) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(17), .roots = .{ @splat(18), @splat(19) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(26), .roots = .{ @splat(27), @splat(28) } },
        .{ .family = .memory, .index = 0, .instance_id = batch.memoryInstanceId(claims[0], 0), .roots = memory_roots[0] },
        .{ .family = .memory, .index = 1, .instance_id = batch.memoryInstanceId(claims[1], 1), .roots = memory_roots[1] },
        .{ .family = .memory_range, .index = 0, .instance_id = batch.rangeShardId(range_plan.digest, 0), .roots = range_roots[0] },
    };
    const sealed = try v5.seal(v5_pins, &entries);
    var proof_loader = Loader{
        .memory_proofs = .{
            try instance.ForBackend(Cpu).prove(a, &first[0], &traces[0], batchSeal(sealed, range_plan.digest), 0, first[0].roots),
            try instance.ForBackend(Cpu).prove(a, &first[1], &traces[1], batchSeal(sealed, range_plan.digest), 1, first[1].roots),
        },
        .table_proof = try table.ForBackend(Cpu).prove(a, &table_first, &counter, range_plan.shards[0], batchSeal(sealed, range_plan.digest), table_first.roots),
    };
    const pinned = batch.Pins{
        .source = source_pins,
        .seal = v5_pins,
        .expected_seal_digest = sealed.digest,
        .first_round = &entries,
        .claims = &claims,
        .memory_roots = &memory_roots,
        .range_roots = &range_roots,
        .expected_total_events = fixture.initial.len,
    };
    var changed_log = claims;
    changed_log[1].log_size = 8;
    var wrong = pinned;
    wrong.claims = &changed_log;
    try std.testing.expectError(error.UntrustedV5MemoryPlan, batch.verify(Cpu, a, wrong, &fixture.input, files.files, proof_loader.interface(), sealed));
    var changed_predecessor = claims;
    changed_predecessor[1].preceding = fixture.initial[0];
    wrong.claims = &changed_predecessor;
    try std.testing.expectError(error.InvalidMemoryInstanceCensus, batch.verify(Cpu, a, wrong, &fixture.input, files.files, proof_loader.interface(), sealed));
    var changed_roots = memory_roots;
    changed_roots[1][1][0] ^= 1;
    wrong = pinned;
    wrong.memory_roots = &changed_roots;
    try std.testing.expectError(error.UntrustedV5MemoryPlan, batch.verify(Cpu, a, wrong, &fixture.input, files.files, proof_loader.interface(), sealed));
    try std.testing.expectEqual(@as(u32, 0), proof_loader.memory_next);
    var wrong_seal = pinned;
    wrong_seal.expected_seal_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedV5MemoryBatchPins, batch.verify(Cpu, a, wrong_seal, &fixture.input, files.files, proof_loader.interface(), sealed));
    const accepted = try batch.verify(Cpu, a, pinned, &fixture.input, files.files, proof_loader.interface(), sealed);
    try std.testing.expectEqual(@as(u64, 4), accepted.event_count);
    try std.testing.expectEqual(@as(u32, 2), accepted.memory_instances);
    try std.testing.expectEqual(@as(u32, 1), accepted.range_shards);
    try std.testing.expectEqual(@as(u64, 4), accepted.first_touch_count);
    try std.testing.expectEqual(@as(u32, 2), proof_loader.memory_next);
    try std.testing.expect(proof_loader.table_taken);

    // A self-consistent new source-file pin and seal cannot omit a touch that
    // the same freshly proved sorted trace consumes from its initial bus.
    const omitted_bytes = std.mem.sliceAsBytes(touches[0..3]);
    try fixture.writeFile(tmp.dir, "touches.bin", omitted_bytes);
    var omitted_sources = source_pins;
    omitted_sources.first_touches = .{ .sha256 = @import("block_v5_initial_sources_v1.zig").sha256(omitted_bytes), .records = 3 };
    var omitted_v5 = v5_pins;
    omitted_v5.initial_source_plan_digest = try omitted_sources.digest();
    const omitted_seal = try v5.seal(omitted_v5, &entries);
    var replay_first: [2]instance.ForBackend(Cpu).FirstRound = undefined;
    for (&replay_first, &traces, 0..) |*committed, *trace, index|
        committed.* = try instance.ForBackend(Cpu).replayFirstRound(a, trace, @intCast(index), memory_roots[index], config);
    defer for (&replay_first) |*committed| committed.deinit(a);
    var replay_table = try table.ForBackend(Cpu).replayFirstRound(a, &counter, range_plan.shards[0], range_roots[0], config);
    defer replay_table.deinit(a);
    var omitted_loader = Loader{
        .memory_proofs = .{
            try instance.ForBackend(Cpu).prove(a, &replay_first[0], &traces[0], batchSeal(omitted_seal, range_plan.digest), 0, memory_roots[0]),
            try instance.ForBackend(Cpu).prove(a, &replay_first[1], &traces[1], batchSeal(omitted_seal, range_plan.digest), 1, memory_roots[1]),
        },
        .table_proof = try table.ForBackend(Cpu).prove(a, &replay_table, &counter, range_plan.shards[0], batchSeal(omitted_seal, range_plan.digest), range_roots[0]),
    };
    var omitted_pins = pinned;
    omitted_pins.source = omitted_sources;
    omitted_pins.seal = omitted_v5;
    omitted_pins.expected_seal_digest = omitted_seal.digest;
    try std.testing.expectError(error.UnclosedV5InitialRelation, batch.verify(Cpu, a, omitted_pins, &fixture.input, files.files, omitted_loader.interface(), omitted_seal));
    try std.testing.expectEqual(@as(u32, 2), omitted_loader.memory_next);
    try std.testing.expect(omitted_loader.table_taken);
}

fn batchSeal(sealed: v5.Sealed, plan_digest: [32]u8) @import("block_v5_initial_memory_receiver_v1.zig").MemorySeal {
    return .{ .source = sealed, .memory_instance_count = 2, .range_shard_digest = plan_digest };
}

const TraceReplay = struct {
    allocator: std.mem.Allocator,
    claims: *const [2]memory.Claim,
    fn load(context: *anyopaque, index: u32) anyerror!trace_mod.Trace {
        const self: *TraceReplay = @ptrCast(@alignCast(context));
        if (index >= 2) return error.InvalidV5TraceIndex;
        var trace = try trace_mod.Trace.init(self.allocator, self.claims[index]);
        errdefer trace.deinit();
        for (fixture.initial[index * 2 ..][0..2]) |event| try trace.append(event);
        try trace.seal();
        return trace;
    }
    fn interface(self: *TraceReplay) artifact.TraceSource {
        return .{ .context = self, .load = load };
    }
};
const Sink = struct {
    loaded: Loader = .{ .memory_proofs = undefined, .table_proof = undefined },
    memory_written: u32 = 0,
    table_written: bool = false,
    fn storeMemory(context: *anyopaque, index: u32, proof: *instance.Proof) anyerror!void {
        const self: *Sink = @ptrCast(@alignCast(context));
        if (index != self.memory_written or index >= self.loaded.memory_proofs.len)
            return error.InvalidV5ProducedMemoryOrder;
        self.loaded.memory_proofs[index] = proof.*;
        proof.* = undefined;
        self.memory_written += 1;
    }
    fn tableProof(context: *anyopaque, index: u32, proof: *table.Proof) anyerror!void {
        const self: *Sink = @ptrCast(@alignCast(context));
        if (index != 0 or self.table_written or self.memory_written != self.loaded.memory_proofs.len)
            return error.InvalidV5ProducedTableOrder;
        self.loaded.table_proof = proof.*;
        proof.* = undefined;
        self.table_written = true;
    }
    fn interface(self: *Sink) artifact.ProofSink {
        return .{ .context = self, .memory = storeMemory, .table = tableProof };
    }
};

test "block-v5 memory artifact roots-only replay and fresh batch receiver" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const input_record = fixture.recordWord(0x6000, fixture.input_value);
    const rw_record = fixture.recordWord(0x2000, 9);
    const touches = [_][9]u8{
        fixture.recordTouch(0, 1, 7),      fixture.recordTouch(1, 0x2000, 9),
        fixture.recordTouch(1, 0x2004, 0), fixture.recordTouch(1, 0x6000, fixture.input_value),
    };
    const touch_bytes = std.mem.sliceAsBytes(&touches);
    try fixture.writeFile(tmp.dir, "input.bin", &input_record);
    try fixture.writeFile(tmp.dir, "rw.bin", &rw_record);
    try fixture.writeFile(tmp.dir, "touches.bin", touch_bytes);
    var files = try fixture.OpenFiles.open(tmp.dir);
    defer files.deinit();
    const source_pins = try fixture.sourcePins(&input_record, &rw_record, touch_bytes);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const claims = [_]memory.Claim{
        try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 2, .first = fixture.initial[0], .last = fixture.initial[1] }, fixture.initial.len, 8, null),
        try memory.Claim.fromSummary(.{ .first_row = 2, .rows = 2, .first = fixture.initial[2], .last = fixture.initial[3] }, fixture.initial.len, 9, fixture.initial[1]),
    };
    var source = TraceReplay{ .allocator = a, .claims = &claims };
    var collected = try artifact.ForBackend(Cpu).collect(a, source.interface(), &claims, fixture.initial.len, config);
    defer collected.deinit(a);
    var v5_pins = try fixture.sealPins(source_pins, config);
    v5_pins.counts[@intFromEnum(v5.Family.memory) - 1] = 2;
    v5_pins.memory_plan_digest = collected.plan_digest;
    const entries = [_]v5.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(11), .roots = .{ @splat(12), @splat(13) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(14), .roots = .{ @splat(15), @splat(16) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(17), .roots = .{ @splat(18), @splat(19) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(26), .roots = .{ @splat(27), @splat(28) } },
        collected.memoryEntry(0),
        collected.memoryEntry(1),
        collected.tableEntry(0),
    };
    const sealed = try v5.seal(v5_pins, &entries);
    var sink = Sink{};
    try collected.prove(a, source.interface(), sink.interface(), v5_pins, &entries, sealed.digest, sealed);
    try std.testing.expectEqual(@as(u32, 2), sink.memory_written);
    try std.testing.expect(sink.table_written);
    const result = try batch.verify(Cpu, a, .{
        .source = source_pins,
        .seal = v5_pins,
        .expected_seal_digest = sealed.digest,
        .first_round = &entries,
        .claims = &claims,
        .memory_roots = collected.memory_roots,
        .range_roots = collected.table_roots,
        .expected_total_events = fixture.initial.len,
    }, &fixture.input, files.files, sink.loaded.interface(), sealed);
    try std.testing.expectEqual(@as(u64, 4), result.event_count);
    try std.testing.expectEqual(@as(u32, 2), result.memory_instances);
}

test "block-v5 memory plan binds two exact range shards and variable AIR size" {
    const a = std.testing.allocator;
    const event = fixture.initial[0];
    const rows_per_instance: u32 = 1 << 20;
    const total_rows: u64 = 59 * @as(u64, rows_per_instance);
    var claims: [59]memory.Claim = undefined;
    var roots: [59][2][32]u8 = undefined;
    for (&claims, &roots, 0..) |*claim, *pair, index| {
        claim.* = try memory.Claim.fromSummary(.{ .first_row = index * @as(u64, rows_per_instance), .rows = rows_per_instance, .first = event, .last = event }, total_rows, 20, if (index == 0) null else event);
        pair.* = .{ @splat(@intCast(index + 1)), @splat(@intCast(index + 2)) };
    }
    var plan = try shard.plan(a, &claims, total_rows);
    defer plan.deinit(a);
    try std.testing.expectEqual(@as(usize, 2), plan.shards.len);
    const table_roots = [_][2][32]u8{ .{ @splat(71), @splat(72) }, .{ @splat(73), @splat(74) } };
    const digest = try batch.memoryPlanDigest(&claims, &roots, &table_roots, &plan);
    claims[58].log_size = 21;
    const changed = try batch.memoryPlanDigest(&claims, &roots, &table_roots, &plan);
    try std.testing.expect(!std.meta.eql(digest, changed));
    claims[58].log_size = 20;
    roots[58][1][0] ^= 1;
    const changed_root = try batch.memoryPlanDigest(&claims, &roots, &table_roots, &plan);
    try std.testing.expect(!std.meta.eql(digest, changed_root));
}
