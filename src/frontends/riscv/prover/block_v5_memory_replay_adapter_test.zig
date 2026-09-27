const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("block_v5_initial_source_test.zig");
const replay_mod = @import("block_memory_replay.zig");
const adapter = @import("block_v5_memory_replay_adapter_v1.zig");
const artifact = @import("block_v5_memory_batch_artifact_v1.zig");
const batch = @import("block_v5_memory_batch_receiver_v1.zig");
const v5 = @import("block_v5_source_seal_v1.zig");
const instance = @import("block_memory_shared_instance_proof_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
const memory_state = @import("../runner/memory_state.zig");
const tracker = @import("../runner/state_chain.zig");

const Store = struct {
    memory_proof: ?instance.Proof = null,
    table_proof: ?table.Proof = null,
    memory_loaded: bool = false,
    table_loaded: bool = false,
    fn writeMemory(context: *anyopaque, index: u32, proof: *instance.Proof) anyerror!void {
        const self: *Store = @ptrCast(@alignCast(context));
        if (index != 0 or self.memory_proof != null) return error.InvalidV5StoredMemory;
        self.memory_proof = proof.*;
        proof.* = undefined;
    }
    fn writeTable(context: *anyopaque, index: u32, proof: *table.Proof) anyerror!void {
        const self: *Store = @ptrCast(@alignCast(context));
        if (index != 0 or self.table_proof != null) return error.InvalidV5StoredTable;
        self.table_proof = proof.*;
        proof.* = undefined;
    }
    fn takeMemory(context: *anyopaque, index: u32) anyerror!instance.Proof {
        const self: *Store = @ptrCast(@alignCast(context));
        if (index != 0 or self.memory_loaded) return error.InvalidV5LoadedMemory;
        self.memory_loaded = true;
        const result = self.memory_proof orelse return error.MissingV5MemoryProof;
        self.memory_proof = null;
        return result;
    }
    fn takeTable(context: *anyopaque, index: u32) anyerror!table.Proof {
        const self: *Store = @ptrCast(@alignCast(context));
        if (index != 0 or self.table_loaded or !self.memory_loaded) return error.InvalidV5LoadedTable;
        self.table_loaded = true;
        const result = self.table_proof orelse return error.MissingV5TableProof;
        self.table_proof = null;
        return result;
    }
    fn sink(self: *Store) artifact.ProofSink {
        return .{ .context = self, .memory = writeMemory, .table = writeTable };
    }
    fn loader(self: *Store) batch.ProofLoader {
        return .{ .context = self, .take_memory = takeMemory, .take_table = takeTable };
    }
};

test "block-v5 real sorted Replay feeds opt-in producer and fresh receiver" {
    try exercise(false);
}
test "block-v5 compact real Replay producer and fresh sorted receiver" {
    try exercise(true);
}
fn exercise(comptime compact: bool) !void {
    const Producer = if (compact) @import("block_v5_memory_compact_replay_v1.zig").ForBackend(Cpu) else adapter.ForBackend(Cpu);
    const verify = if (compact) batch.verifyCompact else batch.verify;
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
    var registers: [32]u32 = @splat(0);
    registers[1] = 7;
    var words = [_]memory_state.WordState{
        .{ .addr = 0x2000, .initial_word = 9, .final_word = 9, .final_clock = 0 },
        .{ .addr = 0x6000, .initial_word = fixture.input_value, .final_word = fixture.input_value, .final_clock = 0, .role = .{ .is_public_input = true } },
    };
    const snapshot = memory_state.Snapshot{ .layout = fixture.layout, .segment_role = .single(), .words = &words };
    var replay = try replay_mod.Replay.initFromSnapshot(a, tmp.dir, registers, &snapshot, 2);
    defer replay.deinit();
    try std.testing.expectEqualDeep(source_pins.initial_rw_root, (try replay.initialRwRoot()).bytes);
    const accesses = [_]tracker.Access{
        .{ .addr_space = 0, .addr = 1, .clk = 1, .clk_prev = 0, .value = 8 },
        .{ .addr_space = 1, .addr = 0x2000, .clk = 2, .clk_prev = 0, .value = 10 },
        .{ .addr_space = 1, .addr = 0x2004, .clk = 3, .clk_prev = 0, .value = 1 },
        .{ .addr_space = 1, .addr = 0x6000, .clk = 5, .clk_prev = 0, .value = fixture.input_value + 1 },
    };
    try replay.append(.{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 }, &accesses);
    var finished = try replay.finish();
    finished.deinit();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const sorted = adapter.fromReplay(&replay);
    var collected = try Producer.collect(a, sorted, accesses.len, 8, 8, config);
    defer collected.deinit();
    try std.testing.expectEqual(@as(usize, 1), collected.first.claims.len);
    try std.testing.expectEqual(@as(u64, 4), collected.first.total_events);
    var seal_pins = try fixture.sealPins(source_pins, config);
    seal_pins.memory_plan_digest = collected.first.plan_digest;
    const entries = [_]v5.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(11), .roots = .{ @splat(12), @splat(13) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(14), .roots = .{ @splat(15), @splat(16) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(17), .roots = .{ @splat(18), @splat(19) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(26), .roots = .{ @splat(27), @splat(28) } },
        collected.first.memoryEntry(0),
        collected.first.tableEntry(0),
    };
    const sealed = try v5.seal(seal_pins, &entries);
    var store = Store{};
    try collected.prove(sorted, store.sink(), seal_pins, &entries, sealed.digest, sealed);
    const accepted = try verify(Cpu, a, .{
        .source = source_pins,
        .seal = seal_pins,
        .expected_seal_digest = sealed.digest,
        .first_round = &entries,
        .claims = collected.first.claims,
        .memory_roots = collected.first.memory_roots,
        .range_roots = collected.first.table_roots,
        .expected_total_events = accesses.len,
    }, &fixture.input, files.files, store.loader(), sealed);
    try std.testing.expectEqual(@as(u64, 4), accepted.event_count);
    try std.testing.expectEqual(@as(u64, 4), accepted.first_touch_count);
    try std.testing.expect(store.memory_loaded and store.table_loaded);
}
