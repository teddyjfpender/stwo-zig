const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const postcard = @import("interop_postcard");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const spool_mod = @import("../../air/block/memory_spool.zig");
const transition = @import("../../air/block/memory_transition.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const producer = @import("../block_memory_batch_produce_v2.zig");
const memory_proof = @import("../block_memory_shared_instance_proof_v2.zig");
const table_proof = @import("../block_memory_shared_table_proof_v2.zig");
const batch = @import("../block_memory_batch_verify_v2.zig");
const seal_mod = @import("../block_memory_source_seal_v2.zig");
const fallback = @import("../block_memory_public_rw_fallback_v2.zig");
const scoped = @import("../block_memory_initial_range_receiver_v2.zig");
const source_roster = @import("../block_memory_source_roster_v2.zig");

const Source = struct {
    spool: *spool_mod.Spool,
    fn open(context: *anyopaque) anyerror!transition.Reader {
        const self: *Source = @ptrCast(@alignCast(context));
        return .{ .sorted = try self.spool.reopenSorted(), .initial = .{ .context = self, .load = load } };
    }
    fn load(_: *anyopaque, _: u1, _: u32) anyerror!u32 {
        return 0;
    }
    fn source(self: *Source) producer.SortedSource {
        return .{ .context = self, .open = open };
    }
};

const Capture = struct {
    a: std.mem.Allocator,
    memory: [2]batch.SerializedMemoryProof = undefined,
    tables: [1]batch.SerializedTableProof = undefined,
    memory_bytes: [2]?[]u8 = .{ null, null },
    table_bytes: [1]?[]u8 = .{null},
    next_memory: usize = 0,
    next_table: usize = 0,
    fn deinit(self: *Capture) void {
        for (self.memory_bytes) |bytes| if (bytes) |owned| self.a.free(owned);
        for (self.table_bytes) |bytes| if (bytes) |owned| self.a.free(owned);
    }
    fn sink(self: *Capture) producer.ProofSink {
        return .{ .context = self, .write_memory = onMemory, .write_table = onTable };
    }
    fn onMemory(context: *anyopaque, index: u32, _: @import("../../air/block/memory_component.zig").Claim, proof: *const memory_proof.Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (index != self.next_memory or index >= self.memory.len) return error.InvalidCaptureOrder;
        var out = std.Io.Writer.Allocating.init(self.a);
        defer out.deinit();
        try postcard.serializeProof(suite.Hasher, &out.writer, proof.stark);
        const owned = try self.a.dupe(u8, out.written());
        self.memory_bytes[index] = owned;
        self.memory[index] = .{ .stark_bytes = owned, .interaction_claim = proof.relation, .range_claims = proof.range_claims };
        self.next_memory += 1;
    }
    fn onTable(context: *anyopaque, _: @import("../block_memory_range_shard_v2.zig").Shard, proof: *const table_proof.Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (self.next_memory != self.memory.len or self.next_table >= self.tables.len) return error.InvalidCaptureOrder;
        var out = std.Io.Writer.Allocating.init(self.a);
        defer out.deinit();
        try postcard.serializeProof(suite.Hasher, &out.writer, proof.stark);
        const owned = try self.a.dupe(u8, out.written());
        self.table_bytes[self.next_table] = owned;
        self.tables[self.next_table] = .{ .stark_bytes = owned, .claim = proof.claim };
        self.next_table += 1;
    }
    fn wire(self: *const Capture) batch.SerializedBatch {
        return .{ .memory = &self.memory, .range_tables = &self.tables, .execution = &.{}, .initial_sources = &.{} };
    }
};

test "scoped receiver freshly verifies serialized memory and table before initial closure" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spool = try spool_mod.Spool.init(a, tmp.dir, 2);
    defer spool.deinit();
    for (0..3) |i| try spool.append(.{ .space = 1, .address = 4096, .clock = @as(u64, @intCast(i)) * 4 + 1, .value = @intCast(i + 1) });
    var sorted = try spool.finish();
    sorted.deinit();
    var source = Source{ .spool = &spool };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var first = try producer.collectFirstPass(Cpu, a, source.source(), 3, 2, 8, config);
    defer first.deinit();

    var image = try tmp.dir.createFile("public-image.bin", .{ .truncate = true, .read = true });
    defer image.close();
    var touch = try tmp.dir.createFile("public-touch.bin", .{ .truncate = true, .read = true });
    defer touch.close();
    var record: [10]u8 = @splat(0);
    record[0] = 1;
    std.mem.writeInt(u32, record[1..5], 4096, .little);
    record[9] = @intFromEnum(@import("../block_memory_replay.zig").InitialSource.rw_root);
    try touch.writeAll(&record);
    const hasher = tree.TreeHasher.init(.memory);
    const root = try hasher.root(&.{});
    const pin = fallback.Pin{ .initial_rw_root = root, .layout = .{
        .program_base = 0,
        .program_end = 4096,
        .data_base = 4096,
        .data_end = 8192,
        .stack_bottom = 8192,
        .stack_top = 12288,
        .io_base = 12288,
        .io_end = 16384,
        .input_base = 6144,
        .input_end = 7168,
        .output_len_addr = 12288,
        .output_data_addr = 12292,
        .output_base = 12288,
        .output_end = 16384,
    }, .image_count = 0, .first_touch_count = 1 };
    const files = fallback.Files{ .nonzero_image = image, .first_touches = touch };
    const rw_digest = try fallback.digestRoster(pin, files);
    const source_entries = [_]source_roster.Entry{
        .{ .family = .public_rw_fallback, .index = 0, .digest = rw_digest },
        .{ .family = .program, .index = 0, .digest = @splat(81) },
        .{ .family = .hash, .index = 0, .digest = @splat(82) },
    };
    const aggregate_digest = try source_roster.digest(&source_entries);
    const memory_pins = [_]batch.MemoryPin{
        .{ .claim = first.claims[0], .roots = first.memory_roots[0] },
        .{ .claim = first.claims[1], .roots = first.memory_roots[1] },
    };
    const execution_pins = [_]batch.Roots{.{ @splat(31), @splat(32) }};
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(35), .instance_count = 1 };
    var statement = batch.PinnedStatement{
        .seal = try seal_mod.SourceSeal.init(base, 0, aggregate_digest),
        .expected_events = 3,
        .memory_instances = &memory_pins,
        .range_table_roots = first.table_roots,
        .execution_roots = &execution_pins,
        .provider_roots = &.{},
    };
    statement.seal = try seal_mod.SourceSeal.initBound(base, 0, aggregate_digest, 1, 2, first.plan.digest, try statement.firstRoundDigest(a));
    var capture = Capture{ .a = a };
    defer capture.deinit();
    try producer.proveSecondPass(Cpu, a, source.source(), &first, statement, config, capture.sink());
    try std.testing.expectEqual(@as(usize, 2), capture.next_memory);
    try std.testing.expectEqual(@as(usize, 1), capture.next_table);
    const sources = scoped.AggregatedSourcePins{ .entries = &source_entries, .expected_program = &.{@splat(81)}, .expected_hash = &.{@splat(82)} };
    const result = try scoped.verifyMemoryInitialRangeAggregated(Cpu, a, statement, capture.wire(), config, .{ .rw = pin, .registers = @splat(0) }, files, sources);
    try std.testing.expectEqual(@as(u64, 1), result.first_touches);
    try std.testing.expectEqual(@as(u64, 1), result.rw_first_touches);
    var changed = capture.wire();
    changed.memory = changed.memory[0..1];
    try std.testing.expectError(error.InvalidBlockProofCensus, scoped.verifyMemoryInitialRangeAggregated(Cpu, a, statement, changed, config, .{ .rw = pin, .registers = @splat(0) }, files, sources));
}
