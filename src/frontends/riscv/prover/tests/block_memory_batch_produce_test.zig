const std = @import("std");
const core = @import("stwo_core");
const spool_mod = @import("../../air/block/memory_spool.zig");
const transition = @import("../../air/block/memory_transition.zig");
const producer = @import("../block_memory_batch_produce_v2.zig");
const artifact = @import("../block_memory_batch_artifact_v2.zig");
const batch = @import("../block_memory_batch_verify_v2.zig");
const seal_mod = @import("../block_memory_source_seal_v2.zig");

const Synthetic = struct {
    spool: *spool_mod.Spool,
    fn open(context: *anyopaque) anyerror!transition.Reader {
        const self: *Synthetic = @ptrCast(@alignCast(context));
        return .{ .sorted = try self.spool.reopenSorted(), .initial = .{ .context = self, .load = load } };
    }
    fn load(_: *anyopaque, _: u1, _: u32) anyerror!u32 {
        return 0;
    }
    fn source(self: *Synthetic) producer.SortedSource {
        return .{ .context = self, .open = open };
    }
};

test "two-pass 2+1 sorted-memory batch stages, verifies, and atomically publishes" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spool = try spool_mod.Spool.init(a, tmp.dir, 2);
    defer spool.deinit();
    for (0..3) |i| try spool.append(.{
        .space = 1,
        .address = 4096,
        .clock = @as(u64, @intCast(i)) * 4 + 1,
        .value = @intCast(i + 1),
    });
    var initially_sorted = try spool.finish();
    initially_sorted.deinit();
    var source = Synthetic{ .spool = &spool };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var first = try producer.collectFirstPass(Cpu, a, source.source(), 3, 2, 8, config);
    defer first.deinit();
    try std.testing.expectEqual(@as(usize, 2), first.claims.len);
    try std.testing.expectEqual(@as(u32, 2), first.claims[0].rows);
    try std.testing.expectEqual(@as(u32, 1), first.claims[1].rows);
    try std.testing.expectEqual(@as(usize, 1), first.plan.shards.len);
    const memory_pins = [_]batch.MemoryPin{
        .{ .claim = first.claims[0], .roots = first.memory_roots[0] },
        .{ .claim = first.claims[1], .roots = first.memory_roots[1] },
    };
    const execution_pins = [_]batch.Roots{.{ @splat(31), @splat(32) }};
    const source_pins = [_]seal_mod.FirstRoundEntry{.{ .family = .initial_rw, .index = 0, .roots = .{ @splat(33), @splat(34) } }};
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(35), .instance_count = 1 };
    var statement = batch.PinnedStatement{
        .seal = try seal_mod.SourceSeal.init(base, 0, @splat(36)),
        .expected_events = 3,
        .memory_instances = &memory_pins,
        .range_table_roots = first.table_roots,
        .execution_roots = &execution_pins,
        .provider_roots = &source_pins,
    };
    statement.seal = try seal_mod.SourceSeal.initBound(base, 0, @splat(36), 1, 2, first.plan.digest, try statement.firstRoundDigest(a));
    var staged = try artifact.StagedWriter.init(a, tmp.dir, 2, 1);
    defer staged.deinit();
    try std.testing.expectError(error.FileNotFound, artifact.verifyPublished(Cpu, a, tmp.dir, statement, config));
    try std.testing.expectError(error.IncompleteStagedBlockMemoryRange, staged.verifyAndPublish(Cpu, statement, config));
    try producer.proveSecondPass(Cpu, a, source.source(), &first, statement, config, staged.proofSink());
    try std.testing.expectError(error.FileNotFound, artifact.verifyPublished(Cpu, a, tmp.dir, statement, config));
    try staged.verifyAndPublish(Cpu, statement, config);
    try artifact.verifyPublished(Cpu, a, tmp.dir, statement, config);
    try std.testing.expectError(error.AlreadyPublishedBlockMemoryRange, artifact.StagedWriter.init(a, tmp.dir, 2, 1));

    // The already-published scoped marker cannot authorize a complete block.
    var wrong = statement;
    wrong.seal.first_round_roster_digest[0] ^= 1;
    try std.testing.expectError(error.UnsealedFirstRoundRoster, artifact.verifyPublished(Cpu, a, tmp.dir, wrong, config));
    var table_file = try tmp.dir.openFile("table-0.v2", .{ .mode = .read_write });
    defer table_file.close();
    const end = try table_file.getEndPos();
    var last: [1]u8 = undefined;
    if (try table_file.preadAll(&last, end - 1) != 1) return error.TruncatedStagedTableProof;
    last[0] ^= 1;
    try table_file.pwriteAll(&last, end - 1);
    try std.testing.expectError(error.PublishedBlockProofDigestMismatch, artifact.verifyPublished(Cpu, a, tmp.dir, statement, config));
}

test "two-pass producer rejects changed sorted bytes and first roots" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spool = try spool_mod.Spool.init(a, tmp.dir, 2);
    defer spool.deinit();
    for (0..3) |i| try spool.append(.{ .space = 1, .address = 4096, .clock = @as(u64, @intCast(i)) * 4 + 1, .value = @intCast(i + 1) });
    var sorted = try spool.finish();
    sorted.deinit();
    var source = Synthetic{ .spool = &spool };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var first = try producer.collectFirstPass(Cpu, a, source.source(), 3, 2, 8, config);
    defer first.deinit();
    const pins = [_]batch.MemoryPin{
        .{ .claim = first.claims[0], .roots = first.memory_roots[0] },
        .{ .claim = first.claims[1], .roots = first.memory_roots[1] },
    };
    const execution = [_]batch.Roots{.{ @splat(31), @splat(32) }};
    const providers = [_]seal_mod.FirstRoundEntry{.{ .family = .initial_rw, .index = 0, .roots = .{ @splat(33), @splat(34) } }};
    const base = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(35), .instance_count = 1 };
    var statement = batch.PinnedStatement{ .seal = try seal_mod.SourceSeal.init(base, 0, @splat(36)), .expected_events = 3, .memory_instances = &pins, .range_table_roots = first.table_roots, .execution_roots = &execution, .provider_roots = &providers };
    statement.seal = try seal_mod.SourceSeal.initBound(base, 0, @splat(36), 1, 2, first.plan.digest, try statement.firstRoundDigest(a));
    var staged = try artifact.StagedWriter.init(a, tmp.dir, 2, 1);
    defer staged.deinit();
    first.memory_roots[0][0][0] ^= 1;
    try std.testing.expectError(error.UnsealedBlockProofRoster, producer.proveSecondPass(Cpu, a, source.source(), &first, statement, config, staged.proofSink()));
    first.memory_roots[0][0][0] ^= 1;
    const name = spool.final_run_name orelse return error.MissingFinalMemoryRun;
    var file = try tmp.dir.openFile(name, .{ .mode = .read_write });
    defer file.close();
    var altered: [4]u8 = undefined;
    std.mem.writeInt(u32, &altered, 99, .little);
    try file.pwriteAll(&altered, 2 * 17 + 13);
    try std.testing.expectError(error.BlockMemoryClaimReplayMismatch, producer.proveSecondPass(Cpu, a, source.source(), &first, statement, config, staged.proofSink()));
    try std.testing.expectError(error.FileNotFound, artifact.verifyPublished(Cpu, a, tmp.dir, statement, config));
}
