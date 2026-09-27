const std = @import("std");
const core = @import("stwo_core");
const trace_mod = @import("memory_component_trace.zig");
const transition = @import("memory_transition.zig");
const instance = @import("memory_instance.zig");
const spool = @import("memory_spool.zig");
const proof_mod = @import("../../prover/block_memory_proof_v2.zig");
const source_seal = @import("../../prover/block_memory_source_seal_v2.zig");
const manifest = @import("../../prover/block_commitment_manifest.zig");

test "two streamed memory instances produce sealed verified receipts and close ordinal links" {
    const a = std.testing.allocator;
    const api = proof_mod.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try spool.Spool.init(a, tmp.dir, 2);
    defer writer.deinit();
    for (0..3) |i| try writer.append(.{
        .space = 1,
        .address = 4096,
        .clock = @as(u64, @intCast(i)) * 4 + 1,
        .value = @intCast(i + 1),
    });
    const Loader = struct {
        fn load(_: *anyopaque, _: u1, _: u32) anyerror!u32 {
            return 0;
        }
    };
    var context: u8 = 0;
    var reader = transition.Reader{ .sorted = try writer.finish(), .initial = .{ .context = &context, .load = Loader.load } };
    defer reader.deinit();
    var partitioner = try instance.Partitioner.init(&reader, 3, 2);
    var traces: [2]trace_mod.Trace = undefined;
    var initialized: usize = 0;
    defer for (traces[0..initialized]) |*trace| trace.deinit();
    for (&traces) |*trace| {
        trace.* = (try trace_mod.Trace.nextFromPartitioner(a, &partitioner, 8)).?;
        initialized += 1;
    }
    try std.testing.expect((try trace_mod.Trace.nextFromPartitioner(a, &partitioner, 8)) == null);
    try std.testing.expectEqual(@as(u32, 2), traces[0].claim.rows);
    try std.testing.expectEqual(@as(u32, 1), traces[1].claim.rows);

    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const sealed = try source_seal.SourceSeal.init(manifest.Sealed{ .digest = @splat(31), .instance_count = 2 }, 0, @splat(29));
    var receipts: [2]proof_mod.VerifiedMemoryReceipt = undefined;
    for (&traces, &receipts, 0..) |*trace, *receipt, index| {
        var first_round = try api.commitFirstRound(a, trace, config);
        defer first_round.deinit(a);
        const proof = try api.proveExperimental(a, &first_round, trace, sealed, @intCast(index), first_round.roots);
        receipt.* = try api.verifyExperimentalOwned(a, proof, trace.claim, sealed, @intCast(index), first_round.roots, config);
    }
    try proof_mod.admitMemoryReceipts(a, sealed, &receipts, 3);
    try std.testing.expectError(error.InvalidMemoryReceiptCensus, proof_mod.admitMemoryReceipts(a, sealed, receipts[0..1], 3));
    const reordered = [_]proof_mod.VerifiedMemoryReceipt{ receipts[1], receipts[0] };
    try std.testing.expectError(error.InvalidMemoryReceiptCensus, proof_mod.admitMemoryReceipts(a, sealed, &reordered, 3));
    var altered_seal = receipts;
    altered_seal[1].sealed_channel_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidMemoryReceiptCensus, proof_mod.admitMemoryReceipts(a, sealed, &altered_seal, 3));
    var altered_link = receipts;
    altered_link[1].relation.link_sum = altered_link[1].relation.link_sum.add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.UnclosedBlockMemoryLink, proof_mod.admitMemoryReceipts(a, sealed, &altered_link, 3));
}
