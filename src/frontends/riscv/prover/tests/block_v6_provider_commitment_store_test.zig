const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Store = @import("../block_v6_provider_commitment_store_v1.zig");
const Rom = @import("../block_v5_program_table_proof_v1.zig");
const Tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
test "provider commitment checkpoint restores ROM empty main tree and verifies byte-identical proof" {
    const a = std.testing.allocator;
    const leaves = [_]Tree.Leaf{ .{ .index = 0, .value = 1 }, .{ .index = 1, .value = 2 }, .{ .index = 2, .value = 3 }, .{ .index = 3, .value = 4 } };
    const root = try Tree.TreeHasher.init(.program).root(&leaves);
    const plan = @import("../block_v5_program_table_v1.zig").Plan{ .program_root = root, .leaves = &leaves, .multiplicities = &.{3}, .expected_fetches = 3, .log_size = 7 };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    var roots: [2][32]u8 = undefined;
    const pin = blk: {
        var collected = try Rom.ForBackend(Cpu).commitCheckpointFirstRound(a, plan, config);
        defer collected.deinit(a);
        roots = collected.roots;
        break :blk try Store.writeProgram(a, temp.dir, "rom.pcs", plan, &collected, .{});
    };
    var original = try Rom.ForBackend(Cpu).commitFirstRound(a, plan, config);
    defer original.deinit(a);
    var restored = try Store.loadProgram(a, temp.dir, "rom.pcs", plan, roots, config, pin, .{});
    defer restored.deinit(a);
    try std.testing.expectEqualDeep(original.roots, restored.roots);
    try std.testing.expectEqual(@as(usize, 0), restored.scheme.trees.items[1].columns.len);
    try std.testing.checkAllAllocationFailures(a, loadProgram, .{ temp.dir, plan, roots, config, pin });
    var wrong = roots;
    wrong[0][0] ^= 1;
    try std.testing.expectError(error.InvalidProviderCheckpointScope, Store.loadProgram(a, temp.dir, "rom.pcs", plan, wrong, config, pin, .{}));
    try std.testing.expectError(error.ProviderCheckpointResourceLimit, Store.loadProgram(a, temp.dir, "rom.pcs", plan, roots, config, pin, .{ .max_loaded_bytes = pin.loaded_bytes - 1 }));
    const seal = try Rom.Seal.init(plan, @splat(41), @splat(53), roots);
    var first_proof = try Rom.ForBackend(Cpu).prove(a, &original, plan, seal);
    defer first_proof.deinit(a);
    var retained_proof = try Rom.ForBackend(Cpu).prove(a, &restored, plan, seal);
    defer retained_proof.deinit(a);
    var before = std.Io.Writer.Allocating.init(a);
    defer before.deinit();
    var after = std.Io.Writer.Allocating.init(a);
    defer after.deinit();
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &before.writer, first_proof.stark);
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &after.writer, retained_proof.stark);
    try std.testing.expectEqualSlices(u8, before.written(), after.written());
    var verified = try Rom.ForBackend(Cpu).verifyCaptureBorrowed(a, &retained_proof, plan, seal, root, roots, config);
    defer verified.deinit(a);
    try std.testing.expectEqual(@as(u64, 3), verified.receipt.fetch_count);
    std.debug.print("PROVIDER_CHECKPOINT rom=true original_destroyed=true empty_main=true proof_byte_parity=true verified=true bytes={d} loaded_bytes={d}\n", .{ pin.bytes, pin.loaded_bytes });
}
fn loadProgram(a: std.mem.Allocator, dir: std.fs.Dir, plan: @import("../block_v5_program_table_v1.zig").Plan, roots: [2][32]u8, config: core.pcs.PcsConfig, pin: Store.Pin) !void {
    var restored = try Store.loadProgram(a, dir, "rom.pcs", plan, roots, config, pin, .{});
    defer restored.deinit(a);
}
