const std = @import("std");
const core = @import("stwo_core");
const E = @import("block_v7_execution_epoch_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
test "v7 source adapter full lifecycle codegen" {
    std.mem.doNotOptimizeAway(&@import("block_v7_native_checkpoint_v1.zig").collect);
    std.mem.doNotOptimizeAway(&@import("block_v7_native_checkpoint_v1.zig").load);
    std.mem.doNotOptimizeAway(&@import("block_v7_native_proof_v1.zig").For(Cpu).prove);
    std.mem.doNotOptimizeAway(&@import("block_v7_native_proof_v1.zig").For(Cpu).verify);
}
test "v7 epoch challenge schedule binds exact roots and typed order" {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    var counts: E.Counts = @splat(0);
    counts[0] = 2;
    var entries = [_]E.Entry{ try E.Entry.init(.native, 0, @splat(1), &.{ @splat(2), @splat(3) }), try E.Entry.init(.native, 1, @splat(4), &.{ @splat(5), @splat(6) }) };
    const epoch = try E.Epoch.init(@splat(9), config, counts, &entries, 2);
    const d = try epoch.draw(a);
    const again = try epoch.draw(a);
    try std.testing.expectEqualDeep(d, again);
    try std.testing.expectError(error.IncompleteV7Epoch, epoch.requireCompleteFamilies());
    entries[1].roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedV7Epoch, epoch.require(@splat(9), config, counts, &entries, 2));
    const changed = try E.Epoch.init(@splat(9), config, counts, &entries, 2);
    try std.testing.expect(!std.meta.eql(d, (try changed.draw(a))));
    std.mem.swap(E.Entry, &entries[0], &entries[1]);
    try std.testing.expectError(error.InvalidV7EpochRoster, E.Epoch.init(@splat(9), config, counts, &entries, 2));
}
