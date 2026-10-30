const std = @import("std");
const Fixture = @import("../prover/block_v7_execution_caller_test_v1.zig");
const Producer = @import("block_v7_bounded_complete_cpu_producer_v1.zig");
const Receiver = @import("block_v7_mixed_batch_receiver_v1.zig");
const Consumer = struct {
    pub const Result = Producer.Output;
    pub fn consume(f: Fixture.Fixture) !Result {
        return Producer.produce(f.allocator, f.trusted, f.input, .{ .profile = .diagnostic_q8_pow0, .max_direct_children = 4, .max_originals = 64 });
    }
};
test "v7 bounded production windows reduce genuine separate memory originals to complete root" {
    const a = std.testing.allocator;
    var output = try Fixture.runFixture(false, true, Consumer);
    defer output.deinit();
    try std.testing.expect(output.counts.len >= 2);
    try std.testing.expect(output.root.charged_peak_bytes <= output.root.planned_peak_bytes.?);
    var covered: usize = 0;
    for (output.windows, output.counts) |window, count| {
        try std.testing.expectEqual(covered, window.first);
        try std.testing.expectEqual(count, window.count);
        try std.testing.expect(window.charged_peak_bytes <= window.planned_peak_bytes);
        covered += count;
    }
    try std.testing.expectEqual(try output.metadata.input().count(), covered);
    // Original fixture and every intermediate proof/row owner are gone here.
    var received = try Receiver.verify(a, output.root.bytes, output.metadata.trusted, output.metadata.input(), output.counts, output.pins, output.root.key, output.root.wires, .{});
    defer received.deinit();
    try std.testing.expectEqual(@as(u64, 12), received.summary.cycles);
    try std.testing.expectEqual(@as(u64, 77), received.summary.ram_events);
    try std.testing.expectError(error.InvalidMixedBatchFanIn, Receiver.verify(a, output.root.bytes, output.metadata.trusted, output.metadata.input(), output.counts[1..], output.pins, output.root.key, output.root.wires, .{}));
    std.debug.print("V7_BOUNDED_COMPLETE windows={d} originals={d} root_bytes={d} reduction_planned_bytes={d} reduction_peak_bytes={d} stats={f} windows_stats={f} originals_destroyed=true intermediates_destroyed=true complete_global_closure=true canonical_security=false\n", .{ output.counts.len, covered, output.root.bytes.len, output.root.planned_peak_bytes.?, output.root.charged_peak_bytes, std.json.fmt(output.stats, .{}), std.json.fmt(output.windows, .{}) });
}
