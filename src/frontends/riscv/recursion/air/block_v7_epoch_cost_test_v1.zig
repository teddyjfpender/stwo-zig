//! Exact compiler census, not proof timings or a qualified shared-prefix AIR.
const std = @import("std");
const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
const Prefix = @import("block_v7_epoch_transcript_v1.zig");
const Sink = @import("blake3_fixed_operation_recorder_v1.zig");
const Plan = @import("blake3_transcript_plan.zig").Plan;

test "v7 common epoch repeated verifier cost census" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var recorder = Sink.Recorder{ .a = temp, .limits = .{} };
    recorder.mixU32s(&.{ 0x42374550, E.VERSION, 2 });
    recorder.mixPublicRoot(.{ .circuit = 4_200_031, .first_wire = 0 }, @splat(0));
    try Prefix.fixed(temp, &recorder);
    var secure_operations: usize = 0;
    var exported_fields: usize = 0;
    for (recorder.operations.items) |op| if (op == .secure) {
        secure_operations += 1;
        exported_fields += op.secure.consumption.words() / 4;
    };
    try std.testing.expectEqual(@as(usize, 54), secure_operations);
    try std.testing.expectEqual(@as(usize, 106), exported_fields);
    for ([_]u32{ 1, 2, 4 }) |capacity| {
        var plan = try Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, recorder.operations.items);
        defer plan.deinit();
        try plan.validate();
        const hashes = plan.fixed.hashCounts();
        const nonhash = .{
            plan.fixed.cohortCount(2),  plan.fixed.cohortCount(6),
            plan.fixed.cohortCount(7),  plan.fixed.cohortCount(8),
            plan.fixed.cohortCount(14), plan.fixed.cohortCount(15),
        };
        std.debug.print("V7_EPOCH_COST version={d} capacity={d} operations={d} secure_operations={d} fields={d} g={d} xor={d} boundary={d} challenge={d} route={d} query={d} retry={d} counter={d}\n", .{ E.VERSION, capacity, recorder.operations.items.len, secure_operations, exported_fields, hashes.g, hashes.xor, nonhash[0], nonhash[1], nonhash[2], nonhash[3], nonhash[4], nonhash[5] });
        // Workload scenarios, not measured production rosters: 67 native
        // children + ROM + lookup + joint memory; then one caller per native.
        for ([_]usize{ 70, 137 }) |children| std.debug.print("V7_EPOCH_REUSE capacity={d} children={d} repeated_g={d} shared_g={d} removable_g={d} repeated_xor={d} removable_xor={d} new_link_fields={d} measured_speedup=false\n", .{ capacity, children, children * hashes.g, hashes.g, (children - 1) * hashes.g, children * hashes.xor, (children - 1) * hashes.xor, children * exported_fields });
    }
}
