//! CPU-only registration-dispatch benchmark over the unchanged original graph.
//! Uses only production BuildMetrics: no append census or reserve path.
const std = @import("std");
const C = @import("../builder/context.zig");
const Schedule = @import("plan.zig");
const Q = @import("stwo_core").fields.qm31.QM31;
fn fingerprint(plan: Schedule.Plan) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("witness/task-append/qualification/v1\x00");
    var word: [8]u8 = undefined;
    for (plan.tasks) |task| {
        hash.update(&.{@intFromEnum(task.kind)});
        std.mem.writeInt(u32, word[0..4], task.index, .little);
        hash.update(word[0..4]);
        std.mem.writeInt(u32, word[0..4], task.level, .little);
        hash.update(word[0..4]);
    }
    for (plan.seeds) |seed| {
        std.mem.writeInt(u32, word[0..4], seed.variable, .little);
        hash.update(word[0..4]);
        for (seed.value.toM31Array()) |coordinate| {
            std.mem.writeInt(u32, word[0..4], coordinate.v, .little);
            hash.update(word[0..4]);
        }
    }
    for (plan.level_ends) |end| {
        std.mem.writeInt(u64, &word, end, .little);
        hash.update(&word);
    }
    return hash.finalResult();
}
test "task append dispatch: validated graphs match DFS and canonical plan fingerprints" {
    const a = std.heap.page_allocator;
    const B = @import("../builder/blake.zig");
    const wrappers = @import("../builder/wrappers.zig");
    const iv = @import("../builder/ivalue.zig");
    for ([_]usize{ 1000, 25000, 250000 }) |rounds| {
        var ctx = try C.Context(Q).initWithWitnessOrigins(a, 1);
        defer ctx.deinit();
        const U = wrappers.U32Wrapper(C.Var);
        var state: [4]U = undefined;
        for (&state, 0..) |*value, i| value.* = .newUnsafe(try ctx.guess(iv.packU32(Q, @intCast(i + 17))));
        const input = U.newUnsafe(try ctx.guess(iv.packU32(Q, 0xdeadbeef)));
        const constant = U.newUnsafe(try ctx.constant(iv.packU32(Q, 123)));
        var accumulator = try ctx.guess(Q.fromU32Unchecked(17, 3, 7, 11));
        for (0..rounds) |i| {
            state = try B.blakeGGate(Q, &ctx, state[0], state[1], state[2], state[3], input, constant);
            accumulator = try ctx.add(try ctx.mul(accumulator, input.get()), state[i % 4].get());
        }
        try ctx.setOutputs(&.{accumulator});
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        var reference = try Schedule.buildDfsReference(a, &ctx);
        defer reference.deinit();
        const expected = fingerprint(reference);
        for (0..3) |trial| {
            var metrics = Schedule.BuildMetrics{};
            var clock = try std.time.Timer.start();
            var actual = try Schedule.buildProfiled(a, &ctx, &metrics);
            const elapsed = clock.read();
            defer actual.deinit();
            try std.testing.expectEqualDeep(reference.tasks, actual.tasks);
            try std.testing.expectEqualDeep(reference.seeds, actual.seeds);
            try std.testing.expectEqualSlices(usize, reference.level_ends, actual.level_ends);
            try std.testing.expectEqualSlices(u8, &expected, &fingerprint(actual));
            if (trial == 0) {
                const replayed = try Schedule.evaluate(a, &ctx, actual);
                defer a.free(replayed);
                try std.testing.expectEqualDeep(ctx.values(), replayed);
            }
            std.debug.print("TASK_APPEND_DISPATCH {{\"rounds\":{},\"trial\":{},\"variables\":{},\"tasks\":{},\"seeds\":{},\"task_bytes\":{},\"tasks_ns\":{},\"plan_ns\":{},\"fingerprint\":\"{s}\"}}\n", .{ rounds, trial, ctx.circuit.n_vars, actual.tasks.len, actual.seeds.len, actual.tasks.len * @sizeOf(Schedule.Task), metrics.tasks_ns, elapsed, std.fmt.bytesToHex(expected, .lower) });
        }
    }
}
