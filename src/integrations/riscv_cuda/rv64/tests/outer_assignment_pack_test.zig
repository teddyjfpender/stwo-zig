const std = @import("std");
const Circuit = @import("stwo_circuit_frontend");
const Q = @import("stwo_core").fields.qm31.QM31;
const Schedule = Circuit.builder.witness_plan;
const Pack = @import("../outer_assignment_pack.zig");
const Identity = @import("../schedule_identity.zig");
const Pools = @import("stwo_prover_engine").work_pool;

// Independent copy of the original host encoding, including CSR append and
// the separate capability pass. This oracle never calls the candidate packer.
fn legacy(a: std.mem.Allocator, ctx: *const Circuit.builder.Context(Q), source: []const Schedule.Task, tasks: []Pack.Task, capabilities: u32) ![]u32 {
    var indices: std.ArrayList(u32) = .empty;
    errdefer indices.deinit(a);
    for (source, tasks) |task, *out| {
        var ibuf: [6]u32 = undefined;
        var obuf: [4]u32 = undefined;
        const in = Schedule.inputs(ctx, task, &ibuf);
        const outputs = Schedule.outputs(ctx, task, &obuf);
        out.* = .{ .kind = @intFromEnum(task.kind), .out = outputs[0] };
        if (task.kind == .permutation) {
            out.args[0] = std.math.cast(u32, indices.items.len) orelse return error.WitnessPlanTooLarge;
            out.args[1] = std.math.cast(u32, in.len) orelse return error.WitnessPlanTooLarge;
            try indices.appendSlice(a, in);
            try indices.appendSlice(a, outputs);
        } else {
            @memcpy(out.args[0..in.len], in);
            if (task.kind == .hint) out.kind = switch (ctx.witness_metadata.?.origins.items[task.index].kind) {
                .seed => return error.InvalidWitnessOrigin,
                .inverse => 8,
                .divide => 9,
                .pointwise_inverse_or_zero => 10,
                .pointwise_lsb => 11,
                .byte => 12,
                .byte_complement => 13,
                .is_nonzero => 14,
                .zero => 15,
            };
            if (task.kind == .hint) {
                const hint = ctx.witness_metadata.?.origins.items[task.index];
                if (hint.kind == .byte or hint.kind == .byte_complement) out.args[1] = hint.b;
            }
        }
    }
    for (tasks) |task| if (capabilities & (@as(u32, 1) << @intCast(task.kind)) == 0) return error.UnsupportedCircuitAssignmentHint;
    return indices.toOwnedSlice(a);
}

fn fixture(a: std.mem.Allocator) !Circuit.builder.Context(Q) {
    var ctx = try Circuit.builder.Context(Q).initWithWitnessOrigins(a, 1);
    errdefer ctx.deinit();
    const x = try ctx.guess(Q.fromU32Unchecked(11, 3, 7, 9));
    const y = try ctx.guess(Q.fromU32Unchecked(17, 0, 0, 0));
    const inv = try ctx.inv(y);
    const div = try ctx.div(x, y);
    const sum = try ctx.add(div, inv);
    _ = try ctx.sub(x, y);
    _ = try ctx.mul(sum, x);
    _ = try ctx.pointwiseMul(sum, x);
    const zero = Circuit.builder.wrappers.U32Wrapper(Circuit.builder.circuit.Var).newUnsafe(ctx.zero());
    _ = try Circuit.builder.blake.blakeGGate(Q, &ctx, zero, zero, zero, zero, zero, zero);
    _ = try Circuit.builder.blake.tripleXor(Q, &ctx, zero, zero, zero);
    const simd = Circuit.builder.simd;
    const lanes = simd.Simd.fromPacked(&.{x}, 4);
    _ = try simd.guessInvOrZero(Q, &ctx, lanes);
    _ = try simd.guessLsb(Q, &ctx, lanes);
    try ctx.setOutputs(&.{sum});
    try ctx.finalize(false);
    return ctx;
}

test "assignment task packing preserves original records levels seeds and identity" {
    const a = std.testing.allocator;
    var ctx = try fixture(a);
    defer ctx.deinit();
    var plan = try Schedule.build(a, &ctx);
    defer plan.deinit();
    const expected = try a.alloc(Pack.Task, plan.tasks.len);
    defer a.free(expected);
    const actual = try a.alloc(Pack.Task, plan.tasks.len);
    defer a.free(actual);
    const indices = try legacy(a, &ctx, plan.tasks, expected, 0xffff);
    defer a.free(indices);
    try std.testing.expectEqual(@as(usize, 0), indices.len);
    const plan_before = try a.dupe(u8, std.mem.sliceAsBytes(plan.tasks));
    defer a.free(plan_before);
    const seed_before = try a.dupe(u8, std.mem.sliceAsBytes(plan.seeds));
    defer a.free(seed_before);
    const levels_before = try a.dupe(u8, std.mem.sliceAsBytes(plan.level_ends));
    defer a.free(levels_before);
    const identity = try Identity.digest(a, .{ std.mem.sliceAsBytes(expected), std.mem.sliceAsBytes(indices), std.mem.sliceAsBytes(plan.level_ends) });
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 64 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    _ = try Pack.fill(&ctx, plan.tasks, actual, 0xffff);
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(expected), std.mem.sliceAsBytes(actual));
    try std.testing.expectEqualSlices(u8, plan_before, std.mem.sliceAsBytes(plan.tasks));
    try std.testing.expectEqualSlices(u8, seed_before, std.mem.sliceAsBytes(plan.seeds));
    try std.testing.expectEqualSlices(u8, levels_before, std.mem.sliceAsBytes(plan.level_ends));
    try std.testing.expectEqualSlices(u8, &identity, &(try Identity.digest(a, .{ std.mem.sliceAsBytes(actual), &.{}, std.mem.sliceAsBytes(plan.level_ends) })));
}

test "assignment packing preserves all hint words capability fallback and error precedence" {
    const a = std.testing.allocator;
    var ctx = try Circuit.builder.Context(Q).initWithWitnessOrigins(a, 0);
    defer ctx.deinit();
    const Origin = @TypeOf(ctx.witness_metadata.?.origins.items[0]);
    ctx.witness_metadata.?.origins.clearRetainingCapacity();
    inline for (.{ .inverse, .divide, .pointwise_inverse_or_zero, .pointwise_lsb, .byte, .byte_complement, .is_nonzero, .zero }) |kind| {
        try ctx.witness_metadata.?.origins.append(a, Origin{ .out = 100, .kind = kind, .a = 1, .b = 3 });
    }
    var tasks: [8]Schedule.Task = undefined;
    for (&tasks, 0..) |*task, i| task.* = .{ .kind = .hint, .index = @intCast(i) };
    var expected: [8]Pack.Task = undefined;
    var actual: [8]Pack.Task = undefined;
    const indices = try legacy(a, &ctx, &tasks, &expected, 0xffff);
    defer a.free(indices);
    _ = try Pack.fill(&ctx, &tasks, &actual, 0xffff);
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(&expected), std.mem.sliceAsBytes(&actual));
    try std.testing.expectError(error.UnsupportedCircuitAssignmentHint, Pack.fill(&ctx, &tasks, &actual, 0xfff));
    try std.testing.expectError(error.TaskPackLengthMismatch, Pack.fill(&ctx, &tasks, actual[0..7], 0xffff));
    // Original precedence: an invalid hint discovered while packing wins over
    // an earlier unsupported capability discovered by the later scan.
    ctx.witness_metadata.?.origins.items[7].kind = .seed;
    try std.testing.expectError(error.InvalidWitnessOrigin, Pack.fill(&ctx, &tasks, &actual, 0));
    try std.testing.expectError(error.InvalidWitnessOrigin, legacy(a, &ctx, &tasks, &expected, 0));
    var permutation = [_]Schedule.Task{.{ .kind = .permutation, .index = 0 }};
    try std.testing.expectError(error.UnexpectedPermutationTask, Pack.fill(&ctx, &permutation, actual[0..1], 0xffff));
}

test "assignment packing mixed-record benchmark exact with scoped pool failures joined" {
    const a = std.testing.allocator;
    var ctx = try fixture(a);
    defer ctx.deinit();
    var plan = try Schedule.build(a, &ctx);
    defer plan.deinit();
    const n: usize = 1 << 23;
    const source = try a.alloc(Schedule.Task, n);
    defer a.free(source);
    // A large record mix drawn from validated fixture records. The repeated
    // compact source fixture is intentional: this measures packing, not plan
    // construction or a claimed complete generated circuit.
    const mix = [_]Schedule.Kind{ .blake_g, .blake_g, .add, .mul, .hint, .triple_xor };
    var examples: [mix.len]Schedule.Task = undefined;
    for (mix, &examples) |kind, *example| {
        var found = false;
        for (plan.tasks) |task| if (task.kind == kind) {
            example.* = task;
            found = true;
            break;
        };
        try std.testing.expect(found);
    }
    for (source, 0..) |*task, i| task.* = examples[i % examples.len];
    const expected = try a.alloc(Pack.Task, n);
    defer a.free(expected);
    const actual = try a.alloc(Pack.Task, n);
    defer a.free(actual);
    var serial_ns: [3]u64 = undefined;
    var parallel_ns: [3]u64 = undefined;
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 64 * 1024, .backing_allocator = a });
    defer pool.deinit();
    for (0..3) |iteration| {
        var timer = try std.time.Timer.start();
        const indices = try legacy(a, &ctx, source, expected, 0xffff);
        serial_ns[iteration] = timer.read();
        a.free(indices);
        var binding = try Pools.ScopedPoolBinding.init(&pool);
        timer.reset();
        const shards = try Pack.fill(&ctx, source, actual, 0xffff);
        parallel_ns[iteration] = timer.read();
        binding.deinit();
        try std.testing.expect(shards > 1);
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(expected), std.mem.sliceAsBytes(actual));
    }
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var held = try pool.acquire(try Pools.WorkerBudget.init(4));
    try std.testing.expectEqual(@as(usize, 1), try Pack.fill(&ctx, source, actual, 0xffff));
    held.deinit();
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(expected), std.mem.sliceAsBytes(actual));
    const old_last = source[n - 1];
    source[n - 1] = .{ .kind = .permutation, .index = 0 };
    try std.testing.expectError(error.UnexpectedPermutationTask, Pack.fill(&ctx, source, actual, 0));
    source[n - 1] = old_last;
    const bad_hint_index: u32 = @intCast(ctx.witness_metadata.?.origins.items.len);
    try ctx.witness_metadata.?.origins.append(a, .{ .out = 100, .kind = .seed });
    source[n - 1] = .{ .kind = .hint, .index = bad_hint_index };
    try std.testing.expectError(error.InvalidWitnessOrigin, Pack.fill(&ctx, source, actual, 0));
    source[n - 1] = old_last;
    _ = try Pack.fill(&ctx, source, actual, 0xffff);
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(expected), std.mem.sliceAsBytes(actual));
    std.mem.sort(u64, &serial_ns, {}, std.sort.asc(u64));
    std.mem.sort(u64, &parallel_ns, {}, std.sort.asc(u64));
    std.debug.print("OUTER_TASK_PACK_PARITY tasks={} bytes={} workers=4 serial_median_ns={} parallel_median_ns={} all_records_exact=true csr=false\n", .{ n, n * @sizeOf(Pack.Task), serial_ns[1], parallel_ns[1] });
}

test "assignment packing leaves CSR permutation records on legacy append path" {
    const a = std.testing.allocator;
    var ctx = try Circuit.builder.Context(Q).initWithWitnessOrigins(a, 1);
    defer ctx.deinit();
    const x = try ctx.guess(Q.fromU32Unchecked(3, 0, 0, 0));
    const y = try ctx.guess(Q.fromU32Unchecked(2, 0, 0, 0));
    const outputs = try ctx.permuteNamed(&.{ x, y }, .sort_by_u_coordinate);
    const first = outputs[0];
    try ctx.setOutputs(&.{first});
    try ctx.finalize(false);
    var plan = try Schedule.build(a, &ctx);
    defer plan.deinit();
    try std.testing.expect(ctx.circuit.permutation.ends.items.len != 0);
    const tasks = try a.alloc(Pack.Task, plan.tasks.len);
    defer a.free(tasks);
    const indices = try legacy(a, &ctx, plan.tasks, tasks, 0xffff);
    defer a.free(indices);
    try std.testing.expectEqual(@as(usize, 4), indices.len);
    try std.testing.expectEqualSlices(u32, &.{ x.idx, y.idx }, indices[0..2]);
    try std.testing.expectError(error.UnexpectedPermutationTask, Pack.fill(&ctx, plan.tasks, tasks, 0xffff));
}

test "parallel ordering preserves real builder GPU record and schedule identities" {
    const a = std.testing.allocator;
    var ctx = try Circuit.builder.Context(Q).initWithWitnessOrigins(a, 1);
    defer ctx.deinit();
    const Var = Circuit.builder.circuit.Var;
    const multiplier = try ctx.guess(Q.fromU32Unchecked(2, 1, 0, 0));
    var last: [256]Var = undefined;
    for (&last, 0..) |*variable, i| variable.* = try ctx.guess(Q.fromU32Unchecked(@intCast(i + 3), 0, 0, 0));
    for (0..256) |_| for (&last) |*variable| {
        variable.* = try ctx.mul(variable.*, multiplier);
    };
    try ctx.setOutputs(&.{last[0]});
    try ctx.finalize(false);
    var reference = try Schedule.buildDfsReference(a, &ctx);
    defer reference.deinit();
    const expected = try a.alloc(Pack.Task, reference.tasks.len);
    defer a.free(expected);
    const indices = try legacy(a, &ctx, reference.tasks, expected, 0xffff);
    defer a.free(indices);
    const identity = try Identity.digest(a, .{ std.mem.sliceAsBytes(expected), std.mem.sliceAsBytes(indices), std.mem.sliceAsBytes(reference.level_ends) });
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 64 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var parallel = try Schedule.build(a, &ctx);
    defer parallel.deinit();
    try std.testing.expectEqualDeep(reference.tasks, parallel.tasks);
    try std.testing.expectEqualDeep(reference.seeds, parallel.seeds);
    try std.testing.expectEqualSlices(usize, reference.level_ends, parallel.level_ends);
    const actual = try a.alloc(Pack.Task, parallel.tasks.len);
    defer a.free(actual);
    try std.testing.expect((try Pack.fill(&ctx, parallel.tasks, actual, 0xffff)) > 1);
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(expected), std.mem.sliceAsBytes(actual));
    try std.testing.expectEqualSlices(u8, &identity, &(try Identity.digest(a, .{ std.mem.sliceAsBytes(actual), &.{}, std.mem.sliceAsBytes(parallel.level_ends) })));
}
