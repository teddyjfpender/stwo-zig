const std = @import("std");
const C = @import("stwo_circuit_frontend");
const Q = @import("stwo_core").fields.qm31.QM31;
const S = @import("../assignment_suffix.zig");
const Schedule = C.builder.witness_plan;
fn fixture(a: std.mem.Allocator, only_constants: bool) !C.builder.Context(Q) {
    var ctx = try C.builder.Context(Q).initWithWitnessOrigins(a, 0);
    errdefer ctx.deinit();
    if (!only_constants) {
        const x = try ctx.guess(Q.fromU32Unchecked(7, 3, 2, 1));
        const y = try ctx.guess(Q.fromU32Unchecked(11, 0, 0, 0));
        _ = try ctx.mul(x, y);
        _ = try ctx.inv(y);
    }
    try ctx.setOutputs(&.{});
    if (only_constants) {
        // Minimal finalized constant-only control for the empty-record edge;
        // this is not an application graph or a claimed proof admission.
        ctx.finalized = true;
        ctx.guesses_finalized = true;
    } else try ctx.finalize(false);
    try C.common.finalize.padToTargets(Q, &ctx, C.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    return ctx;
}
fn check(a: std.mem.Allocator, ctx: *const C.builder.Context(Q)) !S.Tail {
    const tail = try S.derive(ctx);
    var ordinary = try Schedule.build(a, ctx);
    defer ordinary.deinit();
    var plan = try tail.build(a, ctx, null);
    defer plan.deinit();
    const expected = try Schedule.evaluate(a, ctx, ordinary);
    defer a.free(expected);
    // Use original evaluator for prefix assignments, avoiding any alternative
    // operation interpretation. Default evaluator's FULL check is delayed by
    // supplying a borrowed prefix gate view solely in this host qualification.
    var prefix = ctx.*;
    prefix.circuit.add.items = prefix.circuit.add.items[0..tail.add];
    prefix.circuit.triple_xor.items = prefix.circuit.triple_xor.items[0..tail.triple];
    prefix.circuit.m31_to_u32.items = prefix.circuit.m31_to_u32.items[0..tail.m31];
    prefix.circuit.blake_g_gate.items = prefix.circuit.blake_g_gate.items[0..tail.blake];
    const actual = try Schedule.evaluate(a, &prefix, plan);
    defer a.free(actual);
    for (tail.ranges[0..tail.count]) |range| @memset(actual[range.first .. range.first + range.count], Q.fromU32Unchecked(range.value, 0, 0, 0));
    try std.testing.expectEqualDeep(expected, actual);
    try std.testing.expect((try ctx.circuit.check(a, actual)) == null);
    try std.testing.expectEqual(ordinary.seeds.len, plan.seeds.len);
    return tail;
}
test "canonical suffix keeps full assignments constraints and empty-task prefixes exact" {
    const a = std.testing.allocator;
    var ctx = try fixture(a, false);
    defer ctx.deinit();
    const tail = try check(a, &ctx);
    try std.testing.expect(tail.count != 0 and tail.prefix < tail.full);
    var empty = try fixture(a, true);
    defer empty.deinit();
    const zero_task_tail = try check(a, &empty);
    var plan = try zero_task_tail.build(a, &empty, null);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), plan.tasks.len);
    try std.testing.expectEqual(@as(u32, 3), zero_task_tail.prefix);
    const base = @as([32]u8, @splat(1));
    try std.testing.expect(!std.mem.eql(u8, &base, &S.identity(base, tail)));
    var changed = tail;
    changed.ranges[0].value ^= 2;
    try std.testing.expect(!std.mem.eql(u8, &S.identity(base, tail), &S.identity(base, changed)));
}
test "canonical suffix rejects retained EQ public constant hint and permutation references" {
    const a = std.testing.allocator;
    var ctx = try fixture(a, false);
    defer ctx.deinit();
    const tail = try S.derive(&ctx);
    const cut = tail.prefix;
    const oldeq = ctx.circuit.eq.items[0];
    ctx.circuit.eq.items[0].in0 = cut;
    try std.testing.expectError(error.UnsafeSuffixReference, S.derive(&ctx));
    ctx.circuit.eq.items[0] = oldeq;
    const oldout = ctx.circuit.output.items[0];
    ctx.circuit.output.items[0] = cut;
    try std.testing.expectError(error.UnsafeSuffixReference, S.derive(&ctx));
    ctx.circuit.output.items[0] = oldout;
    const oldconst = ctx.constants.values()[0];
    ctx.constants.values()[0].idx = cut;
    try std.testing.expectError(error.InvalidSuffixConstants, S.derive(&ctx));
    ctx.constants.values()[0] = oldconst;
    const oldorigin = ctx.witness_metadata.?.origins.items[0];
    ctx.witness_metadata.?.origins.items[0].out = cut;
    try std.testing.expectError(error.UnsafeSuffixReference, S.derive(&ctx));
    ctx.witness_metadata.?.origins.items[0] = oldorigin;
    const origin_index = ctx.witness_metadata.?.origins.items.len;
    try ctx.witness_metadata.?.origins.append(a, .{ .out = 0, .kind = .byte, .a = 0, .b = 3 });
    _ = try S.derive(&ctx); // b is an immediate byte index, not a variable.
    ctx.witness_metadata.?.origins.items[origin_index].a = cut;
    try std.testing.expectError(error.UnsafeSuffixReference, S.derive(&ctx));
    _ = ctx.witness_metadata.?.origins.pop();
    try ctx.circuit.permutation.inputs.append(a, cut);
    try std.testing.expectError(error.UnsafeSuffixReference, S.derive(&ctx));
    _ = ctx.circuit.permutation.inputs.pop();
    const oldgate = ctx.circuit.mul.items[0];
    ctx.circuit.mul.items[0].in0 = cut;
    const unsafe = try S.derive(&ctx);
    try std.testing.expectError(error.InvalidWitnessVariable, unsafe.build(a, &ctx, null));
    ctx.circuit.mul.items[0] = oldgate;
}
test "canonical suffix never treats a noncanonical final writer as zero" {
    const a = std.testing.allocator;
    var ctx = try fixture(a, false);
    defer ctx.deinit();
    ctx.circuit.blake_g_gate.items[ctx.circuit.blake_g_gate.items.len - 1].input_a = 1;
    const tail = try S.derive(&ctx);
    try std.testing.expectEqual(@as(u32, 0), tail.count);
    try std.testing.expectEqual(ctx.circuit.n_vars, tail.prefix);
    try std.testing.expect(!try S.parseFlag(null));
    try std.testing.expect(!try S.parseFlag("0"));
    try std.testing.expect(try S.parseFlag("1"));
    try std.testing.expectError(error.InvalidPaddingRangeFlag, S.parseFlag("yes"));
    const A = @import("../outer_assignment.zig");
    try std.testing.expectError(error.MissingCircuitAssignmentRangeKernel, A.requireRangeSupport(true, null));
    try A.requireRangeSupport(false, null);
}
