const std = @import("std");
const Padding = @import("padding_plan.zig");
const C = @import("../builder/context.zig");
const B = @import("../builder/mod.zig");
const Schedule = @import("plan.zig");
const Finalize = @import("../common/finalize.zig");
const PP = @import("../common/preprocessed.zig");
const Q = @import("stwo_core").fields.qm31.QM31;
fn context(a: std.mem.Allocator, trace_only: bool) !C.Context(Q) {
    var ctx = if (trace_only) try C.Context(Q).initTraceOnly(a, 1) else try C.Context(Q).initWithWitnessOrigins(a, 1);
    errdefer ctx.deinit();
    const x = try ctx.guess(Q.fromU32Unchecked(7, 3, 2, 1));
    const y = try ctx.guess(Q.fromU32Unchecked(11, 0, 0, 0));
    const result = try ctx.mul(x, y);
    _ = try ctx.inv(y);
    try ctx.setOutputs(&.{result});
    try ctx.finalize(false);
    return ctx;
}
fn fingerprint(ctx: *const C.Context(Q)) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (.{ ctx.circuit.eq.items, ctx.circuit.add.items, ctx.circuit.sub.items, ctx.circuit.mul.items, ctx.circuit.pointwise_mul.items, ctx.circuit.triple_xor.items, ctx.circuit.m31_to_u32.items, ctx.circuit.blake_g_gate.items, ctx.circuit.output.items, ctx.circuit.permutation.inputs.items, ctx.circuit.permutation.outputs.items }) |items| h.update(std.mem.sliceAsBytes(items));
    return h.finalResult();
}

test "padding range CPU prototype exactly replays frozen full padded assignments and PP" {
    const a = std.testing.allocator;
    var ctx = try context(a, false);
    defer ctx.deinit();
    const original_variables = ctx.circuit.n_vars;
    const provenance = try Padding.Provenance.captureAndPad(&ctx, Finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    const frozen = fingerprint(&ctx);
    var original = try Schedule.build(a, &ctx);
    defer original.deinit();
    const old_assignment = try Schedule.evaluate(a, &ctx, original);
    defer a.free(old_assignment);
    try std.testing.expectEqualDeep(ctx.values(), old_assignment);
    var full_pp = try PP.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer full_pp.deinit(a);
    var compact = try Padding.Plan.build(a, &ctx, provenance);
    defer compact.deinit();
    const actual = try compact.evaluate(a, &ctx);
    defer a.free(actual);
    try std.testing.expectEqualDeep(old_assignment, actual);
    try std.testing.expect(compact.prefix_plan.tasks.len < original.tasks.len);
    try std.testing.expectEqual(original.seeds.len, compact.prefix_plan.seeds.len);
    try std.testing.expectEqual(original_variables, provenance.before.variables);
    try std.testing.expectError(error.PaddingRangeGpuUnsupported, compact.requireGpuSupported());
    try std.testing.expectEqualSlices(u8, &frozen, &fingerprint(&ctx));
    // The compact plan never supplies a replacement circuit to the PCS.
    var after_pp = try PP.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer after_pp.deinit(a);
    for (full_pp.columns, after_pp.columns) |expected, observed| {
        try std.testing.expectEqualStrings(expected.id, observed.id);
        try std.testing.expectEqualDeep(expected.values, observed.values);
    }
}

test "padding range trace-only topology and all assignment values match original" {
    const a = std.testing.allocator;
    var full = try context(a, false);
    defer full.deinit();
    var trace = try context(a, true);
    defer trace.deinit();
    const targets = Finalize.computePaddedSizes(.fromBuilder(&full.circuit));
    try Finalize.padToTargets(Q, &full, targets);
    const provenance = try Padding.Provenance.captureAndPad(&trace, targets);
    try std.testing.expectEqual(@as(usize, 0), trace.value_table.items.len);
    try std.testing.expectEqualSlices(u8, &fingerprint(&full), &fingerprint(&trace));
    var compact = try Padding.Plan.build(a, &trace, provenance);
    defer compact.deinit();
    const assignment = try compact.evaluate(a, &trace);
    defer a.free(assignment);
    try std.testing.expectEqualDeep(full.values(), assignment);
    try std.testing.expectEqual(@as(usize, 0), trace.value_table.items.len);
}

test "padding range provenance rejects gate inputs output bounds gaps overlap and mutated range values" {
    const a = std.testing.allocator;
    var ctx = try context(a, false);
    defer ctx.deinit();
    var targets = Finalize.computePaddedSizes(.fromBuilder(&ctx.circuit));
    inline for (std.meta.fields(Finalize.ComponentSizes)) |field| @field(targets, field.name) *= 2;
    const provenance = try Padding.Provenance.captureAndPad(&ctx, targets);
    const ranges = try provenance.validate(&ctx);
    const add = &ctx.circuit.add.items[ranges[0].first_gate];
    const old_add = add.*;
    add.in0 = 0;
    try std.testing.expectError(error.InvalidPaddingProvenance, provenance.validate(&ctx));
    add.* = old_add;
    add.out += 1;
    try std.testing.expectError(error.InvalidPaddingProvenance, provenance.validate(&ctx));
    add.* = old_add;
    const triple = &ctx.circuit.triple_xor.items[ranges[1].first_gate];
    triple.input_c = 1;
    try std.testing.expectError(error.InvalidPaddingProvenance, provenance.validate(&ctx));
    triple.input_c = 0;
    const m31 = &ctx.circuit.m31_to_u32.items[ranges[2].first_gate];
    m31.input = 1;
    try std.testing.expectError(error.InvalidPaddingProvenance, provenance.validate(&ctx));
    m31.input = 0;
    const blake = &ctx.circuit.blake_g_gate.items[ranges[3].first_gate];
    blake.input_f1 = 1;
    try std.testing.expectError(error.InvalidPaddingProvenance, provenance.validate(&ctx));
    blake.input_f1 = 0;
    const eq = &ctx.circuit.eq.items[provenance.before.eq];
    eq.in1 = 1;
    try std.testing.expectError(error.InvalidPaddingProvenance, provenance.validate(&ctx));
    eq.in1 = 0;
    var corrupt = provenance;
    corrupt.before.variables += 1;
    try std.testing.expectError(error.InvalidPaddingProvenance, corrupt.validate(&ctx));
    corrupt = provenance;
    corrupt.after.variables -= 1;
    try std.testing.expectError(error.InvalidPaddingProvenance, corrupt.validate(&ctx));
    var compact = try Padding.Plan.build(a, &ctx, provenance);
    defer compact.deinit();
    compact.ranges[0].kind = .triple_zero; // Would silently set add outputs to0.
    try std.testing.expectError(error.InvalidPaddingProvenance, compact.evaluate(a, &ctx));
    compact.ranges = ranges;
    compact.ranges[1].first = compact.ranges[0].first; // Overlap.
    try std.testing.expectError(error.InvalidPaddingProvenance, compact.evaluate(a, &ctx));
    const old_origin = ctx.witness_metadata.?.origins.items[0];
    ctx.witness_metadata.?.origins.items[0].out = ranges[0].first;
    try std.testing.expectError(error.InvalidPaddingProvenance, provenance.validate(&ctx));
    ctx.witness_metadata.?.origins.items[0] = old_origin;
    const old_constant = ctx.constants.values()[0];
    ctx.constants.values()[0].idx = ranges[0].first;
    try std.testing.expectError(error.InvalidPaddingProvenance, provenance.validate(&ctx));
    ctx.constants.values()[0] = old_constant;
    const old_output = ctx.circuit.output.items[0];
    ctx.circuit.output.items[0] = ranges[0].first;
    try std.testing.expectError(error.InvalidPaddingProvenance, provenance.validate(&ctx));
    ctx.circuit.output.items[0] = old_output;
    try ctx.circuit.permutation.ends.append(a, 0);
    try std.testing.expectError(error.InvalidPaddingProvenance, provenance.validate(&ctx));
    _ = ctx.circuit.permutation.ends.pop();
    corrupt = provenance;
    corrupt.before.variables = 0;
    try std.testing.expectError(error.InvalidPaddingProvenance, corrupt.validate(&ctx));
    // A prefix definition may not acquire a padding address after capture.
    ctx.circuit.mul.items[0].out = ranges[0].first;
    try std.testing.expectError(error.InvalidWitnessVariable, Padding.Plan.build(a, &ctx, provenance));
}

test "padding range compact descriptors remove tasks without a per variable seed expansion" {
    const a = std.testing.allocator;
    var ctx = try context(a, true);
    defer ctx.deinit();
    const before = ctx.circuit.n_vars;
    const provenance = try Padding.Provenance.captureAndPad(&ctx, .{ .eq = 64, .qm31_ops = 1 << 18, .triple_xor = 1 << 16, .m31_to_u32 = 1 << 16, .blake_g_gate = 1 << 18 });
    var timer = try std.time.Timer.start();
    var original = try Schedule.build(a, &ctx);
    defer original.deinit();
    const original_ns = timer.lap();
    var compact = try Padding.Plan.build(a, &ctx, provenance);
    defer compact.deinit();
    const compact_ns = timer.lap();
    const values = try compact.evaluate(a, &ctx);
    defer a.free(values);
    const old = try Schedule.evaluate(a, &ctx, original);
    defer a.free(old);
    try std.testing.expectEqualDeep(old, values);
    try std.testing.expectEqual(original.seeds.len, compact.prefix_plan.seeds.len);
    var ranged_variables: usize = 0;
    var padding_tasks: usize = 0;
    for (compact.ranges) |range| {
        ranged_variables += range.count;
        padding_tasks += range.gate_count;
    }
    try std.testing.expectEqual(@as(usize, ctx.circuit.n_vars - before), ranged_variables);
    try std.testing.expectEqual(original.tasks.len - compact.prefix_plan.tasks.len, padding_tasks);
    std.debug.print("PADDING_RANGE_CPU_PARITY original_variables={} prefix_variables={} ranged_variables={} old_tasks={} compact_tasks={} descriptor_count=4 seed_count={} original_plan_ns={} compact_plan_ns={} all_assignment_values_exact=true gpu_supported=false\n", .{ ctx.circuit.n_vars, before, ranged_variables, original.tasks.len, compact.prefix_plan.tasks.len, compact.prefix_plan.seeds.len, original_ns, compact_ns });
}

test "padding range zero length ranges retain exact default plan and no synthetic seeds" {
    const a = std.testing.allocator;
    var ctx = try context(a, false);
    defer ctx.deinit();
    const targets = Finalize.rawComponentSizes(.fromBuilder(&ctx.circuit));
    const provenance = try Padding.Provenance.captureAndPad(&ctx, targets);
    var regular = try Schedule.build(a, &ctx);
    defer regular.deinit();
    var compact = try Padding.Plan.build(a, &ctx, provenance);
    defer compact.deinit();
    for (compact.ranges) |range| try std.testing.expectEqual(@as(u32, 0), range.count);
    try std.testing.expectEqualDeep(regular.tasks, compact.prefix_plan.tasks);
    try std.testing.expectEqualDeep(regular.seeds, compact.prefix_plan.seeds);
    const assignment = try compact.evaluate(a, &ctx);
    defer a.free(assignment);
    try std.testing.expectEqualDeep(ctx.values(), assignment);
}

fn failBuild(a: std.mem.Allocator, ctx: *const C.Context(Q), provenance: Padding.Provenance) !void {
    var compact = try Padding.Plan.build(a, ctx, provenance);
    defer compact.deinit();
}
fn failEvaluate(a: std.mem.Allocator, ctx: *const C.Context(Q), compact: *const Padding.Plan) !void {
    const values = try compact.evaluate(a, ctx);
    defer a.free(values);
}
test "padding range borrowed prefix header and assignment error paths preserve ownership" {
    const a = std.testing.allocator;
    var ctx = try context(a, true);
    defer ctx.deinit();
    const provenance = try Padding.Provenance.captureAndPad(&ctx, Finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    const frozen = fingerprint(&ctx);
    try std.testing.checkAllAllocationFailures(a, failBuild, .{ &ctx, provenance });
    var compact = try Padding.Plan.build(a, &ctx, provenance);
    defer compact.deinit();
    try std.testing.checkAllAllocationFailures(a, failEvaluate, .{ &ctx, &compact });
    try std.testing.expectEqualSlices(u8, &frozen, &fingerprint(&ctx));
    try std.testing.expectEqual(@as(usize, 0), ctx.value_table.items.len);
}
