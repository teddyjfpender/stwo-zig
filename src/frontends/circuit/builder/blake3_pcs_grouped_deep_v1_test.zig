//! Independent native oracle, unchanged per-response control, grouped Context.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("mod.zig");
const grouped = @import("blake3_pcs_grouped_deep_v1.zig");
const pcs = @import("blake3_pcs_reuse_v1.zig");
const common = @import("../common/mod.zig");
const Q = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const Point = core.circle.CirclePointQM31;
const M = b.wrappers.M31Wrapper(b.Var);
const a = std.testing.allocator;
const current = [_]pcs.Mask{.{ .row_log = 4, .offset = 0 }};
const previous = [_]pcs.Mask{ .{ .row_log = 4, .offset = 0 }, .{ .row_log = 4, .offset = -1 } };
const final = [_]pcs.Mask{ .{ .row_log = 4, .offset = 0 }, .{ .row_log = 4, .offset = 27 } };
const double_step = [_]pcs.Mask{ .{ .row_log = 4, .offset = 0 }, .{ .row_log = 4, .offset = 2 } };
const equivalent = [_]pcs.Mask{ .{ .row_log = 3, .offset = 0 }, .{ .row_log = 3, .offset = 1 } };
const reversed = [_]pcs.Mask{ .{ .row_log = 4, .offset = -1 }, .{ .row_log = 4, .offset = 0 } };
const triple = [_]pcs.Mask{ .{ .row_log = 4, .offset = 0 }, .{ .row_log = 4, .offset = -1 }, .{ .row_log = 4, .offset = 1 } };
const wide = [_]pcs.Mask{ .{ .row_log = 4, .offset = 0 }, .{ .row_log = 4, .offset = -2 }, .{ .row_log = 4, .offset = -1 }, .{ .row_log = 4, .offset = 1 }, .{ .row_log = 4, .offset = 2 }, .{ .row_log = 4, .offset = 27 } };
const trees = [_]pcs.Tree{
    .{ .columns = &.{ .{ .log_size = 4, .masks = &current }, .{ .log_size = 4, .masks = &previous }, .{ .log_size = 3, .masks = &previous } } },
    .{ .columns = &.{} },
    .{ .columns = &.{ .{ .log_size = 2, .masks = &final }, .{ .log_size = 4, .masks = &double_step }, .{ .log_size = 4, .masks = &equivalent }, .{ .log_size = 3, .masks = &reversed }, .{ .log_size = 4, .masks = &triple }, .{ .log_size = 3, .masks = &wide } } },
};
const queries = [_]usize{ 0, 3, 3, 7, 1, 16, 17, 31 };
fn geometry() pcs.Geometry {
    return .{ .config = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = queries.len, .fold_step = 1 } }, .trees = &trees };
}
fn shifted(point: Point, mask: pcs.Mask) Point {
    if (mask.offset == 0) return point;
    const offset = core.poly.circle.canonic.CanonicCoset.new(mask.row_log).step().mulSigned(mask.offset);
    return point.add(.{ .x = Q.fromBase(offset.x), .y = Q.fromBase(offset.y) });
}
const Fixture = struct {
    point: Point,
    beta: Q,
    points: core.pcs.TreeVec([][]Point),
    samples: core.pcs.TreeVec([][]Q),
    logs: core.pcs.TreeVec([]u32),
    values: core.pcs.TreeVec([][]M31),
    expected: []Q,
    fn init(t: std.mem.Allocator) !Fixture {
        const g = geometry();
        const seed = Q.fromU32Unchecked(7, 9, 3, 1);
        const seed2 = seed.mul(seed);
        const inverse = try Q.one().add(seed2).inv();
        const point = Point{ .x = Q.one().sub(seed2).mul(inverse), .y = seed.add(seed).mul(inverse) };
        const beta = Q.fromU32Unchecked(13, 2, 5, 8);
        const points = try t.alloc([][]Point, g.trees.len);
        const samples = try t.alloc([][]Q, g.trees.len);
        const logs = try t.alloc([]u32, g.trees.len);
        const values = try t.alloc([][]M31, g.trees.len);
        var ordinal: u32 = 1;
        for (g.trees, points, samples, logs, values) |tree, *ps, *ss, *ls, *vs| {
            ps.* = try t.alloc([]Point, tree.columns.len);
            ss.* = try t.alloc([]Q, tree.columns.len);
            ls.* = try t.alloc(u32, tree.columns.len);
            vs.* = try t.alloc([]M31, tree.columns.len);
            for (tree.columns, ps.*, ss.*, ls.*, vs.*) |column, *p, *s, *l, *v| {
                p.* = try t.alloc(Point, column.masks.len);
                s.* = try t.alloc(Q, column.masks.len);
                l.* = column.log_size + g.config.fri_config.log_blowup_factor;
                v.* = try t.alloc(M31, queries.len);
                for (p.*, s.*, column.masks) |*sample_point, *sample, mask| {
                    sample_point.* = shifted(point, mask);
                    sample.* = Q.fromU32Unchecked(3 * ordinal + 1, ordinal + 2, ordinal * 7, ordinal + 11);
                    ordinal += 1;
                }
                for (v.*, 0..) |*value, q| value.* = M31.fromCanonical(ordinal * 31 + @as(u32, @intCast(queries[q] * 13)));
            }
        }
        const expected = try core.pcs.quotients.friAnswers(t, .{ .items = logs }, .{ .items = points }, .{ .items = samples }, beta, &queries, .{ .items = values }, (try g.friGeometry()).startLog());
        return .{ .point = point, .beta = beta, .points = .{ .items = points }, .samples = .{ .items = samples }, .logs = .{ .items = logs }, .values = .{ .items = values }, .expected = expected };
    }
};
const Wires = struct { proof: pcs.Proof, oods: pcs.Oods, beta: b.Var, queries: []M };
fn wires(comptime V: type, ctx: *b.Context(V), fixture: Fixture) !Wires {
    const samples = try ctx.scratch().alloc(b.Var, geometry().sampleCount());
    var index: usize = 0;
    for (fixture.samples.items) |tree| for (tree) |column| for (column) |value| {
        samples[index] = try ctx.guess(b.ivalue.fromQm31(V, value));
        index += 1;
    };
    const traces = try ctx.scratch().alloc(pcs.Trace, fixture.values.items.len);
    for (traces, fixture.values.items) |*trace, tree| {
        const values = try ctx.scratch().alloc(M, tree.len * queries.len);
        for (tree, 0..) |column, c| for (column, 0..) |value, q| {
            values[c * queries.len + q] = try b.wrappers.guessM31(V, ctx, b.wrappers.m31Value(V, value));
        };
        trace.* = .{ .values = values, .paths = &.{} };
    }
    const qs = try ctx.scratch().alloc(M, queries.len);
    for (qs, queries) |*query, value| query.* = try b.wrappers.guessM31(V, ctx, b.wrappers.m31Value(V, M31.fromCanonical(@intCast(value))));
    return .{ .proof = .{ .roots = &.{}, .sampled_values = samples, .trace = traces, .nonce = .{ .newUnsafe(ctx.zero()), .newUnsafe(ctx.zero()) }, .fri_proof = .{ .layers = &.{}, .last_coefs = &.{} } }, .oods = .{ .seed = ctx.zero(), .point = .{ .x = try ctx.guess(b.ivalue.fromQm31(V, fixture.point.x)), .y = try ctx.guess(b.ivalue.fromQm31(V, fixture.point.y)) } }, .beta = try ctx.guess(b.ivalue.fromQm31(V, fixture.beta)), .queries = qs };
}
fn run(comptime V: type, comptime use_grouped: bool, ctx: *b.Context(V), fixture: Fixture) ![]b.Var {
    const input = try wires(V, ctx, fixture);
    const answers = if (use_grouped) try grouped.deepAnswers(V, ctx, geometry(), input.proof, input.oods, input.beta, input.queries) else try pcs.deepAnswers(V, ctx, geometry(), input.proof, input.oods, input.beta, input.queries);
    for (answers, fixture.expected) |answer, expected| {
        try ctx.eq(answer, try ctx.constant(expected));
        if (V == Q) try std.testing.expectEqualDeep(expected, ctx.get(answer));
    }
    return answers;
}
fn finish(comptime V: type, ctx: *b.Context(V)) !void {
    try ctx.finalize(true);
    const targets = common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit));
    try common.finalize.padToTargets(V, ctx, targets);
    var preprocessed = try common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer preprocessed.deinit(a);
    if (V == Q) try std.testing.expect(try ctx.isCircuitValid());
}

test "RISC direct original grouped DEEP geometry preserves native response ordinals and point batches" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const fixture = try Fixture.init(arena.allocator());
    var plan = try grouped.Plan.init(a, geometry());
    defer plan.deinit();
    const native = try core.pcs.quotients.buildColumnSampleBatchesFromParallelInputs(arena.allocator(), fixture.points, fixture.samples, fixture.logs, (try geometry().friGeometry()).startLog(), fixture.beta);
    try std.testing.expectEqual(@as(usize, 28), plan.response_count);
    try std.testing.expectEqual(native.len, plan.groups.len);
    try std.testing.expect(plan.groups.len < plan.response_count);
    try std.testing.expectEqualDeep(fixture.expected[1], fixture.expected[2]);
    var equivalent_found = false;
    for (plan.groups) |group| {
        var first = false;
        var second = false;
        for (group.terms) |term| {
            first = first or (term.tree == 2 and term.column == 1 and term.sample == 8);
            second = second or (term.tree == 2 and term.column == 2 and term.sample == 10);
        }
        equivalent_found = equivalent_found or (first and second);
    }
    try std.testing.expect(equivalent_found);
    const powers = try arena.allocator().alloc(Q, plan.response_count);
    powers[0] = Q.one();
    for (powers[1..], 1..) |*power, i| power.* = powers[i - 1].mul(fixture.beta);
    const seen = try arena.allocator().alloc(bool, plan.response_count);
    @memset(seen, false);
    for (plan.groups, native) |shape, batch| {
        const point = fixture.point.add(.{ .x = Q.fromBase(shape.offset.x), .y = Q.fromBase(shape.offset.y) });
        try std.testing.expect(point.eql(batch.point));
        try std.testing.expectEqual(shape.terms.len, batch.cols_vals_randpows.len);
        for (shape.terms, batch.cols_vals_randpows) |term, original| {
            try std.testing.expect(!seen[term.response]);
            seen[term.response] = true;
            try std.testing.expectEqualDeep(powers[term.response], original.random_coeff);
            var flat_column: usize = term.column;
            for (geometry().trees[0..term.tree]) |tree| flat_column += tree.columns.len;
            try std.testing.expectEqual(flat_column, original.column_index);
        }
    }
    for (seen) |present| try std.testing.expect(present);
}

test "RISC direct original grouped DEEP native old grouped all answers and strict NoValue preprocessing agree" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const fixture = try Fixture.init(arena.allocator());
    var old = try b.Context(Q).init(a, 0);
    defer old.deinit();
    var values = try b.Context(Q).init(a, 0);
    defer values.deinit();
    var topology = try b.Context(b.NoValue).init(a, 0);
    defer topology.deinit();
    _ = try run(Q, false, &old, fixture);
    const answers = try run(Q, true, &values, fixture);
    _ = try run(b.NoValue, true, &topology, fixture);
    var plan = try grouped.Plan.init(a, geometry());
    defer plan.deinit();
    try std.testing.expectEqual(plan.response_count * queries.len, old.stats.div);
    try std.testing.expectEqual(@as(usize, 0), values.stats.div);
    try std.testing.expectEqual(plan.groups.len * (queries.len + 1), values.stats.inv);
    try finish(Q, &old);
    try finish(Q, &values);
    try finish(b.NoValue, &topology);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    inline for (.{ "add", "sub", "mul", "pointwise_mul", "eq", "blake_g_gate", "triple_xor", "m31_to_u32", "output" }) |field| try std.testing.expectEqualDeep(@field(values.circuit, field).items, @field(topology.circuit, field).items);
    const previous_value = values.value_table.items[answers[0].idx];
    values.value_table.items[answers[0].idx] = previous_value.add(Q.one());
    try std.testing.expect(!try values.isCircuitValid());
    values.value_table.items[answers[0].idx] = previous_value;
    try std.testing.expect(try values.isCircuitValid());
}

test "RISC direct original grouped DEEP rejects native degenerate sample line before inverse witness" {
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    const g = pcs.Geometry{ .config = geometry().config, .trees = &.{.{ .columns = &.{.{ .log_size = 4, .masks = &current }} }} };
    const point = Point{ .x = Q.one(), .y = Q.zero() };
    try std.testing.expectError(error.DegenerateLine, core.constraints.complexConjugateLineCoeffs(point, Q.one(), Q.one()));
    const proof = pcs.Proof{ .roots = &.{}, .sampled_values = &.{try ctx.guess(Q.one())}, .trace = &.{}, .nonce = .{ .newUnsafe(ctx.zero()), .newUnsafe(ctx.zero()) }, .fri_proof = .{ .layers = &.{}, .last_coefs = &.{} } };
    try std.testing.expectError(error.DegenerateLine, grouped.responses(Q, &ctx, g, proof, .{ .seed = ctx.zero(), .point = .{ .x = ctx.one(), .y = ctx.zero() } }, ctx.one()));
}

test "RISC direct original grouped DEEP rejects zero query denominator with native semantics" {
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    var g = pcs.Geometry{ .config = geometry().config, .trees = &.{.{ .columns = &.{.{ .log_size = 4, .masks = &current }} }} };
    g.config.fri_config.n_queries = 1;
    const domain_point = core.poly.circle.canonic.CanonicCoset.new((try g.friGeometry()).startLog()).circleDomain().at(0);
    // A deliberately invalid borrowed point: the complete PCS adapter derives
    // a circle point itself, but this arithmetic helper still fails closed.
    const point = Point{ .x = Q.fromBase(domain_point.x), .y = Q.fromU32Unchecked(0, 0, 1, 0) };
    try std.testing.expectError(error.DivisionByZero, core.pcs.quotients.denominatorInverses(a, &.{point}, domain_point));
    const value = try b.wrappers.guessM31(Q, &ctx, b.wrappers.m31Value(Q, M31.fromCanonical(7)));
    const query = try b.wrappers.guessM31(Q, &ctx, b.wrappers.m31Value(Q, M31.zero()));
    const proof = pcs.Proof{ .roots = &.{}, .sampled_values = &.{try ctx.guess(Q.one())}, .trace = &.{.{ .values = &.{value}, .paths = &.{} }}, .nonce = .{ .newUnsafe(ctx.zero()), .newUnsafe(ctx.zero()) }, .fri_proof = .{ .layers = &.{}, .last_coefs = &.{} } };
    const oods = pcs.Oods{ .seed = ctx.zero(), .point = .{ .x = try ctx.constant(point.x), .y = try ctx.constant(point.y) } };
    try std.testing.expectError(error.DivisionByZero, grouped.deepAnswers(Q, &ctx, g, proof, oods, ctx.one(), &.{query}));
}
