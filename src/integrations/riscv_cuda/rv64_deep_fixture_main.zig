//! Cold native PCS oracle. All expectations come from core/prover authorities.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const IO = @import("rv64/fixture_io.zig");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const Q = core.pcs.ForField(O).quotients;
const Poly = engine.poly.circle.CircleCoefficients;
const Canonic = core.poly.circle.canonic.CanonicCoset;
const a = std.heap.page_allocator;
fn random(r: std.Random) O {
    var limbs: [8]M = undefined;
    for (&limbs) |*v| v.* = M.fromU64(r.int(u32));
    return O.fromM31Array(limbs);
}
fn bases(w: anytype, values: []const M) !void {
    for (values) |v| try IO.words(w, &.{v.v});
}
fn fixture(dir: std.fs.Dir, count: u32, id: u32) !void {
    const terms = count * 2;
    const output_log: u32 = if (id == 3) 17 else 11;
    const rows = @as(usize, 1) << @intCast(output_log);
    var rng = std.Random.DefaultPrng.init(0xd33f101 + id);
    const alpha = random(rng.random());
    const batches = try a.alloc(Q.ColumnSampleBatch, count);
    const coefficients = try a.alloc([]M, terms);
    const evaluations = try a.alloc([]const M, terms);
    var source_words: std.ArrayList(u32) = .empty;
    var group_words: std.ArrayList(u32) = .empty;
    var term_words: std.ArrayList(u32) = .empty;
    var tree: std.ArrayList(M) = .empty;
    var twiddle_words: std.ArrayList(M) = .empty;
    var coefficient_words: u32 = 0;
    var evaluation_words: u32 = 0;
    var values: std.ArrayList(O) = .empty;
    for (batches, 0..) |*batch, gi| {
        const g: u32 = @intCast(gi);
        const coefficient_log: u32 = if (id == 3) 12 + g % 3 else 5 + g % 4;
        const evaluation_log = coefficient_log + 2;
        const n = @as(usize, 1) << @intCast(coefficient_log);
        const point = try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, random(rng.random()));
        const members = try a.alloc(Q.NumeratorData, 2);
        batch.* = .{ .point = point, .cols_vals_randpows = members };
        try group_words.appendSlice(a, &.{ g * 2, g * 2 + 2, coefficient_log, evaluation_log, coefficient_words, 0, evaluation_words, 0 });
        coefficient_words += @intCast(n * 8);
        evaluation_words += @as(u32, 8) << @intCast(evaluation_log);
        const domain = Canonic.new(evaluation_log).circleDomain();
        var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
        defer engine.poly.twiddles.deinitM31(a, &twiddles);
        try twiddle_words.appendSlice(a, twiddles.twiddles);
        for (members, 0..) |*member, j| {
            const t: u32 = g * 2 + @as(u32, @intCast(j));
            const coeff = try a.alloc(M, n);
            for (coeff) |*v| v.* = M.fromU64(rng.random().int(u32));
            coefficients[t] = coeff;
            try source_words.appendSlice(a, &.{ @intCast(tree.items.len), 0, 0, coefficient_log });
            try tree.appendSlice(a, coeff);
            try term_words.appendSlice(a, &.{ t, g, terms - 1 - t, 0 });
            const poly = try Poly.initBorrowed(coeff);
            const sample = poly.evalAtPointFor(O, point);
            try values.append(a, sample);
            member.* = .{ .column_index = t, .sample_value = sample, .random_coeff = alpha.pow(terms - 1 - t) };
            const evaluated = try poly.evaluate(a, domain);
            evaluations[t] = evaluated.values;
        }
    }
    var constants = try Q.quotientConstants(a, batches);
    defer constants.deinit(a);
    var bytes: std.ArrayList(u8) = .empty;
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52564450, 1, count, terms, terms, output_log, @intCast(tree.items.len), coefficient_words, evaluation_words, @intCast(twiddle_words.items.len) });
    try IO.words(w, source_words.items);
    try IO.words(w, term_words.items);
    try IO.words(w, group_words.items);
    try bases(w, tree.items);
    for (batches) |batch| try IO.felts(w, &.{ batch.point.x, batch.point.y });
    try IO.felts(w, values.items);
    try IO.felts(w, &.{alpha});
    for (constants.line_coeffs) |lines| for (lines) |line| try IO.felts(w, &.{line.c});
    for (constants.line_coeffs) |lines| {
        var sum_a = O.zero();
        var sum_b = O.zero();
        for (lines) |line| {
            sum_a = sum_a.add(line.a);
            sum_b = sum_b.add(line.b);
        }
        try IO.felts(w, &.{ sum_a, sum_b });
    }
    var expected_coefficients: std.ArrayList(M) = .empty;
    var expected_evaluations: std.ArrayList(M) = .empty;
    for (batches, constants.line_coeffs) |batch, lines| {
        const first = batch.cols_vals_randpows[0].column_index;
        const n = coefficients[first].len;
        const log: u32 = @intCast(std.math.log2_int(usize, n) + 2);
        for (0..8) |c| {
            const plane = try a.alloc(M, n);
            for (plane, 0..) |*v, row| v.* = lines[0].c.toM31Array()[c].mul(coefficients[first][row]).add(lines[1].c.toM31Array()[c].mul(coefficients[first + 1][row]));
            try expected_coefficients.appendSlice(a, plane);
            const poly = try Poly.initBorrowed(plane);
            const evaluated = try poly.evaluate(a, Canonic.new(log).circleDomain());
            try expected_evaluations.appendSlice(a, evaluated.values);
        }
    }
    try bases(w, expected_coefficients.items);
    try bases(w, expected_evaluations.items);
    const domain = Canonic.new(output_log).circleDomain();
    const expected = try a.alloc(O, rows);
    const row_values = try a.alloc(M, terms);
    var workspace = try Q.RowQuotientWorkspace.init(a, batches);
    defer workspace.deinit(a);
    for (0..rows) |row| {
        const point = domain.at(core.utils.bitReverseIndex(row, output_log));
        try IO.words(w, &.{ point.x.v, point.y.v });
        for (evaluations, 0..) |evaluation, t| {
            const diff: u6 = @intCast(output_log - std.math.log2_int(usize, evaluation.len));
            const index = ((row >> (diff + 1)) << 1) + (row & 1);
            row_values[t] = evaluation[index];
        }
        expected[row] = try Q.accumulateRowQuotientsWithWorkspace(batches, row_values, &constants, point, &workspace);
    }
    try IO.soa(w, expected);
    try bases(w, twiddle_words.items);
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    try dir.writeFile(.{ .sub_path = name, .data = bytes.items });
    std.debug.print("DEEP case={} groups={} terms={} rows={} coefficient_cells={} evaluation_cells={}\n", .{ id, count, terms, rows, coefficient_words, evaluation_words });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    for ([_]u32{ 1, 3, 10, 3 }, 0..) |count, id| try fixture(dir, count, @intCast(id));
}
