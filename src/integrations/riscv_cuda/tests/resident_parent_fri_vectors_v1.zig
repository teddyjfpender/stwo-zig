//! CPU differential vectors only. Never imported by the resident prover.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
fn word(f: std.fs.File, n: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, n, .little);
    try f.writeAll(&b);
}
fn secure(f: std.fs.File, q: Q) !void {
    for (q.toM31Array()) |v| try word(f, v.v);
}
fn randomQ(rng: std.Random) Q {
    var x: [4]M = undefined;
    for (&x) |*v| v.* = M.fromCanonical(rng.uintLessThan(u32, core.fields.m31.Modulus));
    return Q.fromM31Array(x);
}
pub fn main() !void {
    const a = std.heap.page_allocator;
    const args = try std.process.argsAlloc(a);
    if (args.len != 2) return error.ExpectedOutput;
    const file = try std.fs.cwd().createFile(args[1], .{});
    defer file.close();
    try word(file, 0x46524932);
    try word(file, 30);
    var rng_state = std.Random.DefaultPrng.init(0x987643ff);
    const rng = rng_state.random();
    for ([_]u32{ 7, 13, 20 }) |initial_log| for (1..6) |step_usize| for ([_]u32{ 70, 128 }) |nq| {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const alloc = arena.allocator();
        const step: u32 = @intCast(step_usize);
        const layers = @min(@as(u32, 3), (initial_log - 1) / step);
        const raw = try alloc.alloc(usize, nq);
        const answers = try alloc.alloc(Q, nq);
        for (raw, 0..) |*p, i| {
            p.* = rng.uintLessThan(u32, @as(u32, 1) << @intCast(initial_log));
            if (i % 7 == 0 and i > 0) p.* = raw[0];
            answers[i] = randomQ(rng);
            for (raw[0..i], 0..) |prior, j| if (prior == p.*) {
                answers[i] = answers[j];
                break;
            };
        }
        try word(file, 0x42374652);
        try word(file, nq);
        try word(file, layers);
        try word(file, initial_log);
        for (raw) |p| try word(file, @intCast(p));
        for (answers) |q| try secure(file, q);
        var queries = try core.queries.Queries.init(alloc, raw, initial_log);
        var known = try alloc.alloc(Q, queries.positions.len);
        for (queries.positions, known) |p, *v| for (raw, answers) |r, q| if (r == p) {
            v.* = q;
            break;
        };
        var shift: u32 = 0;
        for (0..layers) |layer| {
            const width = @as(usize, 1) << @intCast(step);
            const witness = try alloc.alloc(Q, nq * width);
            for (witness) |*v| v.* = randomQ(rng);
            var rebuilt = try core.fri.computeDecommitmentPositionsAndRebuildEvals(alloc, queries, known, witness, step);
            defer rebuilt.deinit(alloc);
            const alpha = randomQ(rng);
            try word(file, @intCast(width));
            try word(file, @intCast(rebuilt.consumed_witness));
            try word(file, @intCast(nq * width));
            try secure(file, alpha);
            for (witness[0..rebuilt.consumed_witness]) |q| try secure(file, q);
            for (raw) |p| {
                const group = (p >> @intCast(shift)) >> @intCast(step);
                var gi: usize = 0;
                var prev: ?usize = null;
                for (queries.positions) |position| {
                    const g = position >> @intCast(step);
                    if (prev != null and prev.? == g) continue;
                    if (g == group) break;
                    gi += 1;
                    prev = g;
                }
                for (rebuilt.sparse_evaluation.subset_evals[gi]) |q| try secure(file, q);
            }
            known = if (layer == 0) try rebuilt.sparse_evaluation.foldCircleSubsets(alloc, alpha, core.poly.circle.CanonicCoset.new(queries.log_domain_size).circleDomain(), step) else try rebuilt.sparse_evaluation.foldLineSubsetsN(alloc, alpha, core.poly.line.LineDomain.fromCircleDomain(core.poly.circle.CanonicCoset.new(queries.log_domain_size + 1).circleDomain()), step);
            queries = try queries.fold(alloc, step);
            shift += step;
        }
    };
}
