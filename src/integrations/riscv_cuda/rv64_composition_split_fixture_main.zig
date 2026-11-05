//! Native coefficient oracle for composition interpolation and recursive split.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const IO = @import("rv64/fixture_io.zig");
const M = core.fields.m31.M31;
const a = std.heap.page_allocator;
fn fixture(dir: std.fs.Dir, id: u32, log: u32, depth: u32, coordinates: u32) !void {
    const n = @as(usize, 1) << @intCast(log);
    const chunks = @as(usize, 1) << @intCast(depth);
    const chunk_rows = n / chunks;
    const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
    defer engine.poly.twiddles.deinitM31(a, &tw);
    const coefficients = try a.alloc(M, n * coordinates);
    defer a.free(coefficients);
    var rng = std.Random.DefaultPrng.init(0x329af + id);
    for (coefficients) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, core.fields.m31.Modulus));
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52565350, 1, id, log, depth, coordinates, @intCast(tw.itwiddles.len), 0 });
    for (0..coordinates) |c| {
        const poly = try engine.poly.circle.CircleCoefficients.initBorrowed(coefficients[c * n ..][0..n]);
        const eval = try poly.evaluate(a, domain);
        defer a.free(eval.values);
        for (eval.values) |v| try IO.words(w, &.{v.v});
    }
    for (tw.itwiddles) |v| try IO.words(w, &.{v.v});
    // The verifier's recursive reconstruction requires chunk-major order.
    for (0..chunks) |chunk| for (0..coordinates) |c| {
        for (coefficients[c * n + chunk * chunk_rows ..][0..chunk_rows]) |v| try IO.words(w, &.{v.v});
    };
    const filename = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(filename);
    try dir.writeFile(.{ .sub_path = filename, .data = bytes.items });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    var id: u32 = 0;
    for ([_]u32{ 4, 8 }) |coordinates| for ([_]u32{ 3, 5, 13, 17 }) |log| for ([_]u32{ 1, 2 }) |depth| {
        if (log <= depth + 1) continue;
        try fixture(dir, id, log, depth, coordinates);
        id += 1;
    };
    std.debug.print("PASS native composition split fixtures={}\n", .{id});
}
