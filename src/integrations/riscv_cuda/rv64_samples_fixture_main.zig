//! Native point derivation, polynomial evaluation and channel oracle. No proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const IO = @import("rv64/fixture_io.zig");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const Channel = core.channel.raw_mod_m31.Om31Channel;
const Poly = engine.poly.circle.CircleCoefficients;
const a = std.heap.page_allocator;
fn checkpoint(w: anytype, channel: Channel) !void {
    for (0..8) |i| try IO.words(w, &.{std.mem.readInt(u32, channel.inner.digest[i * 4 ..][0..4], .little)});
    try IO.words(w, &.{channel.inner.n_draws});
}
fn fixture(dir: std.fs.Dir, logs: []const u32, id: u32) !void {
    const count: u32 = @intCast(logs.len);
    const terms = count * 2;
    var channel = Channel.init();
    channel.mixU32s(&.{ 0x52565350, 1, id });
    const initial = channel;
    const parameter = channel.drawSecureFelt();
    const base = try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, parameter);
    var rng = std.Random.DefaultPrng.init(0xf33d010 + id);
    var recipes: std.ArrayList(u32) = .empty;
    var sources: std.ArrayList(u32) = .empty;
    var term_descs: std.ArrayList(u32) = .empty;
    var points: std.ArrayList(O) = .empty;
    var factors: std.ArrayList(O) = .empty;
    var values: std.ArrayList(O) = .empty;
    var trees: [4]std.ArrayList(M) = @splat(.empty);
    try points.appendSlice(a, &.{ base.x, base.y });
    const domain = core.poly.circle.canonic.CanonicCoset.new(12).circleDomain();
    for (logs, 0..) |log, gi| {
        const group: u32 = @intCast(gi);
        const offset = domain.at(gi * 173 + 7);
        const folds = group % 5;
        try recipes.appendSlice(a, &.{ offset.x.v, offset.y.v, folds, log });
        const point = base.add(.{ .x = O.fromBase(offset.x), .y = O.fromBase(offset.y) });
        const evaluation_point = point.repeatedDouble(folds);
        try points.appendSlice(a, &.{ point.x, point.y });
        var fs: [28]O = @splat(O.zero());
        fs[0] = evaluation_point.y;
        var x = evaluation_point.x;
        for (1..log) |k| {
            fs[k] = x;
            const square = x.square();
            x = square.add(square).sub(O.one());
        }
        try factors.appendSlice(a, &fs);
        for (0..2) |j| {
            const t = group * 2 + @as(u32, @intCast(j));
            const tree = t % 4;
            const n = @as(usize, 1) << @intCast(log);
            const start = trees[tree].items.len;
            try sources.appendSlice(a, &.{ @intCast(start), 0, tree, log });
            try term_descs.appendSlice(a, &.{ t, group, terms - 1 - t, 0 });
            const coefficients = try a.alloc(M, n);
            defer a.free(coefficients);
            for (coefficients) |*v| v.* = M.fromU64(rng.random().int(u32));
            const poly = try Poly.initBorrowed(coefficients);
            try values.append(a, poly.evalAtPointFor(O, evaluation_point));
            try trees[tree].appendSlice(a, coefficients);
        }
    }
    channel.mixFelts(values.items);
    const alpha = channel.drawSecureFelt();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52565350, 1, count, terms, @intCast(trees[0].items.len), @intCast(trees[1].items.len), @intCast(trees[2].items.len), @intCast(trees[3].items.len) });
    try checkpoint(w, initial);
    try IO.words(w, recipes.items);
    try IO.words(w, sources.items);
    try IO.words(w, term_descs.items);
    for (trees) |tree| for (tree.items) |value| try IO.words(w, &.{value.v});
    try IO.felts(w, &.{parameter});
    try IO.felts(w, points.items);
    try IO.felts(w, factors.items);
    try IO.felts(w, values.items);
    try IO.felts(w, &.{alpha});
    try checkpoint(w, channel);
    try IO.words(w, &.{ 3, 0, 0, 68, 0, 0, 0 });
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = bytes.items });
    std.debug.print("SAMPLES case={} groups={} terms={} max_coefficient_log={} bytes={}\n", .{ id, count, terms, logs[logs.len - 1], bytes.items.len });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    try fixture(dir, &.{ 1, 2, 3, 5, 10, 11 }, 0);
    try fixture(dir, &.{ 12, 17, 22 }, 1);
}
