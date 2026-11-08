//! Native local and manifest-claim closure oracles, not physical proof inputs.
const std = @import("std");
const core = @import("stwo_core");
const Authority = @import("stwo_riscv_cpu_integration").rv64_gkr_constraints;
const IO = @import("rv64/fixture_io.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const a = std.heap.page_allocator;
fn random(rng: std.Random) O {
    var words: [8]M = undefined;
    for (&words) |*v| v.* = M.fromCanonical(rng.uintLessThan(u32, core.fields.m31.Modulus));
    return O.fromM31Array(words);
}
fn file(dir: std.fs.Dir, id: u32, mode: u32, count: u32, initial: u32, expected: u32, values: []const O, masks: []const u32) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x5256434c, 1, id, mode, count, initial, expected });
    try IO.felts(w, values);
    try IO.words(w, masks);
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = bytes.items });
}
fn local(dir: std.fs.Dir, id: u32, count: u32, attack: u32) !void {
    var rng = std.Random.DefaultPrng.init(0x726748 + id);
    const roots = try a.alloc(O, 2 * count);
    defer a.free(roots);
    var sum = O.zero();
    for (0..count) |i| {
        const value = if (i + 1 == count) sum.neg() else random(rng.random());
        const denominator = random(rng.random());
        roots[2 * i] = value.mul(denominator);
        roots[2 * i + 1] = denominator;
        sum = sum.add(value);
    }
    var expected: u32 = 0;
    if (attack == 1) {
        roots[0] = O.zero();
        roots[1] = O.zero();
        expected = 4;
    }
    if (attack == 2) {
        roots[0] = roots[0].add(roots[1]);
        expected = 8;
    }
    const pairs = try a.alloc([]const O, count);
    defer a.free(pairs);
    for (pairs, 0..) |*p, i| p.* = roots[2 * i ..][0..2];
    if (Authority.LocalClosure.close(a, pairs)) |_| {
        if (expected != 0) return error.NativeLocalMutationAccepted;
    } else |err| {
        if (expected == 0) return err;
        if (attack == 1 and err != error.LocalGkrPole) return err;
        if (attack == 2 and err != error.UnclosedLocalGkr) return err;
    }
    const initial: u32 = if (attack == 3) 0x40000000 else 0;
    try file(dir, id, 0, count, initial, initial | expected, roots, &.{});
}
fn global(dir: std.fs.Dir, id: u32, count: u32, attack: u32) !void {
    const Manifest = Authority.Manifest;
    var rng = std.Random.DefaultPrng.init(0x722251 + id);
    const values = try a.alloc(O, 3 * count);
    defer a.free(values);
    const claims = try a.alloc(Manifest.Claims, count);
    defer a.free(claims);
    const masks = try a.alloc(u32, count);
    defer a.free(masks);
    const entries = try a.alloc(Manifest.Entry, count);
    defer a.free(entries);
    var sums: [3]O = @splat(O.zero());
    for (0..count) |i| {
        masks[i] = if (i == 0 or i + 1 == count) 7 else @intCast(i % 8);
        for (0..3) |j| {
            const v = if (i + 1 == count) sums[j].neg() else if (masks[i] & (@as(u32, 1) << @as(u5, @intCast(j))) != 0) random(rng.random()) else O.zero();
            values[3 * i + j] = v;
            sums[j] = sums[j].add(v);
        }
    }
    var expected: u32 = 0;
    if (attack == 1) {
        values[0] = O.one();
        values[1] = O.one().neg();
        values[2] = O.zero();
        expected = 16 | 32;
    }
    if (attack == 2) {
        masks[0] = 0;
        for (values) |*v| v.* = O.zero();
        values[0] = O.one();
        values[3] = O.one().neg();
        expected = 128;
    }
    if (attack == 3) {
        values[0] = values[0].add(O.one());
        expected = 16;
    }
    for (claims, entries, 0..) |*claim, *entry, i| {
        claim.* = .{ .ram = values[3 * i], .kio = values[3 * i + 1], .wire = values[3 * i + 2] };
        entry.* = undefined;
        entry.global_relations = .{ .ram = masks[i] & 1 != 0, .kio = masks[i] & 2 != 0, .wire = masks[i] & 4 != 0 };
    }
    var manifest: Manifest.PendingManifest = undefined;
    manifest.entries = entries;
    if (manifest.checkGlobalClosure(claims)) |_| {
        if (expected != 0) return error.NativeGlobalMutationAccepted;
    } else |err| {
        if (expected == 0) return err;
        if (attack == 2 and err != error.NonzeroAbsentGlobalGkrClaim) return err;
        if ((attack == 1 or attack == 3) and err != error.UnclosedGlobalGkrRam) return err;
    }
    const initial: u32 = if (attack == 4) 0x40000000 else 0;
    try file(dir, id, 1, count, initial, initial | expected, values, masks);
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    var id: u32 = 0;
    for ([_]u32{ 1, 2, 3, 64 }) |count| {
        try local(dir, id, count, 0);
        id += 1;
    }
    for ([_]u32{ 1, 2, 3 }) |attack| {
        try local(dir, id, 3, attack);
        id += 1;
    }
    for ([_]u32{ 1, 2, 18, 65535 }) |count| {
        try global(dir, id, count, 0);
        id += 1;
    }
    try global(dir, id, 1, 1);
    id += 1;
    try global(dir, id, 2, 2);
    id += 1;
    try global(dir, id, 18, 3);
    id += 1;
    try global(dir, id, 18, 4);
    id += 1;
    std.debug.print("PASS native local/manifest closure fixtures={}\n", .{id});
}
