//! Synthetic seed-program and admission regression ownership.
const std = @import("std");
const Schema = @import("outer_seed_device.zig");
test "seed program: merkle hashes match the domain-prefixed convention" {
    // leaf("") with prefix only differs from node(0,0); both differ from plain.
    const l = Schema.leafHash(&.{});
    const n = Schema.nodeHash(@splat(0), @splat(0));
    try std.testing.expect(!std.mem.eql(u32, &l, &n));
    try std.testing.expect(!std.mem.eql(u32, &l, &Schema.blakeWords(&.{&.{}})));
}

test "seed program: trace.position matches lifting" {
    try std.testing.expectEqual(@as(u32, 5), Schema.position(5, 4, 4));
    // from 5 to 3: drop 2 bits above bit 0
    try std.testing.expectEqual(@as(u32, (0b10110 >> 3) << 1 | 0), Schema.position(0b10110, 5, 3));
}

test "seed program: synthetic children fill, caps verified, negatives fail closed" {
    const t = std.testing;
    const a = t.allocator;
    var c0: Schema.Synthetic = undefined;
    try c0.init(a, 1, 128);
    defer c0.deinit(a);
    var c1: Schema.Synthetic = undefined;
    try c1.init(a, 2, 128);
    defer c1.deinit(a);
    const classes = [_]Schema.ChildClass{
        .{ .shape = c0.shape, .wire_words = 128, .n_outputs = 2, .identity = @splat(7), .fixed_root = @splat(0) },
        .{ .shape = c1.shape, .wire_words = 128, .n_outputs = 2, .identity = @splat(7), .fixed_root = @splat(0) },
    };
    const tape = try Schema.tapeLength(&classes, 3, a);
    const n_const = 5;
    const vars = try a.alloc(u32, tape + n_const);
    defer a.free(vars);
    for (vars, 0..) |*v, i| v.* = @intCast(1000 + i);
    const constants = [_][4]u32{ .{ 1, 2, 3, 4 }, .{ 5, 6, 7, 8 }, .{ 9, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 1, 1, 1, 1 } };
    const prog = try Schema.buildFold(a, &classes, 3, vars, &constants, null);
    defer prog.deinit(a);
    // 2 children x (2 trace trees of height 4 > cap_log 3 + 3 FRI layers of log <= 3, full-path root jobs)
    try t.expectEqual(@as(u32, 10), prog.header(Schema.P.n_caps));
    const scratch = try a.alloc(u32, prog.header(Schema.P.scratch_words) + 8);
    defer a.free(scratch);
    const out = try a.alloc(u32, 5 * vars.len);
    defer a.free(out);
    const regions = [_][]const u32{ c0.region, c1.region };
    try t.expectEqual(@as(u32, 0), Schema.fillHost(prog, &regions, scratch, out));
    for (0..vars.len) |i| try t.expectEqual(vars[i], out[5 * i]);
    try t.expectEqualSlices(u32, &constants[1], out[5 * 1 + 1 ..][0..4]);
    // First tape seeds: child 0 tree-0 root, as 16-bit halves.
    const L = try Schema.Layout.of(c0.shape);
    try t.expectEqual(c0.image[L.roots] & 0xffff, out[5 * n_const + 1]);
    try t.expectEqual(c0.image[L.roots] >> 16, out[5 * (n_const + 1) + 1]);
    // Corrupt one path sibling below the cap: the derived cap no longer
    // hashes to the committed root (or two queries disagree).
    const bad = try a.dupe(u32, c1.region);
    defer a.free(bad);
    const L1 = try Schema.Layout.of(c1.shape);
    bad[128 + L1.trees[0].paths] ^= 1;
    const regions_bad = [_][]const u32{ c0.region, bad };
    const v = Schema.fillHost(prog, &regions_bad, scratch, out);
    try t.expect(v == (@as(u32, 0x0305) << 16 | @intFromEnum(Schema.SeedDetail.cap_mismatch)) or v == (@as(u32, 0x0305) << 16 | @intFromEnum(Schema.SeedDetail.cap_root)));
    // A noncanonical queried value.
    @memcpy(bad, c1.region);
    bad[128 + L1.trees[1].values] = Schema.modulus;
    try t.expectEqual((@as(u32, 0x0305) << 16 | @intFromEnum(Schema.SeedDetail.noncanonical)), Schema.fillHost(prog, &regions_bad, scratch, out));
    // An empty child region (encoder never ran / overrun refused).
    @memcpy(bad, c1.region);
    bad[0] = 0;
    try t.expectEqual((@as(u32, 0x0305) << 16 | @intFromEnum(Schema.SeedDetail.region)), Schema.fillHost(prog, &regions_bad, scratch, out));
    // A bad image header.
    @memcpy(bad, c1.region);
    bad[128] = 0;
    try t.expectEqual((@as(u32, 0x0305) << 16 | @intFromEnum(Schema.SeedDetail.image_header)), Schema.fillHost(prog, &regions_bad, scratch, out));
    // Wrong child count or a corrupted program.
    try t.expectEqual((@as(u32, 0x0305) << 16 | @intFromEnum(Schema.SeedDetail.program)), Schema.fillHost(prog, regions[0..1], scratch, out));
}

test "seed program: caps outside the kernel's fixed arrays are refused" {
    const t = std.testing;
    const ok = Schema.Cap{ .kind = 1, .child = 0, .height = 10, .cl = 3, .values = 0, .width = 8, .paths = 0, .path_stride = 0, .level0 = 0, .root = 0, .scratch = 0, .queries = 0, .nq = 70, .from_log = 0, .to_log = 3, .layer_log = 13, .pack = 0 };
    try t.expect(Schema.capFitsKernel(ok));
    var c = ok;
    c.nq = Schema.kernel_max_queries + 1;
    try t.expect(!Schema.capFitsKernel(c));
    c = ok;
    c.cl = Schema.kernel_max_cap_log + 1;
    c.height = 12;
    try t.expect(!Schema.capFitsKernel(c));
    c = ok;
    c.width = 32;
    c.to_log = 5; // 32 unpacked leaves > level[16]
    try t.expect(!Schema.capFitsKernel(c));
    c.pack = 1; // 8 packed leaves of 4, 3 folds
    try t.expect(Schema.capFitsKernel(c));
    c.to_log = 4; // leaves != 2^(to_log - 2)
    try t.expect(!Schema.capFitsKernel(c));
    c = ok;
    c.kind = 2;
    c.cl = 0;
    c.height = 3;
    c.from_log = 4;
    c.nq = 32;
    try t.expect(Schema.capFitsKernel(c));
    c.nq = 31;
    try t.expect(!Schema.capFitsKernel(c));
    c.nq = 32;
    c.from_log = 0;
    try t.expect(!Schema.capFitsKernel(c));
    var tr = ok;
    tr.kind = 0;
    tr.width = 300; // trace leaves stream their columns: any width
    try t.expect(Schema.capFitsKernel(tr));
}

test "seed program: short FRI gather owns coordinate order and clears unseen groups" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |sparse| {
        var draws: [32]u32 = undefined;
        for (&draws, 0..) |*q, i| q.* = if (sparse) 5 else @intCast(i % 16);
        var child: Schema.Synthetic = undefined;
        try child.initQueries(a, 531, 128, &draws);
        defer child.deinit(a);
        const cls = Schema.ChildClass{ .shape = child.shape, .wire_words = 128, .n_outputs = 2, .identity = @splat(7), .fixed_root = @splat(0) };
        const tape = try Schema.leafTapeLength(a, cls, 0);
        const vars = try a.alloc(u32, tape);
        defer a.free(vars);
        for (vars, 0..) |*v, i| v.* = @intCast(i);
        const prog = try Schema.buildLeaf(a, cls, 0, 0, vars, &.{}, null);
        defer prog.deinit(a);
        const scratch = try a.alloc(u32, prog.header(Schema.P.scratch_words) + 8);
        defer a.free(scratch);
        @memset(scratch, 0xabababab);
        const out = try a.alloc(u32, 5 * vars.len);
        defer a.free(out);
        try std.testing.expectEqual(0, Schema.fillHost(prog, &.{child.region}, scratch, out));
        var grouped: usize = 0;
        for (prog.caps()) |c| if (c.kind == 2) {
            grouped += 1;
            const slots = @as(usize, 1) << @intCast(c.height);
            const row = c.width * 8;
            const paths = c.scratch + slots * row;
            for (0..slots) |group| {
                const q: ?usize = for (draws, 0..) |pos, j| {
                    if ((pos >> @intCast(c.from_log + c.to_log)) == group) break j;
                } else null;
                const vv = scratch[c.scratch + group * row ..][0..row];
                const pp = scratch[paths + group * c.height * 8 ..][0 .. c.height * 8];
                if (q) |j| {
                    try std.testing.expectEqualSlices(u32, child.image[c.values + j * row ..][0..row], vv);
                    try std.testing.expectEqualSlices(u32, child.image[c.paths + j * c.path_stride ..][0..pp.len], pp);
                } else {
                    try std.testing.expect(std.mem.allEqual(u32, vv, 0));
                    try std.testing.expect(std.mem.allEqual(u32, pp, 0));
                }
            }
        };
        try std.testing.expectEqual(2, grouped);
        const bad = prog.caps()[prog.caps().len - 1];
        child.region[128 + bad.values] = Schema.modulus;
        try std.testing.expectEqual((@as(u32, 0x0305) << 16) | @intFromEnum(Schema.SeedDetail.noncanonical), Schema.fillHost(prog, &.{child.region}, scratch, out));
    }
}

test "seed program: a sparse depth-four frontier binds every upper sibling" {
    const a = std.testing.allocator;
    const draws = [_]u32{63} ** 54;
    var child: Schema.Synthetic = undefined;
    try child.initAtDegree(a, 539, 128, &draws, 5);
    defer child.deinit(a);
    const cls = Schema.ChildClass{ .shape = child.shape, .wire_words = 128, .n_outputs = 2, .identity = @splat(7), .fixed_root = @splat(0) };
    const vars = try a.alloc(u32, try Schema.leafTapeLength(a, cls, 4));
    defer a.free(vars);
    for (vars, 0..) |*v, i| v.* = @intCast(i);
    const prog = try Schema.buildLeaf(a, cls, 4, 0, vars, &.{}, null);
    defer prog.deinit(a);
    const scratch = try a.alloc(u32, prog.header(Schema.P.scratch_words) + 8);
    defer a.free(scratch);
    const out = try a.alloc(u32, 5 * vars.len);
    defer a.free(out);
    @memset(scratch, 0xabababab);
    try std.testing.expectEqual(0, Schema.fillHost(prog, &.{child.region}, scratch, out));
    const cap = prog.caps()[0];
    try std.testing.expectEqual(4, cap.cl);
    // Only the leftmost slot of the wholly untouched left half holds its digest.
    try std.testing.expect(std.mem.allEqual(u32, scratch[cap.scratch + 8 ..][0 .. 7 * 8], 0));
    const last = 128 + cap.paths + cap.path_stride + (cap.height - 1) * 8;
    child.region[last] ^= 1;
    try std.testing.expect(Schema.fillHost(prog, &.{child.region}, scratch, out) != 0);
}
