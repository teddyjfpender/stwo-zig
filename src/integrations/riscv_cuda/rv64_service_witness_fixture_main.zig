//! Native row authority versus compact records consumed by service GPU kernels.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air.crypto;
const B = A.bulk_memory;
const S = A.keccak_sponge;
const P = @import("rv64/bulk_sponge.zig");
const IO = @import("rv64/fixture_io.zig");
const a = std.heap.page_allocator;
fn state(v: B.types.State) P.State {
    return .{ .value = v.value, .tick = v.tick, .epoch = v.epoch, .rights = v.rights };
}
fn words(w: anytype, values: anytype) !void {
    try w.writeAll(std.mem.sliceAsBytes(values));
}
fn bulk(dir: std.fs.Dir) !void {
    var calls: [5]B.types.Call = undefined;
    var records: [5]P.BulkCall = undefined;
    var native_words: std.ArrayList(B.types.Word) = .empty;
    defer native_words.deinit(a);
    var gpu_words: std.ArrayList(P.Word) = .empty;
    defer gpu_words.deinit(a);
    const ops = [_]B.types.Op{ .copy, .set, .copy, .cmp, .jumpdest };
    var scans: u32 = 0;
    for (&calls, &records, ops, 0..) |*c, *p, op, k| {
        c.* = .{ .op = op, .pointer = 0xfff0 + 32 * k, .epoch = 2, .tick = 100, .dst = 0x2ffc0, .word1 = if (k == 2) 0x3fffd else if (op == .set) 0xab else 0x40000, .len = if (op == .jumpdest) 72 else 24, .packet = @splat(.{ .value = 0, .epoch = 1, .tick = 3, .rights = 3 }), .examined = 2, .result = -1 };
        p.* = .{ .pointer = c.pointer, .dst = c.dst, .word1 = c.word1, .len = c.len, .epoch = c.epoch, .tick = c.tick, .op = @intFromEnum(op), .examined = c.examined, .result = c.result, .first_word = @intCast(native_words.items.len), .first_scan = scans, .packet = undefined };
        for (c.packet, &p.packet) |s, *out| out.* = state(s);
        if (op == .jumpdest) scans += c.bodyRows();
        for (0..c.entries()) |j| {
            const w = B.types.Word{ .dst = .{ .value = 0x9080706050403020 + j, .epoch = 2, .tick = 7, .rights = 3 }, .src = .{ .value = if (op == .jumpdest) 0x5b7f5b60615b5b5b else 0x1122334455667788 + j, .epoch = 1, .tick = 2, .rights = 1 } };
            try native_words.append(a, w);
            try gpu_words.append(a, .{ .dst = state(w.dst), .src = state(w.src) });
        }
    }
    const pending = try a.alloc(u32, scans);
    defer a.free(pending);
    var hist: [8448]u32 = @splat(0);
    for (calls, records) |c, p| {
        if (c.op != .jumpdest) continue;
        var q: u8 = 0;
        for (native_words.items[p.first_word..][0..c.count()], 0..) |w, j| {
            if (j % 8 == 0) pending[p.first_scan + j / 8] = q;
            for (0..8) |i| {
                const b: u8 = @truncate(w.src.value >> @as(u6, @intCast(8 * i)));
                hist[@as(usize, q) * 256 + b] += 1;
                q = B.types.transition(q, b).next;
            }
        }
    }
    inline for (comptime std.enums.values(B.layout.Kind), 0..) |kind, id| {
        const log: u32 = if (kind == .jtab) 14 else 5;
        const n = @as(usize, 1) << log;
        var rows: std.ArrayList(P.Row) = .empty;
        defer rows.deinit(a);
        for (calls, records, 0..) |c, p, k| {
            if (c.descriptor() == kind) try rows.append(a, .{ .call = @intCast(k), .word = p.first_word, .index = 0 });
            if (c.body() == kind) for (0..c.bodyRows()) |j| try rows.append(a, .{ .call = @intCast(k), .word = p.first_word + @as(u32, @intCast(if (kind == .jscan) 0 else j)), .index = @intCast(j) });
        }
        const expected = try a.alloc(u32, B.layout.main(kind) * n);
        defer a.free(expected);
        var ranges: [65536]u32 = @splat(0);
        for (0..n) |logical| {
            var v: [B.layout.main(kind)]@import("stwo_core").fields.m31.M31 = undefined;
            if (kind == .jtab) {
                v = B.source.jtabRow(if (logical < 8448) hist[logical] else 0);
            } else {
                const active = logical < rows.items.len;
                const r = if (active) rows.items[logical] else P.Row{ .call = 0, .word = 0, .index = 0 };
                const c: ?B.types.Call = if (active) calls[r.call] else null;
                const empty = B.types.Word{ .dst = .{ .value = 0, .rights = 0 } };
                const w = if (active and kind != .desc and kind != .cdesc and kind != .jdesc) native_words.items[r.word] else empty;
                v = switch (kind) {
                    .desc => B.source.descRow(c),
                    .copy => B.source.copyRow(c, r.index, w),
                    .set => B.source.setRow(c, r.index, w),
                    .ucopy => B.source.ucopyRow(c, r.index, w, if (active and r.index != 0) native_words.items[r.word - 1] else empty),
                    .cdesc => B.source.cdescRow(c),
                    .cmp => B.source.cmpRow(c, r.index, w),
                    .jdesc => B.source.jdescRow(c),
                    .jscan => if (c) |cc| B.source.jscanRow(cc, r.index, native_words.items[records[r.call].first_word..][0..cc.entries()], @intCast(pending[records[r.call].first_scan + r.index])) else B.source.jscanRow(null, 0, &.{}, 0),
                    .jtab => unreachable,
                };
            }
            const physical = B.source.physical(logical, log);
            for (v, 0..) |value, col| expected[col * n + physical] = value.v;
            for (B.source.rangeValues(kind, &v)) |x| ranges[x] += 1;
        }
        var output: std.ArrayList(u8) = .empty;
        defer output.deinit(a);
        const w = output.writer(a);
        try IO.words(w, &.{ 0x53565731, 0, @intCast(id), log, @intCast(B.source.Source.rowsFor(kind, &calls)), @intCast(B.layout.main(kind)), calls.len, @intCast(native_words.items.len), scans });
        try words(w, &records);
        try words(w, gpu_words.items);
        try words(w, rows.items);
        try words(w, expected);
        try words(w, &ranges);
        try words(w, &hist);
        const name = try std.fmt.allocPrint(a, "bulk-{}.bin", .{id});
        defer a.free(name);
        try dir.writeFile(.{ .sub_path = name, .data = output.items });
    }
}
fn sponge(dir: std.fs.Dir) !void {
    const lengths = [_]u64{ 0, 1, 135, 136, 137, 272 };
    var calls: [lengths.len]S.types.Call = undefined;
    var records: [lengths.len]P.SpongeCall = undefined;
    var native_words: std.ArrayList(S.types.State) = .empty;
    defer native_words.deinit(a);
    var gpu_words: std.ArrayList(P.State) = .empty;
    defer gpu_words.deinit(a);
    var permutations: std.ArrayList([2][25]u64) = .empty;
    defer permutations.deinit(a);
    for (lengths, 0..) |len, k| {
        var c = S.types.Call{ .pointer = 0x1fff0 + 32 * k, .epoch = 1, .tick = 100, .packet = @splat(.{ .value = 0, .tick = 2, .rights = 3 }), .state = @splat(.{ .value = 0, .tick = 2, .rights = 3 }), .first_word = @intCast(native_words.items.len), .first_perm = @intCast(permutations.items.len) };
        c.packet[0].value = 0x20000;
        c.packet[1].value = 0x3fffb;
        c.packet[2].value = len;
        c.packet[3].value = if (k % 2 == 0) 3 else 1;
        for (&c.state, 0..) |*s, j| s.value = 0x101010101010101 *% j;
        for (0..c.words()) |j| {
            const s = S.types.State{ .value = 0x1122334455667788 +% j, .tick = 3, .rights = 1 };
            try native_words.append(a, s);
            try gpu_words.append(a, state(s));
        }
        const pp = try S.types.permutations(a, c, native_words.items[c.first_word..][0..c.words()]);
        defer a.free(pp);
        try permutations.appendSlice(a, pp);
        calls[k] = c;
        records[k] = .{ .pointer = c.pointer, .epoch = c.epoch, .tick = c.tick, .first_word = c.first_word, .first_perm = c.first_perm, .packet = undefined, .state = undefined };
        for (c.packet, &records[k].packet) |s, *o| o.* = state(s);
        for (c.state, &records[k].state) |s, *o| o.* = state(s);
    }
    inline for (comptime std.enums.values(S.layout.Kind), 0..) |kind, id| {
        const log: u32 = 5;
        const n = 32;
        var rows: std.ArrayList(P.Row) = .empty;
        defer rows.deinit(a);
        for (calls, 0..) |c, k| {
            if (kind == .call) try rows.append(a, .{ .call = @intCast(k), .word = 0, .index = 0 }) else for (0..c.permutations()) |j| try rows.append(a, .{ .call = @intCast(k), .word = 0, .index = @intCast(j) });
        }
        const expected = try a.alloc(u32, S.layout.main(kind) * n);
        defer a.free(expected);
        var ranges: [65536]u32 = @splat(0);
        var bytes: [256]u32 = @splat(0);
        var ands: [65536]u32 = @splat(0);
        for (0..n) |logical| {
            const active = logical < rows.items.len;
            const r = if (active) rows.items[logical] else P.Row{ .call = 0, .word = 0, .index = 0 };
            const c = if (active) calls[r.call] else null;
            const values = if (kind == .call) S.source.callRow(c, if (active) 17 + calls[r.call].first_perm else 0, if (active) permutations.items[calls[r.call].first_perm + calls[r.call].permutations() - 1][1] else undefined) else if (c) |cc| S.source.permRow(cc, native_words.items[cc.first_word..][0..cc.words()], r.index, permutations.items[cc.first_perm..][0..cc.permutations()]) else S.source.permRow(null, &.{}, 0, &.{});
            const physical = S.source.physical(logical, log);
            for (values, 0..) |v, col| expected[col * n + physical] = v.v;
            for (S.source.range16Values(kind, &values)) |x| ranges[x] += 1;
            for (S.source.range8Values(kind, &values)) |x| bytes[x] += 1;
            if (kind == .perm) for (0..136) |t| {
                ands[values[S.layout.perm.pre + t].v * 256 + values[S.layout.perm.msg + t].v] += 1;
            };
        }
        var input: std.ArrayList([25]u64) = .empty;
        defer input.deinit(a);
        for (permutations.items) |p| try input.append(a, p[0]);
        var output: std.ArrayList(u8) = .empty;
        defer output.deinit(a);
        const w = output.writer(a);
        try IO.words(w, &.{ 0x53565731, 1, @intCast(id), log, @intCast(rows.items.len), @intCast(S.layout.main(kind)), calls.len, @intCast(native_words.items.len), @intCast(permutations.items.len) });
        try words(w, &records);
        try words(w, gpu_words.items);
        try words(w, input.items);
        try words(w, rows.items);
        try words(w, expected);
        try words(w, &ranges);
        try words(w, &bytes);
        try words(w, &ands);
        const name = try std.fmt.allocPrint(a, "sponge-{}.bin", .{id});
        defer a.free(name);
        try dir.writeFile(.{ .sub_path = name, .data = output.items });
    }
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    try bulk(dir);
    try sponge(dir);
}
