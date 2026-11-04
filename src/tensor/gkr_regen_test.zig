//! Fast.Regen (engine gkr_prover_fast): a LogUp singles input given by a
//! function must give byte-identical GKR proofs and artifacts to the same
//! input materialised, at every size (small path n < 3, layer n-2 from the
//! source, the block refills) and with several instances and thread counts.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const f = @import("field.zig");
const Transcript = @import("transcript.zig").Transcript;
const QM31 = f.QM31;
const M31 = f.M31;
const Fast = engine.lookups.gkr_prover_fast.ForField(QM31);

const Src = struct {
    t: []const i8,
    alpha: QM31,
    fn fill(ctx: *const anyopaque, out: []QM31, start: usize) void {
        const s: *const Src = @ptrCast(@alignCast(ctx));
        for (out, s.t[start..][0..out.len]) |*d, w| d.* = s.alpha.sub(QM31.fromBase(M31.fromCanonical(@intCast(@as(i32, w) + 128))));
    }
};

fn upd(h: *std.crypto.hash.blake2.Blake2s256, c: QM31) void {
    const l = f.limbs(c);
    h.update(std.mem.asBytes(&l));
}

fn digestOf(r: anytype, ch: anytype) ![32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    for (r.proof.sumcheck_proofs) |p| for (p.round_polys) |rp| for (rp.coeffsSlice()) |c| upd(&h, c);
    for (r.proof.layer_masks_by_instance) |ms| for (ms) |m| for (m.columnsSlice()) |col| for (col) |c| upd(&h, c);
    for (r.proof.output_claims_by_instance) |cs| for (cs) |c| upd(&h, c);
    for (r.artifact.ood_point) |c| upd(&h, c);
    for (r.artifact.claims_to_verify_by_instance) |cs| for (cs) |c| upd(&h, c);
    var c2 = ch.*;
    const tail = c2.drawSecureFelt();
    upd(&h, tail);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn run(a: std.mem.Allocator, tables: []const []const i8, alphas: []const QM31, use_regen: bool, threads: usize) ![32]u8 {
    var srcs: [4]Src = undefined;
    var inputs: [4]Fast.Input = undefined;
    for (tables, 0..) |t, j| {
        srcs[j] = .{ .t = t, .alpha = alphas[j] };
        if (use_regen) {
            inputs[j] = .{ .num = .ones, .den = &.{}, .owned = false, .regen = .{ .ctx = &srcs[j], .fill = Src.fill, .log_len = @intCast(std.math.log2_int(usize, t.len)) } };
        } else {
            const d = try a.alloc(QM31, t.len);
            Src.fill(&srcs[j], d, 0);
            inputs[j] = .{ .num = .ones, .den = d, .owned = true };
        }
    }
    var tr = Transcript.initDomain("regen-test");
    var res = try Fast.proveBatch(a, &tr.ch, inputs[0..tables.len], .{ .threads = threads, .min_parallel = 16 }, null);
    defer res.proof.deinit(a);
    defer res.artifact.deinit(a);
    return digestOf(res, &tr.ch);
}

test "gkr regen: identical proofs to the materialised input" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    const alphas = [_]QM31{ QM31.fromU32Unchecked(11, 22, 33, 44), QM31.fromU32Unchecked(5, 6, 7, 8), QM31.fromU32Unchecked(9, 1, 2, 3) };
    for ([_][3]u5{ .{ 1, 1, 1 }, .{ 2, 3, 2 }, .{ 3, 3, 3 }, .{ 4, 2, 5 }, .{ 7, 7, 1 }, .{ 12, 9, 11 }, .{ 13, 3, 13 } }) |logs| {
        var tabs: [3][]i8 = undefined;
        for (&tabs, logs) |*t, l| {
            t.* = try a.alloc(i8, @as(usize, 1) << l);
            for (t.*) |*w| w.* = r.int(i8);
        }
        defer for (tabs) |t| a.free(t);
        const views = [_][]const i8{ tabs[0], tabs[1], tabs[2] };
        for ([_]usize{ 1, 4 }) |th| {
            const want = try run(a, &views, &alphas, false, th);
            const got = try run(a, &views, &alphas, true, th);
            try std.testing.expectEqualSlices(u8, &want, &got);
        }
    }
}

test "gkr regen: invalid regen inputs are refused" {
    const a = std.testing.allocator;
    const t = [_]i8{ 1, 2, 3, 4 };
    var src = Src{ .t = &t, .alpha = QM31.fromU32Unchecked(3, 0, 0, 0) };
    var d = [_]QM31{QM31.zero()} ** 4;
    var tr = Transcript.initDomain("regen-test");
    const bad = [_]Fast.Input{.{ .num = .ones, .den = &d, .owned = false, .regen = .{ .ctx = &src, .fill = Src.fill, .log_len = 2 } }};
    try std.testing.expectError(error.InvalidInputShape, Fast.proveBatch(a, &tr.ch, &bad, .{}, null));
    const bad0 = [_]Fast.Input{.{ .num = .ones, .den = &.{}, .owned = false, .regen = .{ .ctx = &src, .fill = Src.fill, .log_len = 0 } }};
    try std.testing.expectError(error.InvalidInputShape, Fast.proveBatch(a, &tr.ch, &bad0, .{}, null));
}
