//! Checked raw multiplicity cross-kernel A/B; not proof or execution timing.
const std = @import("std");
const core = @import("stwo_core");
const K = @import("lookups/packed_rows.zig");
const M = core.fields.m31;
fn checkedCross(comptime S: type, n: M.PackedM31, d: K.ForField(S).P) K.ForField(S).P {
    const R = K.ForField(S);
    const P = R.P;
    const O = core.fields.om31.OM31;
    const po = core.fields.packed_om31;
    const positive = n == @as(M.PackedM31, @splat(1));
    if (@reduce(.And, positive)) return d;
    const zero = n == @as(M.PackedM31, @splat(0));
    if (@reduce(.And, zero)) return R.splat(S.zero());
    const negative = n == @as(M.PackedM31, @splat(M.Modulus - 1));
    if (@reduce(.And, negative)) return d.neg();
    if (!@reduce(.And, positive | zero | negative)) return d.mulBase(n);
    var c = if (S == O) po.coordinates(d) else d.coordinates();
    inline for (&c) |*coordinate| coordinate.* = @select(u32, positive, coordinate.*, @select(u32, negative, M.negPacked(coordinate.*), @as(M.PackedM31, @splat(0))));
    return if (S == O) po.fromCoordinates(c) else P.fromCoordinates(c);
}

fn bench(comptime S: type) !void {
    const R = K.ForField(S);
    const count = 1024;
    const a = std.heap.page_allocator;
    const nums = try a.alloc(M.PackedM31, count);
    defer a.free(nums);
    const den = try a.alloc(R.P, count);
    defer a.free(den);
    const out = try a.alloc(R.P, count);
    defer a.free(out);
    var coordinates: [S.zero().toM31Array().len]M.M31 = undefined;
    for (den, 0..) |*d, i| {
        for (&coordinates, 0..) |*c, j| c.* = M.M31.fromCanonical(@intCast((i * 7919 + j * 977 + 3) % M.Modulus));
        d.* = R.splat(S.fromM31Array(coordinates));
    }
    const w = std.fs.File.stdout().deprecatedWriter();
    for (0..6) |pattern| {
        for (nums, 0..) |*n, i| {
            for (0..M.PACK_WIDTH) |lane| n[lane] = switch (pattern) {
                0 => 1,
                1 => ([_]u32{ 0, 1, M.Modulus - 1 })[(i + lane) % 3],
                2 => ([_]u32{ 2, 1000, M.Modulus - 2, 65536 })[(i + lane) % 4],
                4 => 0,
                5 => M.Modulus - 1,
                else => if (i % 10 == 0) @as(u32, @intCast(2 + lane)) else ([_]u32{ 0, 1, M.Modulus - 1 })[(i + lane) % 3],
            };
        }
        for (nums, den) |n, d| {
            const actual = checkedCross(S, n, d);
            for (0..M.PACK_WIDTH) |lane| {
                const expected = R.lane(d, lane).mulM31(M.M31.fromCanonical(n[lane]));
                if (!R.lane(actual, lane).eql(expected)) return error.IncorrectCheckedKernel;
            }
        }
        for (0..7) |sample| for (0..2) |order| {
            const fast = (sample + order) % 2 == 1;
            var timer = try std.time.Timer.start();
            for (0..64) |_| {
                for (nums, den, out) |n, d, *o| o.* = if (fast) checkedCross(S, n, d) else d.mulBase(n);
                std.mem.doNotOptimizeAway(out.ptr);
            }
            const ns = timer.read();
            var checksum = S.zero();
            for (out) |v| checksum = checksum.add(R.lane(v, 0));
            try w.print("{{\"field_bytes\":{d},\"pattern\":{d},\"sample\":{d},\"checked\":{},\"crosses\":{d},\"ns\":{d},\"checksum0\":{d}}}\n", .{ @sizeOf(S), pattern, sample, fast, count * 64, ns, checksum.toM31Array()[0].toU32() });
        };
    }
}
pub fn main() !void {
    try bench(core.fields.qm31.QM31);
    try bench(core.fields.om31.OM31);
}
