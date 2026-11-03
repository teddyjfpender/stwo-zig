const std = @import("std");
const f = @import("field.zig");
const QM31 = f.QM31;
const P: u64 = 0x7fffffff;
fn mm(x: u64, y: u64) u64 {
    return (x * y) % P;
}
fn ref(a: [4]u32, b: [4]u32) [4]u32 {
    const A = [2]u64{ a[0] % P, a[1] % P };
    const B = [2]u64{ a[2] % P, a[3] % P };
    const C = [2]u64{ b[0] % P, b[1] % P };
    const D = [2]u64{ b[2] % P, b[3] % P };
    const cm = struct {
        fn mul(x: [2]u64, y: [2]u64) [2]u64 {
            return .{ (mm(x[0], y[0]) + P - mm(x[1], y[1])) % P, (mm(x[0], y[1]) + mm(x[1], y[0])) % P };
        }
    };
    const ac = cm.mul(A, C);
    const bd = cm.mul(B, D);
    const adv = cm.mul(A, D);
    const bc = cm.mul(B, C);
    const rbd = cm.mul(bd, .{ 2, 1 });
    return .{ @intCast((ac[0] + rbd[0]) % P), @intCast((ac[1] + rbd[1]) % P), @intCast((adv[0] + bc[0]) % P), @intCast((adv[1] + bc[1]) % P) };
}
test "QM31.mul differential (ReleaseFast)" {
    var prng = std.Random.DefaultPrng.init(9);
    const r = prng.random();
    var bad: usize = 0;
    for (0..2_000_000) |_| {
        var a: [4]u32 = undefined;
        var b: [4]u32 = undefined;
        for (&a) |*x| x.* = r.intRangeLessThan(u32, 0, @intCast(P));
        for (&b) |*x| x.* = r.intRangeLessThan(u32, 0, @intCast(P));
        if (r.int(u8) < 30) b = .{ b[0], 0, 0, 0 };
        if (r.int(u8) < 30) a = .{ a[0], 0, 0, 0 };
        const x = QM31.fromU32Unchecked(a[0], a[1], a[2], a[3]);
        const y = QM31.fromU32Unchecked(b[0], b[1], b[2], b[3]);
        const z = f.limbs(x.mul(y));
        const e = ref(a, b);
        if (!std.mem.eql(u32, &z, &e)) {
            if (bad < 3) std.debug.print("bad a={any} b={any} got={any} want={any}\n", .{ a, b, z, e });
            bad += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
