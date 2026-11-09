//! Shared word-operation author for packed SHA round, expansion and feed-forward.
//! Round constants and message/state wiring must be admitted by the caller AIR.
pub const Kind = enum { round, schedule, feed_forward };
pub fn inputCount(comptime kind: Kind) usize {
    return switch (kind) {
        .round => 10,
        .schedule => 4,
        .feed_forward => 2,
    };
}
pub fn outputCount(comptime kind: Kind) usize {
    return if (kind == .round) 2 else 1;
}
fn sigma(comptime O: type, o: *O, x: O.Word, comptime a: u5, comptime b: u5, comptime c: u5, comptime shift: bool) !O.Word {
    const p = try o.rotate(x, a, false);
    const q = try o.rotate(x, b, false);
    const r = try o.rotate(x, c, shift);
    return o.bitwise(try o.bitwise(p, q, 2), r, 2);
}
pub fn run(comptime kind: Kind, comptime O: type, o: *O, x: [inputCount(kind)]O.Word) ![outputCount(kind)]O.Word {
    return switch (kind) {
        .round => blk: {
            // Inputs a,b,c,d,e,f,g,h,W,K; outputs next a and next e.
            const big_e = try sigma(O, o, x[4], 6, 11, 25, false);
            const choose = try o.bitwise(x[6], try o.bitwise(x[4], try o.bitwise(x[5], x[6], 2), 0), 2);
            const t1 = try o.add(&.{ x[7], big_e, choose, x[9], x[8] });
            const big_a = try sigma(O, o, x[0], 2, 13, 22, false);
            const majority = try o.bitwise(try o.bitwise(x[0], x[1], 0), try o.bitwise(x[2], try o.bitwise(x[0], x[1], 2), 0), 2);
            const t2 = try o.add(&.{ big_a, majority });
            break :blk .{ try o.add(&.{ t1, t2 }), try o.add(&.{ x[3], t1 }) };
        },
        .schedule => .{try o.add(&.{ try sigma(O, o, x[0], 17, 19, 10, true), x[1], try sigma(O, o, x[2], 7, 18, 3, true), x[3] })},
        .feed_forward => .{try o.add(&x)},
    };
}
