const E = @import("evaluation.zig");
const Q = E.Q;
const L = E.L;
pub fn evaluate(v: E.View, out: *E.Sink) void {
    const left64 = v.sum(&.{ .SLL, .SLLI });
    const right64 = v.sum(&.{ .SRL, .SRLI });
    const signed64 = v.sum(&.{ .SRA, .SRAI });
    const left32 = v.sum(&.{ .SLLW, .SLLIW });
    const right32 = v.sum(&.{ .SRLW, .SRLIW });
    const signed32 = v.sum(&.{ .SRAW, .SRAIW });
    const enabled64 = left64.add(right64).add(signed64);
    const enabled32 = left32.add(right32).add(signed32);
    for (0..6) |stage| {
        const amount = @as(usize, 1) << @as(u6, @intCast(stage));
        const choice = v.bit(.rhs, stage);
        for (0..64) |i| {
            const current = v.m[L.shift(stage, i)];
            E.boolean(out, current);
            const before = if (stage == 0) v.bit(.a, i) else v.m[L.shift(stage - 1, i)];
            const l = if (i >= amount) (if (stage == 0) v.bit(.a, i - amount) else v.m[L.shift(stage - 1, i - amount)]) else Q.zero();
            const r = if (i + amount < 64) (if (stage == 0) v.bit(.a, i + amount) else v.m[L.shift(stage - 1, i + amount)]) else Q.zero();
            const sr = if (i + amount < 64) r else v.bit(.a, 63);
            out.emit(left64.mul(current.sub(before).sub(choice.mul(l.sub(before)))));
            out.emit(right64.mul(current.sub(before).sub(choice.mul(r.sub(before)))));
            out.emit(signed64.mul(current.sub(before).sub(choice.mul(sr.sub(before)))));
            const active32 = if (stage < 5 and i < 32) enabled32 else Q.zero();
            out.emit(Q.one().sub(enabled64).sub(active32).mul(current));
            if (stage < 5 and i < 32) {
                const rr = if (i + amount < 32) r else Q.zero();
                const ss = if (i + amount < 32) r else v.bit(.a, 31);
                out.emit(left32.mul(current.sub(before).sub(choice.mul(l.sub(before)))));
                out.emit(right32.mul(current.sub(before).sub(choice.mul(rr.sub(before)))));
                out.emit(signed32.mul(current.sub(before).sub(choice.mul(ss.sub(before)))));
            }
        }
    }
    for (0..64) |i| {
        out.emit(enabled64.mul(v.bit(.result, i).sub(v.m[L.shift(5, i)])));
        out.emit(enabled32.mul(v.bit(.result, i).sub(v.m[L.shift(4, if (i < 32) i else 31)])));
    }
}
