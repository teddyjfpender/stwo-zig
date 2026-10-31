//! Control-only authority for the explicit 24/24/16-bit ROM schema. ROM
//! membership bounds each current/inc/target limb. Next-PC is linked by the
//! frame to the following ROM PC or the receiver's terminal PC, including
//! inactive padding. Each grouped integer is at most 2^24-1 (< M31), so
//! zero limb differences cannot hide a field-characteristic multiple. Boolean
//! branch/selector authority reduces every selected flow equation to such a
//! difference. Never recombine a full u64 into one M31 coordinate.
const E = @import("../evaluation.zig");
const Q = E.Q;
pub const Word = [3]Q;
pub const CONSTRAINTS = 19;

/// Group existing BYTE/bit-range-authenticated operand coordinates linearly.
/// This is valid at arbitrary extension points; it is not a host integer cast.
pub fn group(v: E.View, word: E.L.Word) Word {
    return groupGeneric(Q, v, word);
}
pub fn groupGeneric(comptime F: type, v: E.ViewFor(F), word: E.L.Word) [3]F {
    var result: [3]F = @splat(F.zero());
    for (0..3) |limb| {
        for (0..if (limb == 2) @as(usize, 2) else 3) |i| {
            result[limb] = result[limb].add(v.byte(word, 3 * limb + i).mul(E.qFor(F, @as(u32, 1) << @as(u5, @intCast(8 * i)))));
        }
    }
    return result;
}

/// The receiver selects this authority only under limbs24_v2. Shared local
/// arithmetic still enforces branch taken, wrapped address addition, and all
/// result/address byte ranges; the legacy byte-PC residuals are omitted there.
pub fn evaluate(v: E.View, increment: Word, target: Word, next: Word, out: *E.Sink) void {
    return evaluateGeneric(Q, v, increment, target, next, out);
}
pub fn evaluateGeneric(comptime F: type, v: E.ViewFor(F), increment: [3]F, target: [3]F, next: [3]F, out: *E.SinkFor(F)) void {
    const result = groupGeneric(F, v, .result);
    const address = groupGeneric(F, v, .address);
    const branch = v.sum(&.{ .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU });
    const jumps = v.sum(&.{ .JAL, .JALR });
    for (0..3) |i| {
        out.emit(v.op(.AUIPC).mul(result[i].sub(target[i])));
        out.emit(jumps.mul(result[i].sub(increment[i])));
    }
    for (0..3) |i| {
        out.emit(v.f[E.L.fixed.active].sub(branch).sub(jumps).mul(next[i].sub(increment[i])));
        out.emit(branch.mul(next[i].sub(increment[i]).sub(v.m[E.L.taken].mul(target[i].sub(increment[i])))));
        out.emit(v.op(.JAL).mul(next[i].sub(target[i])));
        // Removing the canonical low bit cannot borrow from another limb.
        out.emit(v.op(.JALR).mul(next[i].sub(address[i]).add(if (i == 0) v.bit(.address, 0) else F.zero())));
    }
    out.emit(v.op(.JALR).mul(v.bit(.address, 1)));
}
