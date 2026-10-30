const E = @import("evaluation.zig");
const Q = E.Q;
const L = E.L;
pub fn evaluate(v: E.View, out: *E.Sink) void {
    evaluateProfile(v, out, false);
}
pub fn evaluateProfile(v: E.View, out: *E.Sink, byte_operations: bool) void {
    const one = Q.one();
    const add64 = v.sum(&.{ .ADD, .ADDI });
    const add32 = v.sum(&.{ .ADDW, .ADDIW });
    const sub64 = v.op(.SUB);
    const sub32 = v.op(.SUBW);
    const immediate = v.sum(&.{ .ADDI, .ADDIW, .SLTI, .SLTIU, .XORI, .ORI, .ANDI, .SLLI, .SRLI, .SRAI, .SLLIW, .SRLIW, .SRAIW });
    const rhs_register = v.sum(&.{ .ADD, .SUB, .ADDW, .SUBW, .SLT, .SLTU, .XOR, .OR, .AND, .SLL, .SRL, .SRA, .SLLW, .SRLW, .SRAW, .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU });
    const cmp = v.sum(&.{ .SLT, .SLTU, .SLTI, .SLTIU, .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU });
    const addr = v.sum(&.{ .LB, .LBU, .LH, .LHU, .LW, .LWU, .LD, .SB, .SH, .SW, .SD, .JALR });
    const word = v.sum(&.{ .ADDW, .SUBW, .ADDIW, .SLLW, .SRLW, .SRAW, .SLLIW, .SRLIW, .SRAIW, .MULW, .DIVW, .DIVUW, .REMW, .REMUW });
    var squares = Q.zero();
    for (0..8) |i| {
        const a = v.byte(.a, i);
        const b = v.byte(.rhs, i);
        const r = v.byte(.result, i);
        const enabled_add = add64.add(if (i < 4) add32 else Q.zero());
        const enabled_sub = sub64.add(if (i < 4) sub32 else Q.zero());
        const previous = if (i == 0) Q.zero() else v.carry(.alu, i - 1);
        const carry = v.carry(.alu, i).mul(E.q(256));
        out.emit(enabled_add.mul(a.add(b).add(previous).sub(r).sub(carry)));
        out.emit(enabled_sub.mul(a.add(E.q(255).sub(b)).add(if (i == 0) one else previous).sub(r).sub(carry)));
        out.emit(v.byte(.rhs, i).sub(immediate.mul(v.f[L.fixed.immediate + i])).sub(rhs_register.mul(v.byte(.b, i))));
        const cmp_previous = if (i == 0) one else v.carry(.compare, i - 1);
        out.emit(cmp.mul(a.add(E.q(255).sub(b)).add(cmp_previous).sub(v.byte(.difference, i)).sub(v.carry(.compare, i).mul(E.q(256)))));
        const d = a.sub(b);
        squares = squares.add(d.mul(d));
        out.emit(addr.mul(a.add(v.f[L.fixed.immediate + i]).add(if (i == 0) Q.zero() else v.carry(.address, i - 1)).sub(v.byte(.address, i)).sub(v.carry(.address, i).mul(E.q(256)))));
        if (i >= 4) out.emit(word.mul(r.sub(v.bit(.result, 31).mul(E.q(255)))));
        out.emit(v.op(.LUI).mul(r.sub(v.f[L.fixed.immediate + i])));
        out.emit(v.op(.AUIPC).mul(r.sub(v.f[L.fixed.target + i])));
        out.emit(v.sum(&.{ .JAL, .JALR }).mul(r.sub(v.f[L.fixed.increment + i])));
    }
    out.emit(v.m[L.equal].mul(squares));
    out.emit(squares.mul(v.m[L.equal_inverse]).sub(cmp).add(v.m[L.equal]));
    out.emit(one.sub(cmp).mul(v.m[L.equal_inverse]));
    out.emit(one.sub(cmp).mul(v.m[L.equal]));
    out.emit(v.m[L.equal].mul(v.m[L.equal_inverse]));
    const less_unsigned = one.sub(v.carry(.compare, 7));
    const less_signed = less_unsigned.add(v.bit(.a, 63)).sub(v.bit(.rhs, 63));
    for (0..8) |i| {
        out.emit(v.sum(&.{ .SLTU, .SLTIU }).mul(v.byte(.result, i).sub(if (i == 0) less_unsigned else Q.zero())));
        out.emit(v.sum(&.{ .SLT, .SLTI }).mul(v.byte(.result, i).sub(if (i == 0) less_signed else Q.zero())));
    }
    const branch = v.sum(&.{ .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU });
    const jumps = v.sum(&.{ .JAL, .JALR });
    const expected_taken = v.op(.BEQ).mul(v.m[L.equal]).add(v.op(.BNE).mul(one.sub(v.m[L.equal])))
        .add(v.op(.BLT).mul(less_signed)).add(v.op(.BGE).mul(one.sub(less_signed)))
        .add(v.op(.BLTU).mul(less_unsigned)).add(v.op(.BGEU).mul(one.sub(less_unsigned))).add(jumps);
    out.emit(v.m[L.taken].sub(expected_taken));
    for (0..8) |i| {
        const next = v.f[L.fixed.next_pc + i];
        const inc = v.f[L.fixed.increment + i];
        const target = v.f[L.fixed.target + i];
        out.emit(v.f[L.fixed.active].sub(branch).sub(jumps).mul(next.sub(inc)));
        out.emit(branch.mul(next.sub(inc).sub(v.m[L.taken].mul(target.sub(inc)))));
        out.emit(v.op(.JAL).mul(next.sub(target)));
        out.emit(v.op(.JALR).mul(next.sub(v.byte(.address, i)).add(if (i == 0) v.bit(.address, 0) else Q.zero())));
    }
    out.emit(v.op(.JALR).mul(v.bit(.address, 1)));
    if (byte_operations) return;
    const band = v.sum(&.{ .AND, .ANDI });
    const bor = v.sum(&.{ .OR, .ORI });
    const bxor = v.sum(&.{ .XOR, .XORI });
    for (0..64) |i| {
        const a = v.bit(.a, i);
        const b = v.bit(.rhs, i);
        const r = v.bit(.result, i);
        const ab = a.mul(b);
        out.emit(band.mul(r.sub(ab)));
        out.emit(bor.mul(r.sub(a).sub(b).add(ab)));
        out.emit(bxor.mul(r.sub(a).sub(b).add(ab.mul(E.q(2)))));
    }
}
