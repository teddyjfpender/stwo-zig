//! Exact comparison witnesses from the pinned Stark-V runner.

const M31 = @import("stwo_core").fields.m31.M31;
const w = @import("writer.zig");

const Comparison = struct {
    lhs_msb: M31,
    rhs_msb: M31,
    less: bool,
    markers: [4]u32,
    difference: M31,
};

fn compare(lhs: u32, rhs: u32, signed: bool) Comparison {
    const lhs_bytes = w.limbs(lhs);
    const rhs_bytes = w.limbs(rhs);
    const less = if (signed)
        @as(i32, @bitCast(lhs)) < @as(i32, @bitCast(rhs))
    else
        lhs < rhs;
    const lhs_msb = if (signed) w.signedByte(@truncate(lhs >> 24)) else lhs_bytes[3];
    const rhs_msb = if (signed) w.signedByte(@truncate(rhs >> 24)) else rhs_bytes[3];
    var result = Comparison{
        .lhs_msb = lhs_msb,
        .rhs_msb = rhs_msb,
        .less = less,
        .markers = .{0} ** 4,
        .difference = M31.zero(),
    };
    var limb: usize = 4;
    while (limb > 0) {
        limb -= 1;
        const a = if (limb == 3) lhs_msb else lhs_bytes[limb];
        const b = if (limb == 3) rhs_msb else rhs_bytes[limb];
        if (!a.eql(b)) {
            result.markers[limb] = 1;
            result.difference = if (less) b.sub(a) else a.sub(b);
            break;
        }
    }
    return result;
}

fn writeComparison(columns: anytype, index: usize, start: usize, result: Comparison) void {
    w.set(columns, index, start, result.lhs_msb);
    w.set(columns, index, start + 1, result.rhs_msb);
}

pub fn reg(columns: anytype, index: usize, row: anytype) void {
    const signed = row.opcode == .SLT;
    const result = compare(row.rs1_val, row.rs2_val, signed);
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    w.rs2(columns, index, 22, row);
    w.set(columns, index, 32, w.bit(result.less));
    writeComparison(columns, index, 33, result);
    w.set(columns, index, 35, w.bit(signed));
    w.set(columns, index, 36, w.bit(!signed));
    for (result.markers, 0..) |marker, i| w.set(columns, index, 37 + i, w.u(marker));
    w.set(columns, index, 41, result.difference);
    w.destination(columns, index, 42, row.rd);
}

pub fn immediate(columns: anytype, index: usize, row: anytype) void {
    const signed = row.opcode == .SLTI;
    const rhs: u32 = @bitCast(row.imm);
    const result = compare(row.rs1_val, rhs, signed);
    const bits: u32 = @bitCast(row.imm);
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    w.set(columns, index, 22, w.bit(result.less));
    w.set(columns, index, 23, result.lhs_msb);
    w.set(columns, index, 24, w.u(bits & 0xff));
    w.set(columns, index, 25, w.u((bits >> 8) & 0x7));
    w.set(columns, index, 26, w.u((bits >> 11) & 1));
    w.set(columns, index, 27, w.bit(signed));
    w.set(columns, index, 28, w.bit(!signed));
    for (result.markers, 0..) |marker, i| w.set(columns, index, 29 + i, w.u(marker));
    w.set(columns, index, 33, result.difference);
    w.destination(columns, index, 34, row.rd);
    w.set(columns, index, 36, result.rhs_msb);
}

pub fn branchEqual(columns: anytype, index: usize, row: anytype) void {
    const is_beq = row.opcode == .BEQ;
    const comparison = row.rs1_val == row.rs2_val;
    const taken = if (is_beq) comparison else !comparison;
    w.common(columns, index, 0, row);
    w.rs1(columns, index, 2, row);
    w.rs2(columns, index, 12, row);
    w.set(columns, index, 22, w.signed(row.imm));
    w.set(columns, index, 23, w.bit(taken));
    const lhs = w.limbs(row.rs1_val);
    const rhs = w.limbs(row.rs2_val);
    var wrote_inverse = false;
    for (0..4) |limb| {
        const diff = lhs[limb].sub(rhs[limb]);
        const inverse = if (!wrote_inverse and !diff.isZero()) blk: {
            wrote_inverse = true;
            break :blk diff.invUncheckedNonZero();
        } else M31.zero();
        w.set(columns, index, 24 + limb, inverse);
    }
    w.set(columns, index, 28, w.bit(is_beq));
    w.set(columns, index, 29, w.bit(!is_beq));
}

pub fn branchLess(columns: anytype, index: usize, row: anytype) void {
    const signed = row.opcode == .BLT or row.opcode == .BGE;
    const is_less_opcode = row.opcode == .BLT or row.opcode == .BLTU;
    const less = if (signed)
        @as(i32, @bitCast(row.rs1_val)) < @as(i32, @bitCast(row.rs2_val))
    else
        row.rs1_val < row.rs2_val;
    const taken = if (is_less_opcode) less else !less;
    const result = compare(row.rs1_val, row.rs2_val, signed);
    w.common(columns, index, 0, row);
    w.rs1(columns, index, 2, row);
    w.rs2(columns, index, 12, row);
    writeComparison(columns, index, 22, result);
    w.set(columns, index, 24, w.signed(row.imm));
    w.set(columns, index, 25, w.bit(taken));
    w.set(columns, index, 26, w.bit(less));
    for (result.markers, 0..) |marker, i| w.set(columns, index, 27 + i, w.u(marker));
    w.set(columns, index, 31, result.difference);
    w.set(columns, index, 32, w.u(row.next_pc));
    w.set(columns, index, 33, w.bit(row.opcode == .BLT));
    w.set(columns, index, 34, w.bit(row.opcode == .BLTU));
    w.set(columns, index, 35, w.bit(row.opcode == .BGE));
    w.set(columns, index, 36, w.bit(row.opcode == .BGEU));
}
