//! Test-only oracle for the retired handwritten SLT/SLTU witness path.

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

pub inline fn writeRow(columns: anytype, index: usize, row: anytype) void {
    const signed = row.opcode == .SLT;
    const result = compare(row.rs1_val, row.rs2_val, signed);
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    w.rs2(columns, index, 22, row);
    w.set(columns, index, 32, w.bit(result.less));
    w.set(columns, index, 33, result.lhs_msb);
    w.set(columns, index, 34, result.rhs_msb);
    w.set(columns, index, 35, w.bit(signed));
    w.set(columns, index, 36, w.bit(!signed));
    for (result.markers, 0..) |marker, limb|
        w.set(columns, index, 37 + limb, w.u(marker));
    w.set(columns, index, 41, result.difference);
    w.destination(columns, index, 42, row.rd);
}
