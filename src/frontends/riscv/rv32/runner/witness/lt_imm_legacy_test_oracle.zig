//! Test-only oracle for the retired handwritten SLTI/SLTIU witness path.
//!
//! Production code must not import this module. It intentionally preserves
//! the former scalar implementation so cell and relation differentials remain
//! independent of the typed witness executor.

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
    for (result.markers, 0..) |marker, limb|
        w.set(columns, index, 29 + limb, w.u(marker));
    w.set(columns, index, 33, result.difference);
    w.destination(columns, index, 34, row.rd);
    w.set(columns, index, 36, result.rhs_msb);
}
