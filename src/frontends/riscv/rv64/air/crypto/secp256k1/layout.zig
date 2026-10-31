//! Independently sized concrete modular providers, degree four stitched LogUp.
const std = @import("std");
const core = @import("stwo_core");
pub const P = @import("program.zig");
pub const mul = @import("../../../../air/guest_precompile/secp256k1_mul_direct.zig");
pub const linear = @import("../../../../air/guest_precompile/secp256k1_linear_direct.zig");
pub const Kind = enum { product, linear };
pub const FIXED = 15;
pub const FIRST = 0;
pub const PHASE_FIRST = 1;
pub const COMPLETE = 2;
pub const CALL_INDEX = 3;
pub const OP_INDEX = 4;
pub const LHS_ID = 5;
pub const RHS_ID = 6;
pub const RESULT_ID = 7;
pub const USES = 8;
pub const LHS_WIRE = 9;
pub const RHS_WIRE = 10;
pub const RHS_SMALL = 11;
pub const ADD = 12;
pub const SUB = 13;
pub const REDUCE = 14;
pub const WIRE_ARITY = 35; // program tag, call ID, wire ID,32 bytes.
pub fn base(kind: Kind) usize {
    return if (kind == .product) mul.Layout.main_columns else linear.Layout.main_columns;
}
pub fn main(kind: Kind) usize {
    return base(kind) + 1;
} // main call ID, not fixed/request-derived.
pub fn byteCount(kind: Kind) usize {
    return if (kind == .product) 284 else 128;
}
pub fn batches(kind: Kind) usize {
    return (byteCount(kind) + 2) / 3 + 1;
}
pub fn interaction(kind: Kind) usize {
    return 4 * batches(kind);
}
pub fn direct(kind: Kind) usize {
    return (if (kind == .product) mul.constraint_count else linear.constraint_count) + 8 + base(kind) - 1 + 32 + @as(usize, if (kind == .linear) 3 else 0);
}
pub fn constraints(kind: Kind) usize {
    return direct(kind) + batches(kind);
}
pub fn logSize(kind: Kind, program: *const P.Program, calls: usize) !u32 {
    const rows = try std.math.mul(usize, calls, program.rows(kind == .product));
    const log: u32 = @intCast(std.math.log2_int_ceil(usize, @max(32, try std.math.add(usize, rows, 1))));
    try validate(kind, program, calls, 1, log);
    return log;
}
pub fn validate(kind: Kind, program: *const P.Program, calls: usize, first_id: u32, log: u32) !void {
    const modulus = core.fields.m31.Modulus;
    if (first_id == 0 or first_id >= modulus or @as(u64, first_id) + calls > modulus) return error.InvalidSecpCallSpan;
    if (log < 5 or log > 22) return error.InvalidSecpGeometry;
    const n = @as(usize, 1) << @intCast(log);
    if (try std.math.mul(usize, calls, program.rows(kind == .product)) >= n) return error.InvalidSecpGeometry;
    if (try byteMass(kind, log) >= modulus) return error.SecpLookupMassExceeded;
}
pub fn byteMass(kind: Kind, log: u32) !u64 {
    if (log > 31) return error.InvalidSecpGeometry;
    return std.math.mul(u64, byteCount(kind), @as(u64, 1) << @intCast(log));
}
/// The shared coordinator must admit ALL consumers of the same lookup family.
/// Per-bin bounds alone permit characteristic cancellation across components.
pub const RosterItem = struct { kind: Kind, program: *const P.Program, calls: usize, first_id: u32, log: u32 };
pub const Mass = struct { bytes: u64 = 0, wires: u64 = 0 };
pub fn admitRoster(items: []const RosterItem, other_byte_requests: []const u64) !Mass {
    var total = Mass{};
    for (items) |item| {
        try validate(item.kind, item.program, item.calls, item.first_id, item.log);
        total.bytes = try std.math.add(u64, total.bytes, try byteMass(item.kind, item.log));
        var per: u64 = 0;
        for (0..item.program.rows(item.kind == .product)) |i| {
            const op = item.program.operation(item.kind == .product, i);
            per = try std.math.add(u64, per, 1 + @as(u64, @intFromBool(op.rhs == .wire)) + item.program.uses[op.result]);
        }
        total.wires = try std.math.add(u64, total.wires, try std.math.mul(u64, per, @intCast(item.calls)));
    }
    for (other_byte_requests) |mass| total.bytes = try std.math.add(u64, total.bytes, mass);
    if (total.bytes >= core.fields.m31.Modulus or total.wires >= core.fields.m31.Modulus) return error.SecpLookupMassExceeded;
    return total;
}
