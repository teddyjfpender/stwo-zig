//! Canonical private BN254 scalar writer. Shared source-only authority; caller
//! owns immutable IDs/fanout, BYTE and SSA binding, and every use equation.
const std = @import("std");
const B = @import("../curves/spec.zig");
const E = @import("../../evaluation.zig");
pub const MODULUS = B.BN254_P;
pub const OUTPUT = 0;
pub const DISTANCE = 32;
pub const CARRY = 64; // c1..c31, c0=active, c32=0
pub const MAIN = 95;
pub const FIXED = 3;
pub const ACTIVE = 0;
pub const WRITER_ID = 1;
pub const FANOUT = 2;
pub const BYTE_QUERIES = 64;
pub const CONSTRAINTS = 127;
pub const MAX_INTEGER_RESIDUAL = 511;
pub const Row = [MAIN]u32;
pub const Fixed = [FIXED]u32;
fn k(comptime F: type, value: u32) F {
    return E.qFor(F, value);
}
pub fn byteQuery(comptime F: type, v: anytype, index: usize) F {
    std.debug.assert(index < BYTE_QUERIES);
    return v.main(index);
}
pub fn emitCanonical(comptime F: type, v: anytype, sink: anytype) void {
    const active = v.fixed(ACTIVE);
    for (0..64) |i| sink.emit(F.one().sub(active).mul(v.main(i)));
    for (0..31) |i| {
        const carry = v.main(CARRY + i);
        sink.emit(carry.mul(carry.sub(active)));
    }
    for (0..32) |i| {
        const before = if (i == 0) active else v.main(CARRY + i - 1);
        const after = if (i == 31) F.zero() else v.main(CARRY + i);
        const residual = v.main(OUTPUT + i).add(v.main(DISTANCE + i)).add(before).sub(active.mul(k(F, B.limbOf(MODULUS, i)))).sub(after.mul(k(F, 256)));
        sink.emit(residual);
    }
}
/// Producer tuple is source namespace/call + immutable writer ID + canonical
/// bytes. Namespace/call must be pinned by the caller, not witness advice.
pub fn ssaTuple(comptime F: type, v: anytype, namespace: F, call: F) [35]F {
    var tuple: [35]F = undefined;
    tuple[0] = namespace;
    tuple[1] = call;
    tuple[2] = v.fixed(WRITER_ID);
    for (0..32) |i| tuple[3 + i] = v.main(OUTPUT + i);
    return tuple;
}
pub fn ssaWeight(comptime F: type, v: anytype) F {
    return v.fixed(ACTIVE).mul(v.fixed(FANOUT));
}
pub fn sourceDigest() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("bn254-private-canonical-writer/v1");
    var modulus: [32]u8 = undefined;
    std.mem.writeInt(u256, &modulus, MODULUS, .little);
    h.update(&modulus);
    h.update(@embedFile("source.zig"));
    return h.finalResult();
}
