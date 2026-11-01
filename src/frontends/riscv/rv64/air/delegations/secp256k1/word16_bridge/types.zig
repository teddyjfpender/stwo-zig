const std = @import("std");
const E = @import("../../../evaluation.zig");
const R = @import("../../../memory/closed_ram/mod.zig");
const Owner = @import("../../../memory/load_store_v2/types.zig");
const S = @import("../../../providers/scalar_range.zig");
const P = @import("../program.zig");
const L = @import("layout.zig");
pub const Q = E.Q;
pub const Call = struct { pointer: u64, epoch: u16, tick: u24, before: [24]u64, after: [24]u64, predecessors: [24]R.types.State };
/// Challenges over constant lane C (QM31 natively, a circuit wire lane for
/// recursion). The native layout is unchanged: `Challenges = ChallengesFor(Q)`.
pub fn ChallengesFor(comptime C: type) type {
    return struct { ram: R.types.RamChallengesFor(C), owner: Owner.OwnerChallengesFor(C), wire: @import("../equations.zig").WireFor(C), range16: S.ChallengesFor(C), range8: S.ChallengesFor(C) };
}
pub const Challenges = ChallengesFor(Q);
/// The five physical claims over constant lane C, in transcript order.
pub fn ClaimsFor(comptime C: type) type {
    return struct {
        ram: C,
        owner: C,
        wire: C,
        range16: C,
        range8: C,
        pub fn zero() @This() {
            return .{ .ram = C.zero(), .owner = C.zero(), .wire = C.zero(), .range16 = C.zero(), .range8 = C.zero() };
        }
        pub fn values(self: @This()) [5]C {
            return .{ self.ram, self.owner, self.wire, self.range16, self.range8 };
        }
    };
}
pub const Claims = ClaimsFor(Q);
/// Wire35 packet bridges. ADD/DOUBLE keep the secp program kinds 1/2; the
/// SHA-256 compression packet (admitted by `ethereum_services_v3`) is kind 3:
/// three 32-byte coordinates (state, message halves), only the state written.
/// The arith256_mod packet (v3) is kind 4: five coordinates a, b, c, m, r,
/// only the trailing r written (its before-value is still a Wire35 input).
pub const Kind = enum(u8) { add = 1, double = 2, sha256 = 3, arith256_mod = 4 };
pub fn kindOf(kind: P.Kind) Kind {
    return @enumFromInt(@intFromEnum(kind));
}
fn program(kind: Kind) *const P.Program {
    return P.get(@enumFromInt(@intFromEnum(kind)));
}
pub fn tag(kind: Kind) u32 {
    return switch (kind) {
        .add => 0x20011,
        .double => 0x20012,
        .sha256 => 0x30010,
        .arith256_mod => 0x30021,
    };
}
pub fn coordinates(kind: Kind) usize {
    return switch (kind) {
        .sha256 => 3,
        .arith256_mod => 5,
        else => program(kind).inputs,
    };
}
/// Number of coordinates that the service overwrites (ADD/DOUBLE: X, Y, Z).
pub fn written(kind: Kind) usize {
    return switch (kind) {
        .sha256, .arith256_mod => 1,
        else => 3,
    };
}
/// Whether coordinate `coord` is overwritten: the leading `written` ones,
/// except arith256_mod whose single output r is the last coordinate.
pub fn isWritten(kind: Kind, coord: usize) bool {
    return if (kind == .arith256_mod) coord == 4 else coord < written(kind);
}
/// Wire35 ID of the after-value of written coordinate `coord`.
pub fn outputWire(kind: Kind, coord: usize) u32 {
    return switch (kind) {
        .sha256 => 3,
        .arith256_mod => 5,
        else => program(kind).outputs[coord],
    };
}
pub fn validateGeometry(kind: Kind, calls: usize, first_id: u32, log: u32) !usize {
    const n = try @import("../../../memory/load_store_v2/source.zig").sizeForLog(log);
    if (calls > (n - 1) / coordinates(kind) or first_id == 0 or first_id >= @import("stwo_core").fields.m31.Modulus or calls > @import("stwo_core").fields.m31.Modulus - first_id) return error.InvalidWord16SecpGeometry;
    if (L.U16.len * @as(u64, n) >= @import("stwo_core").fields.m31.Modulus or L.U8.len * @as(u64, n) >= @import("stwo_core").fields.m31.Modulus) return error.Word16SecpMassBound;
    return n;
}
