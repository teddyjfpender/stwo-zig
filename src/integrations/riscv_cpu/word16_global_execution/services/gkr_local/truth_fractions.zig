//! Separate proof-local truth namespaces. No RAM/KIO/Wire term enters this
//! catalog; original tuple/byte authorities and padded query weights are kept.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
pub const Relation = enum {
    chi,
    xor5,
    byte,
    pub fn arity(self: @This()) usize {
        return if (self == .byte) 1 else 6;
    }
};
pub const MAX_ARITY = 6;
pub fn ChallengesFor(comptime C: type) type {
    comptime if (E.extensionDegree(C) != 8) @compileError("truth GKR scope requires explicit degree-eight field");
    return struct {
        /// Main modular-product compression challenge, independent of globalWire.
        polynomial: C,
        offsets: [3]C,
        coefficients: [3][MAX_ARITY]C,
        /// Caller first binds its OWN sealed truth MAIN, expected statement,
        /// shape, source identity and ordinal. This does not replace that gate.
        pub fn draw(channel: anytype) @This() {
            channel.mixU32s(&.{ 0x54474b31, 8, 3, 0x43484936, 0x584f5235, 0x42595445 });
            var out: @This() = undefined;
            channel.mixU32s(&.{0x504f4c59});
            out.polynomial = channel.drawSecureFelt();
            for (std.enums.values(Relation)) |relation| {
                const index = @intFromEnum(relation);
                channel.mixU32s(&.{ @intCast(index), @intCast(relation.arity()) });
                out.offsets[index] = channel.drawSecureFelt();
                out.coefficients[index] = @splat(C.zero());
                for (0..relation.arity()) |i| out.coefficients[index][i] = if (relation == .byte) C.one() else channel.drawSecureFelt();
            }
            return out;
        }
        pub fn denominatorBase(self: *const @This(), relation: Relation, tuple: anytype) C {
            std.debug.assert(tuple.len == relation.arity());
            const index = @intFromEnum(relation);
            var d = self.offsets[index];
            for (tuple, 0..) |v, i| d = d.sub(self.coefficients[index][i].mulM31(v));
            return d;
        }
        pub fn denominatorFor(self: *const @This(), comptime F: type, relation: Relation, tuple: anytype) E.SecureFor(F) {
            std.debug.assert(tuple.len == relation.arity());
            const index = @intFromEnum(relation);
            return E.denominatorFor(F, self.offsets[index], self.coefficients[index][0..relation.arity()], tuple[0..], true);
        }
    };
}
/// Negative round-active coefficient exactly matches the existing permutation
/// emitter. Zero-weight real queries still exist; only UNUSED fact lanes pad0/1.
pub fn keccakFor(comptime F: type, row: K.equations.RowFor(F), sink: anytype) void {
    return keccakForPolicy(F, .triple_v2, row, sink);
}
pub fn keccakForPolicy(comptime F: type, policy: K.equations.BatchPolicy, row: K.equations.RowFor(F), sink: anytype) void {
    const weight = K.equations.roundActiveFor(F, row).neg();
    if (policy.throughputTables()) {
        for (0..policy.lookups()) |event| sink.emit(if (event < policy.chiLookups()) .chi else .xor5, K.equations.throughputTupleFor(F, row.main[0..K.layout.STATE], row.main[K.layout.STATE..K.layout.ACTIVE_A], row.state_plus_one, row.fixed[2..26], event), weight);
        return;
    }
    for (0..K.layout.STATE) |event| sink.emit(.chi, K.equations.lookupTupleFor(F, row, event), weight);
    for (0..K.layout.PARITY) |event| sink.emit(.xor5, K.equations.lookupTupleFor(F, row, K.layout.STATE + event), weight);
}
pub fn keccakTableFor(comptime F: type, kind: K.component.Kind, tuple: [6]F, multiplicity: F, sink: anytype) void {
    std.debug.assert(kind == .chi or kind == .xor5);
    sink.emit(if (kind == .chi) .chi else .xor5, tuple, multiplicity);
}
pub fn secpFor(comptime F: type, kind: S.layout.Kind, policy: S.layout.BytePolicy, main: []const F, sink: anytype) void {
    for (0..S.layout.byteCountFor(kind, policy)) |index| sink.emit(.byte, [1]F{S.equations.byteForPolicy(F, kind, policy, main, index)}, F.one());
}
pub fn byteTableFor(comptime F: type, value: F, multiplicity: F, sink: anytype) void {
    sink.emit(.byte, [1]F{value}, multiplicity.neg());
}
