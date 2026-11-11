//! AIR boundary checks deliberately bypass native packet validation: acceptance
//! must come from the source-owned equations and authenticated range relations.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const S = A.crypto.secp256k1.word16_bridge;
const L = S.layout;
const E = A.evaluation;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const LAST_LEGAL: u64 = std.math.maxInt(u64) - (640 - 1);
pub fn call() S.types.TowerCall {
    var out = S.types.TowerCall{ .pointer = LAST_LEGAL, .epoch = 1, .tick = 4, .before = @splat(0), .after = @splat(0), .predecessors = @splat(.{ .value = 0, .rights = 1 }) };
    for (out.predecessors[0..48]) |*predecessor| predecessor.rights = 3;
    return out;
}
/// Forge consistent wrapped addresses and Boolean carries, rather than merely
/// changing one field. The terminal carry equation must still reject this.
pub fn poisonPointer(row: *[L.MAIN]M, coordinate: usize, hide_last_carry: bool) void {
    const pointer: u64 = std.math.maxInt(u64) - 31;
    const address = pointer +% @as(u64, @intCast(coordinate * 32));
    var carry: u64 = 0;
    for (0..4) |limb| {
        const p: u64 = @as(u16, @truncate(pointer >> @as(u6, @intCast(16 * limb))));
        const sum = p + (if (limb == 0) coordinate * 32 else carry);
        carry = sum >> 16;
        row[L.POINTER + limb] = M.fromCanonical(@intCast(p));
        row[L.ADDRESS + limb] = M.fromCanonical(@as(u16, @truncate(address >> @as(u6, @intCast(16 * limb)))));
        row[L.CARRY + limb] = M.fromCanonical(@intCast(carry));
    }
    for (L.ALIGN..L.MAIN, 5..) |column, bit| row[column] = M.fromCanonical(@intCast((pointer >> @as(u6, @intCast(bit))) & 1));
    if (hide_last_carry) row[L.CARRY + 3] = M.zero();
}
fn accepted(fixed: []const M, row: *const [L.MAIN]M, previous: *const [L.MAIN]M) bool {
    var f: [L.FIXED]Q = undefined;
    var main: [L.MAIN]Q = undefined;
    var prior: [L.MAIN]Q = undefined;
    for (&f, fixed) |*out, value| out.* = Q.fromBase(value);
    for (&main, row) |*out, value| out.* = Q.fromBase(value);
    for (&prior, previous) |*out, value| out.* = Q.fromBase(value);
    var residuals: [373]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    S.equations.emitMainFor(Q, .bn254_sparse034, &f, &main, &prior, .{ .calls = 1, .first_id = 1 }, &sink);
    std.debug.assert(sink.count == residuals.len);
    for (residuals) |value| if (!value.isZero()) {
        return false;
    };
    // The proof-local GKR range authority includes every pointer/address limb;
    // allowing arbitrary M31 values here would invalidate integer carry bounds.
    for (L.U16) |column| if (row[column].v >= 65536) {
        return false;
    };
    for (L.U8) |column| if (row[column].v >= 256) {
        return false;
    };
    return true;
}
test "OP640 bridge AIR rejects wrapped pointer and enforces readonly rights without native guards" {
    const a = std.testing.allocator;
    const fixed_columns = try S.source.fixed(a, .bn254_sparse034, 5);
    defer a.free(fixed_columns);
    const packet = call();
    try S.source.validateTower(.bn254_sparse034, packet);
    for (0..20) |coordinate| {
        const row = S.source.nativeTowerRow(packet, coordinate, 1);
        const previous = if (coordinate == 0) [_]M{M.zero()} ** L.MAIN else S.source.nativeTowerRow(packet, coordinate - 1, 1);
        var fixed: [L.FIXED]M = undefined;
        const physical = A.memory.closed_ram.trace.physical(coordinate, 5);
        for (&fixed, 0..) |*value, column| value.* = fixed_columns[column * 32 + physical];
        try std.testing.expect(accepted(&fixed, &row, &previous));
        if (coordinate > 0) {
            var forged = row;
            var forged_previous = previous;
            poisonPointer(&forged, coordinate, false);
            poisonPointer(&forged_previous, coordinate - 1, false);
            try std.testing.expect(!accepted(&fixed, &forged, &forged_previous));
            poisonPointer(&forged, coordinate, true);
            poisonPointer(&forged_previous, coordinate - 1, true);
            try std.testing.expect(!accepted(&fixed, &forged, &forged_previous));
        }
        var forbidden = row;
        if (coordinate < 12) {
            forbidden[L.WRITABLE + 2] = M.zero();
            try std.testing.expect(!accepted(&fixed, &forbidden, &previous));
        } else {
            try std.testing.expectEqual(M.zero(), row[L.WRITE]);
            for (0..4) |lane| try std.testing.expectEqual(M.zero(), row[L.WRITABLE + lane]);
            // READ-only service transitions still advance to this call's tick.
            const ram = S.equations.ramRow(Q, &lift(row), 2);
            try std.testing.expectEqual(Q.fromBase(M.fromCanonical(1)), ram[9]);
            try std.testing.expectEqual(Q.fromBase(M.fromCanonical(4)), ram[12]);
            forbidden[L.AFTER] = M.one();
            try std.testing.expect(!accepted(&fixed, &forbidden, &previous));
            forbidden = row;
            forbidden[L.WRITE] = M.one();
            try std.testing.expect(!accepted(&fixed, &forbidden, &previous));
        }
        forbidden = row;
        forbidden[L.READABLE + 2] = M.zero();
        try std.testing.expect(!accepted(&fixed, &forbidden, &previous));
    }
}
fn lift(row: [L.MAIN]M) [L.MAIN]Q {
    var out: [L.MAIN]Q = undefined;
    for (&out, row) |*value, x| value.* = Q.fromBase(x);
    return out;
}
