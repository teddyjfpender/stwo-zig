//! Algebra and authentic typed-tuple extraction, not a complete original proof.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Guard = @import("../block_v8_caller_halt_policy_v1.zig");
const Access = @import("../block_execution_access_bridge_v2.zig");
fn q(v: u32) Q {
    return Q.fromBase(M.fromCanonical(v));
}
fn pair(address: u32, after: u32) Access.Pair(Q) {
    return .{ .active = Q.one(), .space = Q.one(), .source_address = q(address), .address_unit = .byte_address, .local_clock = q(6), .consume_clock = q(0), .before = @splat(Q.zero()), .after = .{ q(after & 255), q((after >> 8) & 255), q((after >> 16) & 255), q(after >> 24) }, .pair_residuals = @splat(Q.zero()), .access_ordinal = null };
}
fn accepted(row: Access.Pair(Q), aux: [2]Q) !bool {
    for (try Guard.constraints(Q, .{ .halt_address = 0x100 }, row, q(2), aux)) |residual| if (!residual.isZero()) return false;
    return true;
}
test "caller first halt rejects transient writes even when final endpoint is zero" {
    const policy = Guard.Policy{ .halt_address = 0x100 };
    const write = pair(0x100, 1);
    const clear = pair(0x100, 0);
    const w = try Guard.witness(write, policy);
    const c = try Guard.witness(clear, policy);
    try std.testing.expect(!try accepted(write, .{ Q.fromBase(w[0]), Q.fromBase(w[1]) }));
    try std.testing.expect(try accepted(clear, .{ Q.fromBase(c[0]), Q.fromBase(c[1]) }));
    // A dishonest producer cannot pretend the exact address was a miss.
    try std.testing.expect(!try accepted(write, .{ Q.zero(), Q.zero() }));
    var nonzero_read = write;
    nonzero_read.before = write.after;
    try std.testing.expect(!try accepted(nonzero_read, .{ Q.one(), Q.zero() }));
    for (0..4) |byte| {
        var forged = clear;
        forged.after[byte] = q(255);
        try std.testing.expect(!try accepted(forged, .{ Q.one(), Q.zero() }));
    }
}
test "caller halt inverse and inactivity are canonical but non-halt writes remain legal" {
    var row = pair(0x104, 0xffffffff);
    const w = try Guard.witness(row, .{ .halt_address = 0x100 });
    try std.testing.expect(try accepted(row, .{ Q.fromBase(w[0]), Q.fromBase(w[1]) }));
    try std.testing.expect(!try accepted(row, .{ Q.one(), Q.zero() }));
    row.active = Q.zero();
    try std.testing.expect(try accepted(row, .{ Q.zero(), Q.zero() }));
    try std.testing.expect(!try accepted(row, .{ Q.zero(), Q.one() }));
    row.active = q(2);
    try std.testing.expectError(error.InvalidCallerHaltActive, Guard.witness(row, .{ .halt_address = 0x100 }));
    row = pair(0x100, 0);
    row.address_unit = .word_index;
    try std.testing.expectError(error.InvalidCallerHaltAccess, Guard.witness(row, .{ .halt_address = 0x100 }));
    row.address_unit = .byte_address;
    row.consume_clock = null;
    try std.testing.expectError(error.InvalidCallerHaltAccess, Guard.witness(row, .{ .halt_address = 0x100 }));
    try std.testing.expectError(error.UnqualifiedCallerTerminalHaltPolicy, Guard.validate(.{ .halt_address = 0x100, .permitted_final_instruction_cycle = 2 }));
}
test "caller halt OODS evaluator preserves algebraic enablers and extension values" {
    var row = pair(0x104, 0);
    row.active = Q.fromU32Unchecked(3, 5, 7, 11);
    row.source_address = Q.fromU32Unchecked(13, 17, 19, 23);
    row.after = .{ Q.fromU32Unchecked(29, 31, 37, 41), q(7), q(5), q(3) };
    const aux = [2]Q{ Q.fromU32Unchecked(43, 47, 53, 59), Q.fromU32Unchecked(61, 67, 71, 73) };
    const got = try Guard.constraints(Q, .{ .halt_address = 0x100 }, row, q(2), aux);
    const expected = @import("../block_v8_native_halt_policy_v1.zig").constraints(Q, .{ .halt_address = 0x100 }, row.active, row.source_address, q(2), row.after, aux);
    try std.testing.expectEqualDeep(expected, got);
}
