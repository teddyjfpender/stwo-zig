const std = @import("std");
const F = @import("fixture.zig");
const Native = @import("recursive_statement.zig");
const G = @import("../protocol.zig");
const a = std.testing.allocator;

test "Word16 span reference folds two authentic native CPU boundaries with Keccak and secp truth closure" {
    var c = try F.Case.init(a);
    defer c.deinit();
    const setups = c.keys();
    const truths = c.truths();
    const result = try Native.verifyNativeAndFold(a, &setups, &truths, c.expected(), &c.bundle);
    try std.testing.expectEqual(@as(u32, 2), result.span.cpu_count);
    try std.testing.expectEqual(@as(u32, 3), result.truth_proofs);
    try std.testing.expectEqual(@as(u64, 7), result.span.steps);
    try std.testing.expectEqual(@as(u32, 1), result.span.first_epoch);
    try std.testing.expectEqual(@as(u32, 3), result.span.end_epoch_exclusive);
    try std.testing.expect(!Native.NativeRoot.recursively_verified);
    try std.testing.expect(!Native.NativeRoot.whole_protocol_128_qualified);
    const expected = c.expected();
    const left = try Native.fromPublicCpu(expected, c.bundle.cpus[0], 0, 0);
    const right = try Native.fromPublicCpu(expected, c.bundle.cpus[1], 1, left.steps);
    try std.testing.expectEqualDeep(result.span, try Native.fold(left, right));
    try std.testing.expectEqualDeep(result, try Native.closePublic(expected, result.span, &truths, c.bundle.truths));

    var gap = right;
    gap.first_step += 1;
    try std.testing.expectError(error.Word16FoldNonadjacent, Native.fold(left, gap));
    gap = right;
    gap.first_pc += 4;
    try std.testing.expectError(error.Word16FoldNonadjacent, Native.fold(left, gap));
    gap = right;
    gap.first_registers[10] ^= 1;
    try std.testing.expectError(error.Word16FoldNonadjacent, Native.fold(left, gap));
    gap = right;
    gap.program[0] ^= 1;
    try std.testing.expectError(error.Word16FoldIdentityMismatch, Native.fold(left, gap));
    try std.testing.expectError(error.Word16FoldNonadjacent, Native.fold(right, left));
    try std.testing.expectError(error.Word16RootIncompleteExecution, Native.closePublic(expected, left, &truths, c.bundle.truths));
    var modified = result.span;
    modified.ram = G.Q.one();
    try std.testing.expectError(error.Word16RootUnclosedRam, Native.closePublic(expected, modified, &truths, c.bundle.truths));
    modified = result.span;
    modified.keccak_io = modified.keccak_io.add(G.Q.one());
    try std.testing.expectError(error.Word16RootUnclosedKeccakIo, Native.closePublic(expected, modified, &truths, c.bundle.truths));
    modified = result.span;
    modified.secp_wire = modified.secp_wire.add(G.Q.one());
    try std.testing.expectError(error.Word16RootUnclosedSecpWire, Native.closePublic(expected, modified, &truths, c.bundle.truths));
    try std.testing.expectError(error.Word16RootTruthRosterMismatch, Native.closePublic(expected, result.span, truths[0..2], c.bundle.truths));
}

test "Word16 native-verifying fold refuses balanced unproven claim substitution and omitted physical proofs" {
    var c = try F.Case.init(a);
    defer c.deinit();
    const setups = c.keys();
    const truths = c.truths();
    const root = try Native.verifyNativeAndFold(a, &setups, &truths, c.expected(), &c.bundle);
    // Pure host folding is not proof verification; this checks the actual
    // verifying entry, which must reject despite zero changed global sum.
    const delta = G.Q.one();
    c.bundle.cpus[0].claims.extras[0].truth = c.bundle.cpus[0].claims.extras[0].truth.add(delta);
    c.bundle.cpus[1].claims.extras[0].truth = c.bundle.cpus[1].claims.extras[0].truth.sub(delta);
    if (Native.verifyNativeAndFold(a, &setups, &truths, c.expected(), &c.bundle)) |_|
        return error.Word16FoldAcceptedForgedBalancedClaims
    else |_| {}
    c.bundle.cpus[0].claims.extras[0].truth = c.bundle.cpus[0].claims.extras[0].truth.sub(delta);
    c.bundle.cpus[1].claims.extras[0].truth = c.bundle.cpus[1].claims.extras[0].truth.add(delta);
    const saved = c.bundle.truths;
    c.bundle.truths = saved[0..2];
    if (Native.verifyNativeAndFold(a, &setups, &truths, c.expected(), &c.bundle)) |_|
        return error.Word16FoldAcceptedMissingTruthProof
    else |_| {}
    c.bundle.truths = saved;
    try std.testing.expectEqualDeep(root, try Native.verifyNativeAndFold(a, &setups, &truths, c.expected(), &c.bundle));
}
