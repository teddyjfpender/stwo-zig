//! Actual compact-owner wide proofs: parity is checked with the durable codec.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("om31_stark_test.zig");
const Codec = @import("stwo_proof_wire").ForField(core.fields.om31.OM31);
const A = std.testing.allocator;
fn parity(a: std.mem.Allocator, fold: u32, mixed: bool) !void {
    var retained = if (mixed) try Base.produceMixedWithStorage(a, fold, false, null) else try Base.produceTraceWithStorage(a, false, fold, false, null);
    defer retained.deinit(a);
    var compact = if (mixed) try Base.produceMixedWithStorage(a, fold, true, null) else try Base.produceTraceWithStorage(a, false, fold, true, null);
    defer compact.deinit(a);
    const expected = try Codec.encodeProofBytesBinary(a, retained.proof);
    defer a.free(expected);
    const actual = try Codec.encodeProofBytesBinary(a, compact.proof);
    defer a.free(actual);
    try std.testing.expectEqualSlices(u8, expected, actual);
    const decoded = try Codec.decodeProofBytesBinary(a, actual);
    if (mixed) try Base.verifyMixed(a, decoded, fold) else try Base.verifyFold(a, decoded, fold);
    std.debug.print("OM31_COMPACT_PARITY fold={d} mixed={} bytes={d}\n", .{ fold, mixed, actual.len });
}
test "OM31 compact full STARK preserves durable bytes and fresh verification fold1 fold4 mixed" {
    for ([_]u32{ 1, 4 }) |fold| {
        try parity(A, fold, false);
        try parity(A, fold, true);
    }
}
fn lifecycle(a: std.mem.Allocator) !void {
    var proof = try Base.produceTraceWithStorage(a, false, 1, true, null);
    defer proof.aux.deinit(a);
    try Base.verifyFold(a, proof.proof, 1);
}
test "OM31 compact pipeline all allocation failures release owners" {
    try std.testing.checkAllAllocationFailures(A, lifecycle, .{});
}
test "OM31 aggregate quotient byte budget refuses before group materialization" {
    try std.testing.expectError(error.QuotientScratchBudgetExceeded, Base.produceTraceWithStorage(A, false, 1, true, 1));
}

test "OM31 hybrid retained and compact mixed-height inputs preserve bytes" {
    for ([_]u32{ 1, 4 }) |fold| {
        var retained = try Base.produceMixedWithStorage(A, fold, false, null);
        defer retained.deinit(A);
        // Mainlog5 is retained (LDElog6); Mainlog6 and composition (LDElog7)
        // are compact. This is the production threshold geometry in miniature.
        var hybrid = try Base.produceMixedWithStorageThreshold(A, fold, true, null, 7);
        defer hybrid.deinit(A);
        const expected = try Codec.encodeProofBytesBinary(A, retained.proof);
        defer A.free(expected);
        const actual = try Codec.encodeProofBytesBinary(A, hybrid.proof);
        defer A.free(actual);
        try std.testing.expectEqualSlices(u8, expected, actual);
        const decoded = try Codec.decodeProofBytesBinary(A, actual);
        try Base.verifyMixed(A, decoded, fold);
        std.debug.print("OM31_HYBRID_PARITY fold={d} bytes={d}\n", .{ fold, actual.len });
    }
}

test "OM31 quotient domain geometry is rejected before constructing a canonic domain" {
    const engine = @import("stwo_prover_engine");
    const O = core.fields.om31.OM31;
    const Provider = engine.pcs.quotient_ops.ForField(O).LazyQuotientProvider;
    var columns = [_][]const engine.pcs.ColumnEvaluation{};
    var points = [_][][]core.circle.CirclePoint(O){};
    var values = [_][][]O{};
    for ([_]u32{ 0, 31, 63 }) |log| try std.testing.expectError(error.InvalidColumnLogSize, Provider.init(A, core.pcs.TreeVec([]const engine.pcs.ColumnEvaluation).initOwned(&columns), core.pcs.TreeVec([][]core.circle.CirclePoint(O)).initOwned(&points), core.pcs.TreeVec([][]O).initOwned(&values), O.one(), log));
}
