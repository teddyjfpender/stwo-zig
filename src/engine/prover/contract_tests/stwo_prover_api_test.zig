//! Transaction semantics the generic prover consumes from its API owner.
const std = @import("std");
const api = @import("stwo_prover_api");
const core = @import("stwo_core");

test "cdc: prover column lifting preserves pairs and rejects bad ingress without mutation" {
    const F = core.fields.m31.M31;
    const values = [_]F{ F.fromCanonical(1), F.fromCanonical(2), F.fromCanonical(3), F.fromCanonical(4) };
    const column = api.ColumnEvaluation{ .log_size = 2, .values = &values };
    for (0..16) |position| {
        const expected = values[((position >> 3) << 1) + (position & 1)];
        try std.testing.expectEqual(expected, try column.valueAtLiftingPosition(4, position));
    }
    try std.testing.expectError(error.ShapeMismatch, column.valueAtLiftingPosition(4, 16));
    try std.testing.expectError(error.InvalidColumnLogSize, column.valueAtLiftingPosition(1, 0));
    const short = api.ColumnEvaluation{ .log_size = 2, .values = values[0..2] };
    try std.testing.expectError(error.InvalidColumnLength, short.validate());
    try std.testing.expectEqual(@as(u32, 1), values[0].v);
}

test "cdc: prover diagnostics retain the first original failure" {
    var diagnostic: ?api.ProveDiagnostic = null;
    api.ProveDiagnostic.recordFirst(&diagnostic, .tree1, error.OutOfMemory);
    api.ProveDiagnostic.recordFirst(&diagnostic, .finalize, error.ShapeMismatch);
    try std.testing.expectEqual(api.ProvePhase.tree1, diagnostic.?.phase);
    try std.testing.expectEqual(error.OutOfMemory, diagnostic.?.cause);
    api.ProveDiagnostic.recordFirst(null, .tree1, error.OutOfMemory);
}
