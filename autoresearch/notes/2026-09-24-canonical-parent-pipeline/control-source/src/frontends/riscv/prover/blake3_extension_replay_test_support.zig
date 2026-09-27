//! Fast recursive-verifier regression without proving another parent.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
pub fn check(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8) !void {
    var composition = try @import("../recursion/air/blake3_execution_composition.zig").prepare(a, admitted, capture, expected);
    defer composition.deinit();
    try composition.validate(a, admitted, capture, expected);
    var deep = try @import("../recursion/air/blake3_execution_deep.zig").prepare(a, admitted, capture, expected);
    defer deep.deinit();
    var transcript = try @import("../recursion/air/blake3_execution_transcript.zig").planReplay(a, admitted, capture, expected, 2);
    defer transcript.deinit();
    // Claims are circuit inputs linked to the transcript, not specialized
    // constants. Perturb the last component total while keeping samples fixed.
    var last_claim: ?usize = null;
    for (composition.sources, 0..) |source, index| if (source == .claim) {
        last_claim = index;
    };
    const index = last_claim orelse return error.MissingClaimInput;
    if (admitted.ranges != null) {
        const extended = comptime @import("../recursion/air/blake3_execution_profile.zig").isExtension(@TypeOf(capture.*));
        const shape = if (extended) &admitted.native else &admitted.shape;
        const compact_index = @import("blake3_execution_codec.zig").claimCount(shape);
        var target: ?usize = null;
        for (composition.sources, 0..) |source, i| {
            if (source == .claim and source.claim == compact_index) target = i;
        }
        const node = target orelse return error.MissingCompactClaimInput;
        const saved = composition.inputs[node];
        composition.inputs[node] = saved.add(Q.one());
        defer composition.inputs[node] = saved;
        const scratch = try a.alloc(Q, composition.values.len);
        defer a.free(scratch);
        try std.testing.expectError(error.UnsatisfiedCircuit, composition.circuit.evaluateInto(composition.inputs, scratch));
    }
    const original = composition.inputs[index];
    composition.inputs[index] = original.add(Q.one());
    defer composition.inputs[index] = original;
    const scratch = try a.alloc(Q, composition.values.len);
    defer a.free(scratch);
    try std.testing.expectError(error.UnsatisfiedCircuit, composition.circuit.evaluateInto(composition.inputs, scratch));
    std.debug.print("BLAKE3_EXTENSION_REPLAY composition=true deep=true transcript=true changed_claim_rejected=true\n", .{});
}
