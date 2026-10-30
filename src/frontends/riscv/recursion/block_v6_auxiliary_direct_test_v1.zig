const std = @import("std");
const Bus = @import("block_v6_auxiliary_direct_public_v1.zig");
const Prep = @import("block_v6_auxiliary_direct_prepare_v1.zig");

test "auxiliary direct batch compiles original caller and raw fold PAGE preparation and rejects empty roster" {
    try std.testing.expectError(error.InvalidAuxiliaryDirectCount, Prep.prepare(std.testing.allocator, &.{}, &.{}, 2));
}

test "auxiliary direct batch schedule retains family and duplicate namespace rejection" {
    var wires = [_]Bus.Wire{
        .{ .circuit = 1, .wire = 0, .uses = 1, .child = 0, .source = .{ .caller_arithmetic = .open_sum }, .coordinate = 0 },
        .{ .circuit = 2, .wire = 0, .uses = 1, .child = 1, .source = .{ .source_raw = .public_input }, .coordinate = 0 },
    };
    const original = try Bus.scheduleDigest(&wires);
    wires[1].source = .{ .source_fold = .public_input };
    try std.testing.expect(!std.meta.eql(original, try Bus.scheduleDigest(&wires)));
    wires[1].circuit = 1;
    try std.testing.expectError(error.InvalidAuxiliaryDirectSchedule, Bus.scheduleDigest(&wires));
    wires[1].circuit = 2;
    wires[0].coordinate = 1;
    try std.testing.expectError(error.InvalidCallerRecursiveSchedule, Bus.scheduleDigest(&wires));
}

test "auxiliary direct batch reconstruction rejects changed root routing with identical public data" {
    // Literal public framing is a negative transport fixture, not a proof.
    const Original = @import("../prover/block_v5_caller_fused_proof_v1.zig");
    const Q = @import("stwo_core").fields.qm31.QM31;
    var words: [36]u32 = @splat(0);
    words[0..4].* = .{ Original.TAG, Original.VERSION, 1, 0 };
    @memset(words[4..12], 1);
    @memset(words[12..20], 2);
    @memset(words[20..28], 3);
    var fields = [_]Q{Q.one()};
    const expected_child = Bus.Child{ .index = 0, .value = .{ .caller_fused = .{
        .allocator = std.testing.allocator,
        .template = @splat(4),
        .roots_count = 3,
        .public = &fields,
        .statement = .{ .allocator = std.testing.allocator, .words = &words, .felts = &.{}, .first = &.{}, .claims = &.{}, .sealed_offset = 28, .roots_offset = .{ 4, 12, 20 } },
    } } };
    const expected = Bus.Values{ .children = &.{expected_child} };
    var changed_child = expected_child;
    const wires = [_]Bus.Wire{.{ .circuit = 1, .wire = 0, .uses = 1, .child = 0, .source = .{ .caller_fused = .first_root }, .coordinate = 0 }};
    const actual = Bus.Values{ .children = @as(*const [1]Bus.Child, @ptrCast(&changed_child))[0..] };
    try actual.requireReconstructed(expected, &wires);
    changed_child.value.caller_fused.statement.roots_offset[0] = 12;
    try std.testing.expectError(error.UntrustedAuxiliaryDirectPublic, actual.requireReconstructed(expected, &wires));
}
