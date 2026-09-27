//! SHA shares VM buses, but never the BLAKE3 provider's internal wire challenge.
const std = @import("std");
const core = @import("stwo_core");
const universal = @import("../../recursion/air/universal_challenges.zig");
const relation = @import("../lang/relation.zig");
const Q = core.fields.qm31.QM31;
pub const draw_count = 2;

/// Invoke after the complete main commitment, on both prover and verifier.
/// The caller's versioned transcript owns placement of this frame.
pub fn draw(a: std.mem.Allocator, channel: anytype, vm: universal.UniversalRelations) !universal.UniversalRelations {
    try vm.validate();
    channel.mixU32s(&.{ 0x53484157, 1 }); // SHAW, wire challenge schema 1
    const values = try channel.drawSecureFelts(a, draw_count);
    defer a.free(values);
    if (values.len != draw_count) return error.InvalidShaChallengeDraw;
    return fromDraws(vm, values[0..draw_count].*);
}

pub fn fromDraws(vm: universal.UniversalRelations, values: [draw_count]Q) !universal.UniversalRelations {
    try vm.validate();
    const wire = try vm.getExact(.recursion_wire);
    var result = vm;
    result.elements[@intFromEnum(relation.Domain.recursion_wire)] = universal.Elements.init(wire.arity, values[0], values[1]);
    return result;
}

test "SHA provider wires are independent while all VM tuple challenges remain shared" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const vm = try universal.UniversalRelations.draw(std.testing.allocator, &channel);
    var verifier_channel = channel;
    const sha = try draw(std.testing.allocator, &channel, vm);
    const expected = try draw(std.testing.allocator, &verifier_channel, vm);
    try std.testing.expect(std.meta.eql(sha, expected));
    const index = @intFromEnum(relation.Domain.recursion_wire);
    for (vm.elements, sha.elements, 0..) |left, right, i| {
        if (i != index) try std.testing.expect(std.meta.eql(left, right));
    }
    const tuple = [_]core.fields.m31.M31{ .fromCanonical(17), .fromCanonical(1), .fromCanonical(2), .fromCanonical(3), .fromCanonical(4), .fromCanonical(5) };
    const vm_denominator = try vm.get(.recursion_wire).combineBase(&tuple);
    const sha_denominator = try sha.get(.recursion_wire).combineBase(&tuple);
    try std.testing.expect(!vm_denominator.eql(sha_denominator));
}
