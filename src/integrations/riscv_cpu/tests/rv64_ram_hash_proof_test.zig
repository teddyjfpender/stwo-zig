const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const ram = frontend.rv64_air.memory;
const proof = @import("../rv64_ram_hash_proof.zig");

test "RV64 RAM public ledger hash STARK freshly verifies and rejects unused-output and image substitutions" {
    const a = std.testing.allocator;
    var memory = frontend.rv64.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 8, .permissions = .{ .read = true, .write = true } });
    try memory.store(0x1000, 8, 17);
    var witness = try ram.transition.Witness.build(a, &memory, &.{1}, &.{.{ .address = 0x1000, .value = 19, .byte_mask = 1 }});
    defer witness.deinit();
    try memory.store(0x1000, 8, 19);
    var final = try ram.image.snapshot(a, &memory);
    defer final.deinit();
    const encoded = try proof.prove(a, &witness);
    defer a.free(encoded);
    // prove() releases the complete PCS owner; verify() reconstructs setup,
    // transcript, graph and request sum from these bytes and boundary inputs.
    const updates = [_]ram.transition.NetUpdate{.{ .address = 0x1000, .value = 19, .byte_mask = 1 }};
    try proof.verify(a, &witness, witness.before, final.root(), &.{1}, &updates, encoded);
    try std.testing.expectError(error.InvalidRamHashProofShape, proof.verifyReceipt(a, &witness, witness.before, final.root(), &.{1}, &updates, encoded));
    try std.testing.expectError(error.UnexpectedRamNetUpdate, proof.verify(a, &witness, witness.before, final.root(), &.{1}, &.{}, encoded));
    const changed = try a.dupe(u8, encoded);
    defer a.free(changed);
    const calls = std.mem.readInt(u32, changed[4..8], .little);
    const unused_output = 8 + (@as(usize, calls) - 1) * 64 + 15 * 4;
    const old = std.mem.readInt(u32, changed[unused_output..][0..4], .little);
    std.mem.writeInt(u32, changed[unused_output..][0..4], (old + 1) % @import("stwo_core").fields.m31.Modulus, .little);
    if (proof.verify(a, &witness, witness.before, final.root(), &.{1}, &updates, changed)) |_| return error.ExpectedFullIoRejection else |_| {}
    const M = @import("stwo_core").fields.m31.M31;
    const ledger = try a.alloc([16]M, calls);
    defer a.free(ledger);
    for (ledger, 0..) |*state, i| {
        for (state, 0..) |*word, lane|
            word.* = M.fromCanonical(std.mem.readInt(u32, changed[8 + i * 64 + lane * 4 ..][0..4], .little));
    }
    // This capacity word does not affect the digest or any later graph node.
    // Seal it into a NEW transcript: the real provider must still reject it,
    // independently of rejection from editing an old proof's transcript.
    var graph = try witness.replayHashCalls(a, ledger);
    defer graph.deinit();
    try std.testing.expectError(error.UnbalancedRamHashClaims, proof.proveFromPublicLedger(a, &witness, ledger));
    var wrong = witness.before;
    wrong[8] ^= 1;
    try std.testing.expectError(error.RamBoundaryMismatch, proof.verify(a, &witness, wrong, final.root(), &.{1}, &updates, encoded));
    std.mem.writeInt(u32, changed[4..8], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.InvalidRamHashProofShape, proof.verify(a, &witness, witness.before, final.root(), &.{1}, &updates, changed));
}
