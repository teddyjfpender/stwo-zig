const std = @import("std");
const Receiver = @import("prover/block_v6_complete_root_receiver_v1.zig");
test "complete root receiver and canonical public projection compile" {
    _ = &Receiver.verify;
    _ = &Receiver.publicChildren;
    try std.testing.expect((Receiver.Limits{}).max_proof_bytes > 0);
}
