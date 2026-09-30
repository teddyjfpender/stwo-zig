//! Circuit-only proof sections not covered by the shared root/FRI capturer.
//! Both PoW nonces and all eleven claims stay on the device until the single
//! terminal read. Their order is fixed by the circuit verifier transcript.
const circuit = @import("stwo_circuit_frontend");
const cuda = @import("stwo_cuda_backend");
const shared = @import("stwo_native_cuda_integration").common;
const common = cuda.runtime.stages.common;

pub fn captureClaims(
    session: anytype,
    proof: shared.resident_views.Proof,
    claims: common.SecureFields,
) !void {
    const claim_count = circuit.common.component_list.N_COMPONENTS;
    if (claims.len != claim_count or proof.trace_commitments.len != 4 * 8 + claim_count * 4)
        return error.InvalidCircuitTerminalBinding;
    try session.context.copyDeviceSlice(
        u32,
        try proof.trace_commitments.sub(4 * 8, claim_count * 4),
        try claims.cast(u32),
    );
}

pub fn captureInteractionNonce(
    session: anytype,
    proof: shared.resident_views.Proof,
    nonce: common.Words,
) !void {
    if (proof.pow_nonce.len != 4 or nonce.len != 2)
        return error.InvalidCircuitTerminalBinding;
    try session.context.copyDeviceSlice(u32, try proof.pow_nonce.sub(0, 2), nonce);
}

pub fn captureQueryNonce(
    session: anytype,
    proof: shared.resident_views.Proof,
    nonce: common.Words,
) !void {
    if (proof.pow_nonce.len != 4 or nonce.len != 2)
        return error.InvalidCircuitTerminalBinding;
    try session.context.copyDeviceSlice(u32, try proof.pow_nonce.sub(2, 2), nonce);
}

test "resident circuit claims and both nonces occupy disjoint terminal ranges" {
    const std = @import("std");
    const FakeContext = struct {
        offsets: [3]usize = undefined,
        count: usize = 0,
        pub fn copyDeviceSlice(self: *@This(), comptime F: type, destination: anytype, _: anytype) !void {
            try std.testing.expectEqual(u32, F);
            self.offsets[self.count] = destination.address;
            self.count += 1;
        }
    };
    const FakeSession = struct { context: FakeContext = .{} };
    var session = FakeSession{};
    var proof: shared.resident_views.Proof = undefined;
    proof.trace_commitments = .{ .address = 0x1000, .len = 4 * 8 + circuit.common.component_list.N_COMPONENTS * 4, .owner = 1 };
    proof.pow_nonce = .{ .address = 0x2000, .len = 4, .owner = 1 };
    try captureClaims(&session, proof, .{ .address = 0x3000, .len = circuit.common.component_list.N_COMPONENTS, .owner = 1 });
    try captureInteractionNonce(&session, proof, .{ .address = 0x4000, .len = 2, .owner = 1 });
    try captureQueryNonce(&session, proof, .{ .address = 0x5000, .len = 2, .owner = 1 });
    try std.testing.expectEqual(@as(usize, 3), session.context.count);
    try std.testing.expectEqual(@as(usize, 0x1000 + 32 * 4), session.context.offsets[0]);
    try std.testing.expectEqual(@as(usize, 0x2000), session.context.offsets[1]);
    try std.testing.expectEqual(@as(usize, 0x2000 + 2 * 4), session.context.offsets[2]);
}
