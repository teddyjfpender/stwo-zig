//! Canonical CPU-oracle inputs for CUDA parity and release gates.

const std = @import("std");
const state_machine = @import("../../../examples/state_machine.zig");
const pcs = @import("stwo_core").pcs;
const M31 = @import("stwo_core").fields.m31.M31;
const proof_wire = @import("../../../interop/proof_wire.zig");

pub const Target = struct {
    request: state_machine.Request,
};

pub const cuda_exact_protocol_available = false;

pub const functional = [_]Target{
    .{ .request = .{
        .log_n_rows = 14,
        .initial_state = .{ M31.fromU64(9), M31.fromU64(3) },
    } },
    .{ .request = .{
        .log_n_rows = 16,
        .initial_state = .{ M31.fromU64(9), M31.fromU64(3) },
    } },
};

pub fn checkCpuOracle(
    allocator: std.mem.Allocator,
    target: Target,
) !void {
    const protocol = pcs.PcsConfig.default();
    var output = try state_machine.prove(
        allocator,
        protocol,
        target.request.log_n_rows,
        target.request.initial_state,
    );
    var proof_live = true;
    defer if (proof_live) output.proof.deinit(allocator);

    const encoded = try proof_wire.encodeProofBytes(
        allocator,
        output.proof,
    );
    defer allocator.free(encoded);
    if (encoded.len == 0) return error.ParityTargetMismatch;

    proof_live = false;
    try state_machine.verify(
        allocator,
        protocol,
        output.statement,
        output.proof,
    );
}

test "state-machine parity targets cover increasing trace sizes" {
    try std.testing.expect(!cuda_exact_protocol_available);
    try std.testing.expectEqual(@as(usize, 2), functional.len);
    try std.testing.expect(
        functional[0].request.log_n_rows <
            functional[1].request.log_n_rows,
    );
}

test "state-machine CPU parity targets remain verified" {
    for (functional) |target|
        try checkCpuOracle(std.testing.allocator, target);
}
