const std = @import("std");
const examples_xor = @import("../examples/xor.zig");
const examples_state_machine = @import("../examples/state_machine.zig");
const examples_wide_fibonacci = @import("../examples/wide_fibonacci.zig");

/// Freestanding-friendly verifier shim surface.
///
/// This module intentionally exposes verification-only wrappers that can be
/// compiled for freestanding targets, while preserving behavior of the
/// standard verifier paths for identical inputs.
pub fn verifyXor(
    allocator: std.mem.Allocator,
    pcs_config: @import("../core/pcs/mod.zig").PcsConfig,
    statement: examples_xor.Statement,
    proof: examples_xor.Proof,
) anyerror!void {
    try examples_xor.verify(allocator, pcs_config, statement, proof);
}

pub fn verifyStateMachine(
    allocator: std.mem.Allocator,
    pcs_config: @import("../core/pcs/mod.zig").PcsConfig,
    statement: examples_state_machine.PreparedStatement,
    proof: examples_state_machine.Proof,
) anyerror!void {
    try examples_state_machine.verify(allocator, pcs_config, statement, proof);
}

pub fn verifyWideFibonacci(
    allocator: std.mem.Allocator,
    pcs_config: @import("../core/pcs/mod.zig").PcsConfig,
    statement: examples_wide_fibonacci.Statement,
    proof: examples_wide_fibonacci.Proof,
) anyerror!void {
    try examples_wide_fibonacci.verify(allocator, pcs_config, statement, proof);
}

test "std_shims verifier profile: xor verification parity with standard path" {
    const alloc = std.testing.allocator;
    const config = @import("../core/pcs/mod.zig").PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: examples_xor.Statement = .{
        .log_size = 5,
        .log_step = 2,
        .offset = 7,
    };

    var output = try examples_xor.prove(alloc, config, statement);
    defer output.proof.deinit(alloc);

    const proof_wire = @import("../interop/proof_wire.zig");
    const bytes = try proof_wire.encodeProofBytes(alloc, output.proof);
    defer alloc.free(bytes);

    const standard_proof = try proof_wire.decodeProofBytes(alloc, bytes);
    try examples_xor.verify(alloc, config, output.statement, standard_proof);

    const shim_proof = try proof_wire.decodeProofBytes(alloc, bytes);
    try verifyXor(alloc, config, output.statement, shim_proof);
}
