const std = @import("std");
const examples_blake = @import("../examples/blake.zig");
const examples_poseidon = @import("../examples/poseidon.zig");
const examples_plonk = @import("../examples/plonk.zig");
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

pub fn verifyPoseidon(
    allocator: std.mem.Allocator,
    pcs_config: @import("../core/pcs/mod.zig").PcsConfig,
    statement: examples_poseidon.Statement,
    proof: examples_poseidon.Proof,
) anyerror!void {
    try examples_poseidon.verify(allocator, pcs_config, statement, proof);
}

pub fn verifyBlake(
    allocator: std.mem.Allocator,
    pcs_config: @import("../core/pcs/mod.zig").PcsConfig,
    statement: examples_blake.Statement,
    proof: examples_blake.Proof,
) anyerror!void {
    try examples_blake.verify(allocator, pcs_config, statement, proof);
}

pub fn verifyPlonk(
    allocator: std.mem.Allocator,
    pcs_config: @import("../core/pcs/mod.zig").PcsConfig,
    statement: examples_plonk.Statement,
    proof: examples_plonk.Proof,
) anyerror!void {
    try examples_plonk.verify(allocator, pcs_config, statement, proof);
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

test "std_shims verifier profile: plonk verification parity with standard path" {
    const alloc = std.testing.allocator;
    const config = @import("../core/pcs/mod.zig").PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: examples_plonk.Statement = .{
        .log_n_rows = 5,
    };

    var output = try examples_plonk.prove(alloc, config, statement);
    defer output.proof.deinit(alloc);

    const proof_wire = @import("../interop/proof_wire.zig");
    const bytes = try proof_wire.encodeProofBytes(alloc, output.proof);
    defer alloc.free(bytes);

    const standard_proof = try proof_wire.decodeProofBytes(alloc, bytes);
    try examples_plonk.verify(alloc, config, output.statement, standard_proof);

    const shim_proof = try proof_wire.decodeProofBytes(alloc, bytes);
    try verifyPlonk(alloc, config, output.statement, shim_proof);
}

test "std_shims verifier profile: poseidon verification parity with standard path" {
    const alloc = std.testing.allocator;
    const config = @import("../core/pcs/mod.zig").PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: examples_poseidon.Statement = .{
        .log_n_instances = 8,
    };

    var output = try examples_poseidon.prove(alloc, config, statement);
    defer output.proof.deinit(alloc);

    const proof_wire = @import("../interop/proof_wire.zig");
    const bytes = try proof_wire.encodeProofBytes(alloc, output.proof);
    defer alloc.free(bytes);

    const standard_proof = try proof_wire.decodeProofBytes(alloc, bytes);
    try examples_poseidon.verify(alloc, config, output.statement, standard_proof);

    const shim_proof = try proof_wire.decodeProofBytes(alloc, bytes);
    try verifyPoseidon(alloc, config, output.statement, shim_proof);
}

test "std_shims verifier profile: blake verification parity with standard path" {
    const alloc = std.testing.allocator;
    const config = @import("../core/pcs/mod.zig").PcsConfig{
        .pow_bits = 0,
        .fri_config = try @import("../core/fri.zig").FriConfig.init(0, 1, 3),
    };
    const statement: examples_blake.Statement = .{
        .log_n_rows = 5,
        .n_rounds = 10,
    };

    var output = try examples_blake.prove(alloc, config, statement);
    defer output.proof.deinit(alloc);

    const proof_wire = @import("../interop/proof_wire.zig");
    const bytes = try proof_wire.encodeProofBytes(alloc, output.proof);
    defer alloc.free(bytes);

    const standard_proof = try proof_wire.decodeProofBytes(alloc, bytes);
    try examples_blake.verify(alloc, config, output.statement, standard_proof);

    const shim_proof = try proof_wire.decodeProofBytes(alloc, bytes);
    try verifyBlake(alloc, config, output.statement, shim_proof);
}
