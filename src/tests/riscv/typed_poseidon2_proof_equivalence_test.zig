//! H-007 product evidence for the typed Poseidon2 compiler pilot.
//!
//! These exercises instantiate the backend-generic harness through the real
//! CPU commitment and proving backend.  The honest case commits typed-generated
//! main, interaction, and claim artifacts inside a complete RISC-V proof and
//! verifies it through the production verifier.  The negative case mutates
//! each artifact class after authentication and requires proving to reject it.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const riscv_cpu = @import("stwo_riscv_cpu_integration");

const proof_equivalence = frontend.testing.typed_poseidon2_proof_test;
const Backend = riscv_cpu.CpuProverEngine.Backend;

test "typed Poseidon2: CPU commits generated artifacts and verifies" {
    const receipt = try proof_equivalence.exerciseBackend(
        Backend,
        std.testing.allocator,
    );
    try receipt.validate();
    try std.testing.expectEqualStrings(@typeName(Backend), receipt.backend_name);
    try std.testing.expectEqual(@as(usize, 46), receipt.active_rows);
    try std.testing.expectEqual(receipt.active_rows, receipt.narrow_rows);
    try std.testing.expectEqual(@as(usize, 0), receipt.wide_rows);
    try std.testing.expectEqual(@as(usize, 0), receipt.io_rows);
}

test "typed Poseidon2: CPU rejects generated artifact mutations" {
    try proof_equivalence.exerciseMutationNegatives(
        Backend,
        std.testing.allocator,
    );
}
