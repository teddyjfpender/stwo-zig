const std = @import("std");
// Named modules only: this root lives under `src/products/native/tests/`.
const interop = struct {
    pub const proof_wire = @import("stwo_proof_wire");
    pub const postcard = @import("interop_postcard");
    pub const native_artifact = @import("stwo_native_artifact");
    pub const riscv_artifact = @import("interop_riscv_artifact");
    pub const atomic_file = @import("atomic_file");
    pub const output_transaction = @import("output_transaction");
};
const native_cuda_poseidon = @import("stwo_native_cuda_integration").poseidon;
const native_cuda_poseidon_geometry = native_cuda_poseidon.geometry;
const native_cuda_poseidon_layout = native_cuda_poseidon.layout;
const native_cuda_poseidon_topology = native_cuda_poseidon.topology;
const native_cuda_poseidon_oods = native_cuda_poseidon.oods;
const native_cuda_poseidon_ingress = native_cuda_poseidon.canonical_ingress;
const native_cuda_poseidon_program = native_cuda_poseidon.program;
const native_cuda_poseidon_proof_bundle = native_cuda_poseidon.proof_bundle;
const native_cuda_poseidon_terminal_bundle = native_cuda_poseidon.terminal_bundle;
const native_cuda_poseidon_transcript = native_cuda_poseidon.transcript_schedule;

test {
    _ = @import("stwo_metal_backend").telemetry;
    _ = @import("stwo_cairo_cuda_integration");
    _ = @import("stwo_cairo_metal_integration").oods;
    _ = @import("stwo_cairo_metal_integration").quotient_inputs;
    _ = @import("stwo_cairo_metal_integration").quotient_reference;
    _ = @import("stwo_cairo_metal_integration").schedule_bindings;
    _ = @import("prover/mod.zig");
    _ = @import("parity/mod.zig");
    std.testing.refAllDeclsRecursive(@import("stwo_core"));
    std.testing.refAllDeclsRecursive(@import("stwo_prover_engine"));
    std.testing.refAllDeclsRecursive(@import("stwo_native_examples"));
    std.testing.refAllDeclsRecursive(interop);
    std.testing.refAllDeclsRecursive(@import("stwo_tracing"));
    std.testing.refAllDeclsRecursive(native_cuda_poseidon_geometry);
    std.testing.refAllDeclsRecursive(native_cuda_poseidon_layout);
    std.testing.refAllDeclsRecursive(native_cuda_poseidon_topology);
    std.testing.refAllDeclsRecursive(native_cuda_poseidon_oods);
    std.testing.refAllDeclsRecursive(native_cuda_poseidon_ingress);
    std.testing.refAllDeclsRecursive(native_cuda_poseidon_program);
    std.testing.refAllDeclsRecursive(native_cuda_poseidon_proof_bundle);
    std.testing.refAllDeclsRecursive(native_cuda_poseidon_terminal_bundle);
    std.testing.refAllDeclsRecursive(native_cuda_poseidon_transcript);
}
