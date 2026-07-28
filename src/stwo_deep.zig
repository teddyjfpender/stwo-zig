const std = @import("std");
const stwo = @import("stwo.zig");
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
    _ = @import("integrations/cairo_cuda/mod.zig");
    _ = @import("stwo_cairo_metal_integration").oods;
    _ = @import("stwo_cairo_metal_integration").quotient_inputs;
    _ = @import("stwo_cairo_metal_integration").quotient_reference;
    _ = @import("stwo_cairo_metal_integration").schedule_bindings;
    _ = @import("tests/native/prover/mod.zig");
    _ = @import("interop/parity/mod.zig");
    std.testing.refAllDecls(stwo);
    std.testing.refAllDeclsRecursive(stwo.core);
    std.testing.refAllDeclsRecursive(stwo.prover);
    std.testing.refAllDeclsRecursive(stwo.examples);
    std.testing.refAllDeclsRecursive(stwo.interop);
    std.testing.refAllDeclsRecursive(stwo.tracing);
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
