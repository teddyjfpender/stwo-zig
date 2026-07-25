const std = @import("std");
const stwo = @import("stwo.zig");
const native_cuda_poseidon_geometry =
    @import("integrations/native_cuda/poseidon/geometry.zig");
const native_cuda_poseidon_layout =
    @import("integrations/native_cuda/poseidon/layout.zig");
const native_cuda_poseidon_topology =
    @import("integrations/native_cuda/poseidon/topology.zig");
const native_cuda_poseidon_oods =
    @import("integrations/native_cuda/poseidon/oods.zig");
const native_cuda_poseidon_ingress =
    @import("integrations/native_cuda/poseidon/canonical_ingress.zig");
const native_cuda_poseidon_program =
    @import("integrations/native_cuda/poseidon/program.zig");
const native_cuda_poseidon_proof_bundle =
    @import("integrations/native_cuda/poseidon/proof_bundle.zig");
const native_cuda_poseidon_terminal_bundle =
    @import("integrations/native_cuda/poseidon/terminal_bundle.zig");
const native_cuda_poseidon_transcript =
    @import("integrations/native_cuda/poseidon/transcript_schedule.zig");

test {
    _ = @import("backends/metal/telemetry.zig");
    _ = @import("core/fri/tests.zig");
    _ = @import("core/fields/tests/m31.zig");
    _ = @import("core/pcs/quotients/tests.zig");
    _ = @import("frontends/cairo/witness/resident_geometry.zig");
    _ = @import("frontends/cairo/witness/resident_proof.zig");
    _ = @import("frontends/cairo/witness/resident_types.zig");
    _ = @import("frontends/cairo/witness/resident_verifier.zig");
    _ = @import("integrations/cairo_cuda/mod.zig");
    _ = @import("integrations/cairo_metal/oods.zig");
    _ = @import("integrations/cairo_metal/quotient_inputs.zig");
    _ = @import("integrations/cairo_metal/quotient_reference.zig");
    _ = @import("integrations/cairo_metal/schedule_bindings.zig");
    _ = @import("prover/tests/mod.zig");
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
