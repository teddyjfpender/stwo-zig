//! Focused Stwo facade for Native example AIRs on Metal.

const std = @import("std");

pub const core = @import("stwo_core");
pub const backend = @import("stwo_backend_contracts");
pub const prover = @import("stwo_prover_engine");

pub const backends = struct {
    pub const cpu = @import("stwo_cpu_backend");
    pub const metal = @import("stwo_metal_backend");
};

pub const examples = @import("stwo_native_examples");

pub const interop = struct {
    pub const atomic_file = @import("atomic_file");
    pub const examples_artifact = @import("stwo_native_artifact").examples_artifact;
    pub const examples_artifact_verifier = @import("stwo_native_artifact").examples_artifact_verifier;
    pub const postcard = @import("interop_postcard");
    pub const proof_wire = @import("stwo_proof_wire");
};

test {
    std.testing.refAllDecls(@This());
}
