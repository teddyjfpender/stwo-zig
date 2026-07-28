//! Focused Stwo facade for Native example AIRs on Metal.

const std = @import("std");

pub const core = @import("stwo_core");
pub const backend = @import("stwo_backend_contracts");
pub const prover = @import("stwo_prover_impl");

pub const backends = struct {
    pub const cpu = @import("stwo_cpu_backend");
    pub const metal = @import("stwo_metal_backend");
};

pub const examples = struct {
    pub const blake = @import("examples/blake.zig");
    pub const plonk = @import("examples/plonk.zig");
    pub const plonk_logup = @import("examples/plonk_logup.zig");
    pub const poseidon = @import("examples/poseidon.zig");
    pub const state_machine = @import("examples/state_machine.zig");
    pub const wide_fibonacci = @import("examples/wide_fibonacci.zig");
    pub const xor = @import("examples/xor.zig");
};

pub const interop = struct {
    pub const atomic_file = @import("interop/atomic_file.zig");
    pub const examples_artifact = @import("interop/examples_artifact.zig");
    pub const examples_artifact_verifier = @import("interop/examples_artifact_verifier.zig");
    pub const postcard = @import("interop/postcard.zig");
    pub const proof_wire = @import("interop/proof_wire.zig");
};

test {
    std.testing.refAllDecls(@This());
}
