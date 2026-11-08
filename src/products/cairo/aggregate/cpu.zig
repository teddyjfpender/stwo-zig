//! Capability facade for the aggregate CPU CLI.
//!
//! The public `stwo` package remains the compatibility SDK. This narrower
//! facade prevents deferred frontends and backends from entering the released
//! aggregate command through convenience re-exports.

pub const core = @import("stwo_core");
pub const backend = @import("stwo_backend_contracts");
pub const prover = @import("stwo_prover_engine");

pub const backends = struct {
    pub const cpu = @import("stwo_cpu_backend");
};

pub const examples = @import("stwo_native_examples");

pub const frontends = struct {
    pub const riscv = @import("stwo_riscv_frontend");
};

pub const integrations = struct {
    pub const riscv_cpu = @import("stwo_riscv_cpu_integration");
};

pub const interop = struct {
    pub const atomic_file = @import("interop/atomic_file.zig");
    pub const examples_artifact = @import("interop/examples_artifact.zig");
    pub const examples_artifact_verifier = @import("interop/examples_artifact_verifier.zig");
    pub const postcard = @import("interop_postcard");
    pub const proof_wire = @import("stwo_proof_wire");
    pub const riscv_artifact = @import("interop/riscv_artifact.zig");
};
