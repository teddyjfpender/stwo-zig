//! `stwo` root module: the thin waist plus the prover engine.
//!
//! Public surface (ENGINEERING_STANDARDS thin waist): `core`, `backend`,
//! `prover_api`, `proof_wire`, `recursion_wire` and `prover`. Frontends,
//! integrations and examples come from their product facades
//! (`src/products/<line>/<target>/root.zig`), not from this module.
//!
//! Every declaration is a named-module import, so this root can live inside
//! `src/products/stwo/` under Zig 0.15's module-root rule.

pub const core = @import("stwo_core");
pub const backend = @import("stwo_backend_contracts");
pub const prover_api = @import("stwo_prover_api");
pub const proof_wire = @import("stwo_proof_wire");
/// Shared circuit-recursion codecs with the Cairo frontend's injected authorities.
pub const recursion_wire = @import("stwo_circuit_recursion_wire");
pub const prover = @import("stwo_prover_engine");

// ---------------------------------------------------------------------------
// Deprecated forwarding namespaces. They keep existing `stwo.<namespace>`
// consumers compiling for one minor version; new code imports the named
// package module (or its product facade) directly. Members resolve lazily, so
// a build that does not wire a package fails only if a consumer uses it.
// ---------------------------------------------------------------------------

/// Deprecated: import `stwo_cpu_backend`, `stwo_cuda_backend` or `stwo_metal_backend`.
pub const backends = struct {
    pub const cpu_scalar = @import("stwo_cpu_backend");
    pub const cuda = @import("stwo_cuda_backend");
    pub const metal = @import("stwo_metal_backend");

    pub const CpuBackend = cpu_scalar.CpuBackend;
    pub const CudaBackend = cuda.CudaBackend;
    pub const MetalRuntime = metal.Runtime;
};

/// Deprecated: import the frontend package module.
pub const frontends = struct {
    pub const examples = @import("stwo_native_examples");
    pub const cairo = @import("stwo_cairo_frontend");
    pub const riscv = @import("legacy_riscv_frontend");
};

/// Deprecated: import the integration package module.
pub const integrations = struct {
    pub const cairo_metal = @import("stwo_cairo_metal_integration");
    pub const cairo_cpu = @import("stwo_cairo_cpu_integration");
    pub const cairo_cuda = @import("stwo_cairo_cuda_integration");
    pub const native_cuda = @import("stwo_native_cuda_integration");
    pub const riscv_cpu = @import("legacy_riscv_cpu_integration");
};

/// Deprecated: import `stwo_native_examples`.
pub const examples = @import("stwo_native_examples");

/// Deprecated: the former `src/interop` aggregate, now split across
/// `waist/proof_wire`, `waist/recursion_wire`, `support/io` and the product
/// artifact codecs.
pub const interop = struct {
    pub const proof_wire = @import("stwo_proof_wire");
    pub const stwo_json = @import("stwo_core").proof_json;
    pub const postcard = @import("interop_postcard");
    pub const examples_artifact = @import("stwo_native_artifact").examples_artifact;
    pub const examples_artifact_verifier = @import("stwo_native_artifact").examples_artifact_verifier;
    pub const riscv_artifact = @import("interop_riscv_artifact");
    pub const atomic_file = @import("atomic_file");
    pub const output_transaction = @import("output_transaction");
};

/// Deprecated: import `stwo_artifact_store`.
pub const artifact_store = @import("stwo_artifact_store");
/// Deprecated: import `stwo_metal_session`.
pub const metal_session = @import("stwo_metal_session");
/// Deprecated: import `stwo_std_shims`.
pub const std_shims = @import("stwo_std_shims");
/// Deprecated: import `stwo_tracing`.
pub const tracing = @import("stwo_tracing");

test {
    // Every documented thin-waist export must resolve in the assembled SDK.
    _ = core;
    _ = backend;
    _ = prover_api;
    _ = proof_wire;
    _ = recursion_wire;
    _ = prover;
    _ = backends;
    _ = frontends;
    _ = integrations;
    _ = examples;
    _ = interop;
    _ = artifact_store;
    _ = metal_session;
    _ = std_shims;
    _ = tracing;
}
