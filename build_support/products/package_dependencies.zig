//! Package-root closures admitted by product and tool build scopes.

pub const core_package_roots = &.{
    "dependency:../src/waist/core:fields/om31_test.zig",
    "dependency:../src/waist/core:focused_test_root.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/waist/core:om31_deep_test.zig",
    "dependency:../src/waist/core:om31_fri_test.zig",
    "dependency:../src/waist/core:om31_pcs_test.zig",
};

pub const protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

/// `protocol_package_roots` plus the focused test roots of the core and
/// prover products, for the scopes that construct those products whole
/// (`prover`, `package`).
pub const core_prover_products_package_roots = &.{
    "dependency:../src/engine/prover:coefficient_storage_test_root.zig",
    "dependency:../src/engine/prover:focused_test_root.zig",
    "dependency:../src/engine/prover:gkr_resource_test_root.zig",
    "dependency:../src/engine/prover:merkle_test_root.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/engine/prover:tests/work_pool_test.zig",
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:fields/om31_test.zig",
    "dependency:../src/waist/core:focused_test_root.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/waist/core:om31_deep_test.zig",
    "dependency:../src/waist/core:om31_fri_test.zig",
    "dependency:../src/waist/core:om31_pcs_test.zig",
    "dependency:../src/waist/core:vcs_lifted/testdata/lifted_height_vectors.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const native_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
    "dependency:../src/engine/prover:native/resource_admission.zig",
    "dependency:../src/engine/prover:native/runner.zig",
};

pub const riscv_frontend_package_roots = &.{
    "dependency:../src/frontends/riscv:mod.zig",
};

pub const cairo_frontend_package_roots = &.{
    "dependency:../src/frontends/cairo:mod.zig",
};

pub const cpu_backend_package_roots = &.{
    "dependency:../src/backends/cpu_scalar:mod.zig",
};

pub const cuda_backend_package_roots = &.{
    "dependency:../src/backends/cuda:mod.zig",
};

pub const riscv_cpu_integration_package_roots = &.{
    "dependency:../src/integrations/riscv_cpu:mod.zig",
};

pub const riscv_cuda_integration_package_roots = &.{
    "dependency:../src/integrations/riscv_cuda:mod.zig",
};

pub const cairo_cpu_integration_package_roots = &.{
    "dependency:../src/integrations/cairo_cpu:mod.zig",
};

pub const riscv_metal_integration_package_roots = &.{
    "dependency:../src/integrations/riscv_metal:mod.zig",
};

pub const cairo_metal_integration_package_roots = &.{
    "dependency:../src/integrations/cairo_metal:mod.zig",
};

pub const artifact_store_package_roots = &.{
    "dependency:../src/engine/artifact_store:mod.zig",
};

pub const metal_session_package_roots = &.{
    "dependency:../src/engine/artifact_store:mod.zig",
    "dependency:../src/backends/metal/session:mod.zig",
};

pub const proof_wire_package_roots = &.{
    "dependency:../src/waist/proof_wire:mod.zig",
};

pub const native_examples_package_roots = &.{
    "dependency:../src/products/native/examples:mod.zig",
};

pub const native_cuda_integration_package_roots = &.{
    "dependency:../src/integrations/native_cuda:mod.zig",
};

pub const cairo_cuda_integration_package_roots = &.{
    "dependency:../src/integrations/cairo_cuda:mod.zig",
};

pub const metal_backend_package_roots = &.{
    "dependency:../src/backends/metal:mod.zig",
};

pub const cpu_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const cairo_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const cairo_cuda_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/cuda:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/products/native/examples:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/integrations/cairo_cuda:mod.zig",
    "dependency:../src/integrations/native_cuda:mod.zig",
    "dependency:../src/waist/proof_wire:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const cairo_cpu_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/cairo:interop/felt_json.zig",
    "dependency:../src/frontends/cairo:interop/cairo_prover_parameters.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const circuit_recursion_cpu_protocol_package_roots = &.{
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/frontends/cairo:interop/cairo_prover_parameters.zig",
    "dependency:../src/frontends/cairo:interop/felt_json.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/circuit:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/circuit_cpu:mod.zig",
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/waist/proof_wire:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
    "dependency:../src/waist/recursion_wire:mod.zig",
};

pub const cairo_metal_cpu_protocol_package_roots = &.{
    "dependency:../src/engine/artifact_store:mod.zig",
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/cairo_metal:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
    "dependency:../src/backends/metal/session:mod.zig",
};

pub const riscv_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const frontend_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const frontend_cpu_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const frontend_metal_cpu_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const frontend_cuda_metal_cpu_protocol_package_roots = &.{
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/cuda:mod.zig",
    "dependency:../src/backends/metal/session:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/engine/artifact_store:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/frontends/cairo:interop/cairo_prover_parameters.zig",
    "dependency:../src/frontends/cairo:interop/felt_json.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/cairo_cuda:mod.zig",
    "dependency:../src/integrations/cairo_metal:mod.zig",
    "dependency:../src/integrations/native_cuda:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/products/native/examples:mod.zig",
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/waist/proof_wire:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
    "dependency:../src/waist/recursion_wire:postcard/mod.zig",
};

pub const metal_tools_package_roots = &.{
    "dependency:../src/engine/artifact_store:mod.zig",
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/cuda:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/backends/metal:shader_manifest.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/products/native/examples:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/cairo_cuda:mod.zig",
    "dependency:../src/integrations/cairo_metal:mod.zig",
    "dependency:../src/integrations/native_cuda:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/waist/proof_wire:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
    "dependency:../src/backends/metal/session:mod.zig",
};

pub const riscv_cpu_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/frontends/riscv:refinement_ir_export_test.zig",
    "dependency:../src/frontends/riscv:refinement_program_export_test.zig",
    "dependency:../src/frontends/riscv:sail_oracle_test_root.zig",
    "dependency:../src/integrations/riscv_cpu:degree5_poseidon_proof_test.zig",
    "dependency:../src/integrations/riscv_cpu:degree5_provider_proof_v1_test.zig",
    "dependency:../src/integrations/riscv_cpu:degree_bounded_poseidon_proof_test.zig",
    "dependency:../src/integrations/riscv_cpu:memory_provider_shard_benchmark.zig",
    "dependency:../src/integrations/riscv_cpu:memory_provider_shard_proof_test.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/integrations/riscv_cpu:proof_adapter.zig",
    "dependency:../src/waist/proof_wire:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const riscv_metal_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/riscv_metal:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const riscv_cuda_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/cuda:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/riscv_cuda:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
};

pub const native_riscv_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
    "dependency:../src/engine/prover:native/resource_admission.zig",
    "dependency:../src/engine/prover:native/runner.zig",
};

pub const native_cpu_protocol_package_roots = &.{
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/engine/prover:gkr_parallel_test_root.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/engine/prover:native/resource_admission.zig",
    "dependency:../src/engine/prover:native/runner.zig",
    "dependency:../src/engine/prover:wide_sampling_test_root.zig",
    "dependency:../src/products/native/examples:mod.zig",
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/waist/proof_wire:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
    "dependency:../src/waist/recursion_wire:postcard/mod.zig",
};

pub const native_metal_cpu_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/products/native/examples:mod.zig",
    "dependency:../src/waist/proof_wire:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
    "dependency:../src/engine/prover:native/resource_admission.zig",
    "dependency:../src/engine/prover:native/runner.zig",
};

pub const native_riscv_cpu_protocol_package_roots = &.{
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/products/native/examples:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/riscv_cpu:proof_adapter.zig",
    "dependency:../src/waist/recursion_wire:postcard/mod.zig",
    "dependency:../src/waist/proof_wire:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
    "dependency:../src/engine/prover:native/resource_admission.zig",
    "dependency:../src/engine/prover:native/runner.zig",
};

pub const compatibility_package_roots = &.{
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/cuda:mod.zig",
    "dependency:../src/backends/metal/session:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/engine/artifact_store:mod.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/engine/prover:native/resource_admission.zig",
    "dependency:../src/engine/prover:native/runner.zig",
    "dependency:../src/frontends/cairo:interop/cairo_prover_parameters.zig",
    "dependency:../src/frontends/cairo:interop/felt_json.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/cairo:tests/mod.zig",
    "dependency:../src/frontends/cairo:witness/composition_bundle.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/cairo_cuda:mod.zig",
    "dependency:../src/integrations/cairo_metal:mod.zig",
    "dependency:../src/integrations/native_cuda:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/products/native/examples:mod.zig",
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/waist/proof_wire:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
    "dependency:../src/waist/recursion_wire:mod.zig",
    "dependency:../src/waist/recursion_wire:postcard/mod.zig",
};

// The retained public `stwo` compatibility facade binds these existing
// modules in addition to the focused core/prover products.
pub const public_package_roots = &.{
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/cuda:mod.zig",
    "dependency:../src/backends/metal/session:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/engine/artifact_store:mod.zig",
    "dependency:../src/engine/prover:coefficient_storage_test_root.zig",
    "dependency:../src/engine/prover:focused_test_root.zig",
    "dependency:../src/engine/prover:gkr_resource_test_root.zig",
    "dependency:../src/engine/prover:merkle_test_root.zig",
    "dependency:../src/engine/prover:mod.zig",
    "dependency:../src/engine/prover:tests/work_pool_test.zig",
    "dependency:../src/frontends/cairo:interop/cairo_prover_parameters.zig",
    "dependency:../src/frontends/cairo:interop/felt_json.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/cairo_cuda:mod.zig",
    "dependency:../src/integrations/cairo_metal:mod.zig",
    "dependency:../src/integrations/native_cuda:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/products/native/examples:mod.zig",
    "dependency:../src/waist/backend:mod.zig",
    "dependency:../src/waist/core:fields/om31_test.zig",
    "dependency:../src/waist/core:focused_test_root.zig",
    "dependency:../src/waist/core:mod.zig",
    "dependency:../src/waist/core:om31_deep_test.zig",
    "dependency:../src/waist/core:om31_fri_test.zig",
    "dependency:../src/waist/core:om31_pcs_test.zig",
    "dependency:../src/waist/core:vcs_lifted/testdata/lifted_height_vectors.zig",
    "dependency:../src/waist/proof_wire:mod.zig",
    "dependency:../src/waist/prover_api:mod.zig",
    "dependency:../src/waist/recursion_wire:mod.zig",
    "dependency:../src/waist/recursion_wire:postcard/mod.zig",
};
