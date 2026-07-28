//! Package-root closures admitted by product and tool build scopes.

pub const core_package_roots = &.{
    "dependency:../src/core:mod.zig",
};

pub const protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const native_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/prover:mod.zig",
    "dependency:../src/prover:native/resource_admission.zig",
    "dependency:../src/prover:native/runner.zig",
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

pub const cairo_cpu_integration_package_roots = &.{
    "dependency:../src/integrations/cairo_cpu:mod.zig",
};

pub const riscv_metal_integration_package_roots = &.{
    "dependency:../src/integrations/riscv_metal:mod.zig",
};

pub const metal_backend_package_roots = &.{
    "dependency:../src/backends/metal:mod.zig",
};

pub const cpu_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const cairo_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const cairo_cuda_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cuda:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const cairo_cpu_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const cairo_metal_cpu_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const riscv_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const frontend_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const frontend_cpu_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const frontend_metal_cpu_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const frontend_cuda_metal_cpu_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/cuda:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const metal_tools_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/cuda:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/backends/metal:shader_manifest.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const riscv_cpu_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/integrations/riscv_cpu:proof_adapter.zig",
    "dependency:../src/prover:mod.zig",
};

pub const riscv_metal_cpu_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/riscv_metal:mod.zig",
    "dependency:../src/prover:mod.zig",
};

pub const native_riscv_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/prover:mod.zig",
    "dependency:../src/prover:native/resource_admission.zig",
    "dependency:../src/prover:native/runner.zig",
};

pub const native_cpu_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/prover:mod.zig",
    "dependency:../src/prover:native/resource_admission.zig",
    "dependency:../src/prover:native/runner.zig",
};

pub const native_metal_cpu_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/prover:mod.zig",
    "dependency:../src/prover:native/resource_admission.zig",
    "dependency:../src/prover:native/runner.zig",
};

pub const native_riscv_cpu_protocol_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/integrations/riscv_cpu:proof_adapter.zig",
    "dependency:../src/prover:mod.zig",
    "dependency:../src/prover:native/resource_admission.zig",
    "dependency:../src/prover:native/runner.zig",
};

pub const compatibility_package_roots = &.{
    "dependency:../src/backend:mod.zig",
    "dependency:../src/backends/cpu_scalar:mod.zig",
    "dependency:../src/backends/cuda:mod.zig",
    "dependency:../src/backends/metal:mod.zig",
    "dependency:../src/core:mod.zig",
    "dependency:../src/frontends/cairo:mod.zig",
    "dependency:../src/frontends/cairo:tests/mod.zig",
    "dependency:../src/frontends/cairo:witness/composition_bundle.zig",
    "dependency:../src/frontends/riscv:mod.zig",
    "dependency:../src/integrations/cairo_cpu:mod.zig",
    "dependency:../src/integrations/riscv_cpu:mod.zig",
    "dependency:../src/prover:mod.zig",
    "dependency:../src/prover:native/resource_admission.zig",
    "dependency:../src/prover:native/runner.zig",
};
