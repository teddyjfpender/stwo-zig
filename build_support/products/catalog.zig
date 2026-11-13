//! Typed non-product scopes and compatibility steps for the build catalog.

const std = @import("std");
pub const package_dependencies = @import("package_dependencies.zig");

const types = @import("catalog_types.zig");
pub const Scope = types.Scope;
pub const Step = types.Step;
pub const ScopeRole = types.ScopeRole;
pub const Configure = types.Configure;

pub const steps = @import("step_catalog.zig").steps;

/// Configure declarations for scopes that are not a single catalog product.
/// Product scopes are derived directly from their product descriptors.
pub const configure = [_]Configure{
    .{ .scope = .architecture, .role = .gates, .external_tools = &.{"python3"}, .constructors = &.{ "gates/architecture_receipts.addGates", "gates/baseline.addGate" } },
    .{ .scope = .riscv_cpu_compat, .role = .product, .inherited_product_scope = .riscv_cpu, .constructors = &.{ "products/matrix.construct.riscv_cpu", "compatibility aliases" } },
    .{
        .scope = .riscv_metal,
        .role = .product,
        .product_ids = &.{"stwo-riscv-metal"},
        .module_roots = &.{
            "src/products/riscv/metal/main.zig",
            "src/products/riscv/tools/bench/metal_main.zig",
            "src/products/riscv/metal/root.zig",
            "src/integrations/riscv_metal/mod.zig",
            "src/products/riscv/cpu/tests/metal_backend_test.zig",
            "src/products/riscv/cpu/tests/recursive_framework_aot_test.zig",
            "src/products/riscv/cpu/tests/recursive_framework_resident_test.zig",
            "src/frontends/riscv/mod.zig",
        },
        // The production CLI carries `build_identity` and `product_identity`
        // options modules, and reaches the shared engine-generic adapter and
        // the proof-wire codec through their owning packages. Both are scope
        // observations rather than declarations, so they must be listed here
        // exactly: `check_build_configure_closure.py` compares the observed
        // generated and dependency roots against this catalog for equality,
        // not containment.
        .generated_module_roots = &.{"generated:options:"},
        .dependency_module_roots = &.{
            "dependency:../src/waist/backend:mod.zig",
            "dependency:../src/backends/metal:mod.zig",
            "dependency:../src/waist/core:mod.zig",
            "dependency:../src/frontends/riscv:mod.zig",
            "dependency:../src/integrations/riscv_cpu:proof_adapter.zig",
            "dependency:../src/integrations/riscv_metal:mod.zig",
            "dependency:../src/waist/proof_wire:mod.zig",
            "dependency:../src/engine/prover:mod.zig",
            "dependency:../src/waist/prover_api:mod.zig",
        },
        .external_tools = &.{"python3"},
        .runtime_probes = &.{ "Metal.framework", "Foundation.framework", "libobjc" },
        .allowed_module_files = &.{
            "src/backends/metal/runtime.m",
            "src/support/io/output_transaction.zig",
            "src/waist/recursion_wire/postcard/mod.zig",
            "src/products/riscv/artifact/mod.zig",
            "src/products/riscv/metal/app.zig",
            "src/products/riscv/metal/capabilities.zig",
            "src/products/riscv/metal/cli.zig",
            "src/products/riscv/metal/guest_poseidon2_app.zig",
            "src/products/riscv/metal/registry.zig",
            "src/products/riscv/metal/runtime_admission.zig",
            "src/products/riscv/shared/app.zig",
            "src/products/riscv/shared/cli.zig",
            "src/products/riscv/shared/registry.zig",
        },
        .constructors = &.{"products/matrix.construct.riscv_metal"},
        .constructed_products = &.{.{
            .product_id = "stwo-riscv-metal",
            .frontend = "riscv",
            .backend = "metal",
            .role = "cli",
            .protocol_manifest = "rv32im-zkvm-v1+lifted-pcs-v1+metal-runtime-v2+authenticated-core-aot-v2+rv32im-zkvm-poseidon2-v1+csp-ecdsa-typed-recovery-v1",
        }},
    },
    .{ .scope = .package, .role = .package_exports, .product_ids = &.{ "stwo-core", "stwo-prover", "stwo" }, .module_roots = &.{ "src/products/stwo/prover/root.zig", "src/products/stwo/root.zig", "src/products/stwo/tests/public_modules.zig", "build_support/products/consumer_laws.zig" }, .generated_module_roots = &.{"generated:options:"}, .dependency_module_roots = package_dependencies.public_package_roots, .allowed_module_files = &.{ "src/products/stwo/root.zig", "src/products/stwo/tests/public_modules.zig", "build_support/products/consumer_laws.zig", "build_support/graph/identity/emitter.zig", "src/products/native/artifact/mod.zig", "src/products/riscv/artifact/mod.zig", "src/support/io/atomic_file.zig", "src/support/io/output_transaction.zig", "src/support/shims/mod.zig", "src/support/tracing/mod.zig" }, .allowed_module_prefixes = &.{ "src/products/stwo/core", "src/products/stwo/prover" }, .external_tools = &.{"python3"}, .constructors = &.{"products/libraries.addProducts"}, .constructed_products = &.{
        .{ .product_id = "stwo-core", .frontend = "none", .backend = "none", .role = "library", .protocol_manifest = "stwo-core-v1" },
        .{ .product_id = "stwo-prover", .frontend = "none", .backend = "contracts", .role = "library", .protocol_manifest = "generic-prover+backend-contracts-v1" },
        .{ .product_id = "stwo", .frontend = "aggregate", .backend = "contracts", .role = "library", .protocol_manifest = "aggregate-sdk-v1" },
    } },
    .{ .scope = .metal_tools, .role = .backend_tools, .product_ids = &.{"stwo-native-metal-tools"}, .module_roots = &.{ "src/products/stwo/root.zig", "src/backends/metal/shader_manifest.zig" }, .generated_module_roots = &.{"generated:options:"}, .dependency_module_roots = package_dependencies.metal_tools_package_roots, .allowed_module_files = &.{ "src/products/stwo/root.zig", "src/backends/metal/tests/system/root.zig", "src/backends/metal/tools/arena_plan/main.zig", "src/products/riscv/tools/bench/metal_main.zig" }, .allowed_module_prefixes = &.{ "src/backends", "src/frontends", "src/integrations", "src/products", "src/support", "src/waist" }, .runtime_probes = &.{ "Metal.framework", "Foundation.framework", "libobjc" }, .constructors = &.{ "backends/metal_aot.addProducts", "benchmarks/metal.addProducts" } },
    .{
        .scope = .cuda_tools,
        .role = .backend_tools,
        .product_ids = &.{"stwo-native-cuda-tools"},
        .module_roots = &.{
            "build_support/backends/cuda.zig",
            "src/products/cairo/tools/cuda_eval_aot/main.zig",
            "src/products/cairo/tools/cuda_witness_aot/main.zig",
            "src/products/cairo/tools/witness_cpu_codegen/model.zig",
        },
        .dependency_module_roots = package_dependencies.frontend_cuda_metal_cpu_protocol_package_roots,
        .allowed_module_files = &.{
            "tests/cuda/cumetal/native_frontend_execution.zig",
            "tests/cuda/rv64/native/runtime/device_arena_test.cpp",
            "tests/cuda/rv64/native/rv64/pcs_idle_cache_test.cpp",
            "tests/cuda/rv64/native/rv64/prefix_banks_test.cpp",
            "tests/cuda/rv64/native/rv64/pcs_oom_diagnostics_test.cpp",
            // The deduction contract the CUDA witness AOT generator shares
            // with the Cairo witness programs.
            "src/frontends/cairo/witness/deduction_contract.zig",
            "src/frontends/cairo/interop/felt_json.zig",
            "src/frontends/cairo/interop/cairo_prover_parameters.zig",
            "src/waist/recursion_wire/postcard/mod.zig",
            "src/products/native/cuda/blake_route.zig",
            "src/products/stwo/root.zig",
            "src/products/native/tools/cuda_ec_composite_oracle/main.zig",
            "tests/native_cuda_blake_exact_structure.zig",
            "tests/native_cuda_plonk_logup.zig",
            "tests/native_cuda_poseidon_arena.zig",
            "tests/native_cuda_state_machine.zig",
            "tests/native_cuda_xor_logup.zig",
        },
        .allowed_module_prefixes = &.{
            "build_support/backends",
            "src/backends/cuda",
            "src/products/cairo/tools/cuda_eval_aot",
            "src/products/cairo/tools/cuda_witness_aot",
            "src/products/cairo/tools/witness_cpu_codegen",
        },
        .external_tools = &.{"python3"},
        .constructors = &.{"backends/cuda_tools.addProducts"},
    },
    .{
        .scope = .compatibility_tools,
        .role = .compatibility_tools,
        .product_ids = &.{"stwo-compatibility-tools"},
        .module_roots = &.{
            "src/products/native/tools/interop/main.zig",
            "src/products/cairo/tools/inspectors/input_inspector.zig",
            "src/products/cairo/tools/inspectors/air_bundle_inspector.zig",
            "src/frontends/cairo/witness/composition_bundle.zig",
            "src/frontends/cairo/tests/mod.zig",
            "src/products/cairo/cpu/tests/cpu_air_test.zig",
            "src/products/riscv/tools/opcode_manifest/main.zig",
            "src/products/riscv/tools/bench/main.zig",
            "src/products/native/tools/proof_bench/cpu.zig",
        },
        .dependency_module_roots = package_dependencies.compatibility_package_roots,
        .allowed_module_files = &.{ "src/products/stwo/root.zig", "src/support/shims/mod.zig", "src/support/tracing/mod.zig" },
        .allowed_module_prefixes = &.{
            "src/frontends/cairo",
            "src/frontends/riscv",
            "src/integrations/riscv_cpu",
            "src/integrations/cairo_cpu",
            "src/support/io",
            "src/waist/proof_wire",
            "src/waist/recursion_wire",
            "src/products/native/artifact",
            "src/products/riscv/artifact",
            "src/products/native/cpu",
            "src/products/cairo/cpu/tests",
            "src/products/cairo/tools",
            "src/products/native/tools",
            "src/products/riscv/tools",
            "src/products/stwo/tools",
        },
        .constructors = &.{"products/compatibility_tools.addProducts"},
    },
    .{ .scope = .verification, .role = .gates, .external_tools = &.{ "python3", "zig" }, .constructors = &.{ "gates/riscv.addGates", "gates/native.addGates", "benchmarks/native.addProducts", "gates/release_evidence.addGates" } },
    .{ .scope = .policy, .role = .gates, .external_tools = &.{ "python3", "zig" }, .constructors = &.{"internal_build.addPolicyGates"} },
    .{ .scope = .release, .role = .gates, .product_ids = &.{"stwo-zig-release"}, .external_tools = &.{ "python3", "zig" }, .constructors = &.{"gates/release.addGates"} },
};

pub fn configureFor(scope: Scope) ?Configure {
    for (configure) |spec| if (spec.scope == scope) return spec;
    return null;
}

pub fn parse(name: []const u8) ?Scope {
    return std.meta.stringToEnum(Scope, name);
}
