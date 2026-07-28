//! Stable descriptor for the opt-in aggregate compatibility CLI.

const graph = @import("../graph/modules.zig");
const policy = @import("../graph/product.zig");

const cpu_facade = "src/stwo_aggregate_cpu.zig";
const metal_facade = "src/stwo_aggregate_metal.zig";

const common_allowed_files = [_][]const u8{
    cpu_facade,
    "src/products/native_cpu/capabilities.zig",
    "src/products/riscv_cpu/capabilities.zig",
    "src/interop/atomic_file.zig",
    "src/interop/examples_artifact.zig",
    "src/interop/examples_artifact_verifier.zig",
    "src/interop/output_transaction.zig",
    "src/interop/postcard.zig",
    "src/interop/proof_wire/mod.zig",
    "src/interop/riscv_artifact.zig",
    "src/integrations/native/product_identity.zig",
    "src/integrations/native/transaction.zig",
};

const common_allowed_prefixes = [_][]const u8{
    "src/backend",
    "src/backends/cpu_scalar",
    "src/core",
    "src/examples",
    "src/frontends/riscv",
    "src/integrations/riscv_cpu",
    "src/interop/postcard",
    "src/interop/riscv_artifact",
    "src/prover",
    "src/std_shims",
    "src/tools/prove",
    "src/tracing",
};

const metal_allowed_files = common_allowed_files ++ .{
    metal_facade,
    "src/backends/metal/arena_plan.zig",
    "src/backends/metal/cairo/diagnostics/transcript_fixture.zig",
    "src/backends/metal/command_epoch.zig",
    "src/backends/metal/commit_backend.zig",
    "src/backends/metal/commit_policy.zig",
    "src/backends/metal/core_aot.zig",
    "src/backends/metal/merkle_tree.zig",
    "src/backends/metal/mod.zig",
    "src/backends/metal/protocol_recipes.zig",
    "src/backends/metal/prover_engine.zig",
    "src/backends/metal/recovery.zig",
    "src/backends/metal/resident_arena.zig",
    "src/backends/metal/runtime.zig",
    "src/backends/metal/shader_manifest.zig",
    "src/backends/metal/shared_runtime.zig",
    "src/backends/metal/telemetry.zig",
};

const metal_allowed_prefixes = common_allowed_prefixes ++ .{
    "src/backends/metal/recipes",
    "src/backends/metal/runtime",
    "src/backends/metal/shaders",
    "src/backends/metal/tests",
};

const shared_named_imports = [_]policy.NamedImport{
    .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
    .{ .name = "stwo_core", .source = "src/core/mod.zig" },
    .{ .name = "stwo_cpu_backend", .source = "src/backends/cpu_scalar/mod.zig" },
    .{ .name = "stwo_native_examples", .source = "src/examples/mod.zig" },
    .{ .name = "stwo_proof_wire", .source = "src/interop/proof_wire/mod.zig" },
    .{ .name = "stwo_prover_engine", .source = "src/prover/mod.zig" },
    .{ .name = "stwo_riscv_frontend", .source = "src/frontends/riscv/mod.zig" },
    .{ .name = "stwo_riscv_cpu_integration", .source = "src/integrations/riscv_cpu/mod.zig" },
    .{ .name = "native_proof_runner", .source = "src/prover/native/runner.zig" },
    .{ .name = "native_resource_admission", .source = "src/prover/native/resource_admission.zig" },
    .{ .name = "native_transaction", .source = "src/integrations/native/transaction.zig" },
    .{ .name = "output_transaction", .source = "src/interop/output_transaction.zig" },
    .{ .name = "native_product_identity", .source = "src/integrations/native/product_identity.zig" },
    .{ .name = "native_cpu_capabilities", .source = "src/products/native_cpu/capabilities.zig" },
    .{ .name = "riscv_cpu_capabilities", .source = "src/products/riscv_cpu/capabilities.zig" },
    .{ .name = "riscv_adapter", .source = "src/integrations/riscv_cpu/proof_adapter.zig" },
};

const cpu_named_imports = .{
    policy.NamedImport{ .name = "stwo", .source = cpu_facade },
} ++ shared_named_imports;

const metal_named_imports = .{
    policy.NamedImport{ .name = "stwo", .source = metal_facade },
    policy.NamedImport{
        .name = "stwo_metal_backend",
        .source = "src/backends/metal/mod.zig",
    },
} ++ shared_named_imports;

const cpu_source_closure = sourceClosure(false);
const metal_source_closure = sourceClosure(true);

fn sourceClosure(comptime metal: bool) policy.SourceClosure {
    return .{
        .entry_roots = &.{
            "src/tools/prove/main.zig",
            if (metal) metal_facade else cpu_facade,
            "src/prover/native/runner.zig",
        },
        .named_imports = if (metal) &metal_named_imports else &cpu_named_imports,
        .generated_imports = &.{"aggregate_capabilities"},
        .allowed_files = if (metal) &metal_allowed_files else &common_allowed_files,
        .allowed_prefixes = if (metal) &metal_allowed_prefixes else &common_allowed_prefixes,
        .required_dynamic_dependencies = if (metal) &.{
            "Metal.framework",
            "Foundation.framework",
            "libobjc",
        } else &.{},
        .forbidden_dynamic_dependencies = if (metal)
            &.{"cuda"}
        else
            &.{ "Metal.framework", "Foundation.framework", "libobjc", "cuda" },
    };
}

pub const descriptor = policy.Descriptor{
    .product = product(false),
    .state = .released,
    .target_support = .any,
    .build_step = "stwo-zig",
    .test_step = "test",
    .executable = "stwo-zig",
    .installed_artifacts = &.{"stwo-zig"},
    .release_gates = &.{ "test", "vectors", "interop" },
    .dependencies = .{ .module_roots = cpu_source_closure.entry_roots },
    .source_closure = cpu_source_closure,
};

pub fn product(metal: bool) graph.Product {
    return .{
        .name = "stwo-zig",
        .frontend = .aggregate,
        .backend = if (metal) .metal else .cpu,
        .role = .cli,
        .protocol_features = if (metal)
            "aggregate-compat-v1+cpu+metal"
        else
            "aggregate-compat-v1+cpu",
    };
}

pub fn descriptorFor(metal: bool) policy.Descriptor {
    var result = descriptor;
    result.product = product(metal);
    result.dependencies.module_roots = if (metal)
        metal_source_closure.entry_roots
    else
        cpu_source_closure.entry_roots;
    result.source_closure = if (metal) metal_source_closure else cpu_source_closure;
    return result;
}

test "aggregate product closures cannot own deferred implementation trees" {
    const std = @import("std");
    const deferred = [_][]const u8{
        "src/backends/cuda",
        "src/frontends/cairo",
        "src/integrations/cairo_cpu",
        "src/integrations/cairo_metal",
        "src/backends/metal/cairo",
    };
    inline for (.{ cpu_source_closure, metal_source_closure }) |closure| {
        for (closure.allowed_prefixes) |allowed| {
            for (deferred) |blocked| {
                try std.testing.expect(!owns(allowed, blocked));
            }
        }
    }
}

fn owns(allowed: []const u8, blocked: []const u8) bool {
    const std = @import("std");
    return std.mem.eql(u8, allowed, blocked) or
        (std.mem.startsWith(u8, blocked, allowed) and blocked[allowed.len] == '/');
}
