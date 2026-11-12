//! Stable descriptor for the opt-in aggregate compatibility CLI.

const std = @import("std");
const graph = @import("../graph/modules.zig");
const policy = @import("../graph/product.zig");

const cpu_facade = "src/products/cairo/aggregate/cpu.zig";
const metal_facade = "src/products/cairo/aggregate/metal.zig";

const common_allowed_files = [_][]const u8{
    "src/products/native/artifact/tests/xor_codec_roundtrip.zig",
    "src/waist/proof_wire/bounded_count_test.zig",
    "src/waist/proof_wire/hash_family_test.zig",
    "src/waist/proof_wire/wide_test.zig",

    cpu_facade,
    "src/products/native/cpu/capabilities.zig",
    "src/products/riscv/cpu/capabilities.zig",
    "src/support/io/atomic_file.zig",
    "src/products/native/artifact/examples_artifact.zig",
    "src/products/native/artifact/examples_artifact_verifier.zig",
    "src/support/io/output_transaction.zig",
    "src/waist/recursion_wire/postcard/mod.zig",
    "src/waist/proof_wire/mod.zig",
    "src/waist/proof_wire/family.zig",
    "src/products/riscv/artifact/mod.zig",
    "src/integrations/native/product_identity.zig",
    "src/integrations/native/transaction.zig",
};

const common_allowed_prefixes = [_][]const u8{
    "src/waist/backend",
    "src/backends/cpu_scalar",
    "src/waist/core",
    "src/products/native/examples",
    "src/frontends/riscv",
    "src/integrations/riscv_cpu",
    "src/waist/recursion_wire/postcard",
    "src/products/riscv/artifact",
    "src/engine/prover",
    "src/waist/prover_api",
    "src/support/shims",
    "src/products/stwo/tools/prove",
    "src/support/tracing",
};

// Metal ownership is enumerated leaf by leaf rather than granted with any
// directory prefix that stands above a deferred subtree. Such a prefix hands
// the aggregate compatibility CLI implementation trees this product must never
// carry, and the hazard is not confined to `src/backends/metal` itself:
// `src/backends/metal/shaders` stands directly above the deferred
// `src/backends/metal/shaders/cairo` shader tree, so it is enumerated leaf by
// leaf too. Every entry below is measured against the real closure, not
// guessed: `scripts/repo/check_product_closure.py` run with a candidate grant
// withheld reports exactly the files that grant must restore.
const metal_allowed_files = common_allowed_files ++ .{
    metal_facade,
    // Also the `stwo_metal_backend` named-import source, which the closure
    // checker honours on its own. Listed anyway so this leaf enumeration
    // answers "which Metal sources does the product carry?" completely,
    // without a reader having to cross-reference the named-import table.
    "src/backends/metal/arena_plan.zig",
    "src/backends/metal/mod.zig",
    "src/backends/metal/command_epoch.zig",
    "src/backends/metal/commit_backend.zig",
    "src/backends/metal/commit_backend_fri.zig",
    "src/backends/metal/commit_policy.zig",
    "src/backends/metal/core_aot.zig",
    "src/backends/metal/host_primitives.zig",
    "src/backends/metal/merkle_tree.zig",
    "src/backends/metal/protocol_recipes.zig",
    "src/backends/metal/prover_engine.zig",
    "src/backends/metal/recovery.zig",
    "src/backends/metal/resident_arena.zig",
    "src/backends/metal/runtime.zig",
    // The three shader-tree sources the closure actually reaches. The former
    // `src/backends/metal/shaders` prefix additionally granted the deferred
    // `cairo/` shader tree and `runtime_initialization_contract_test.zig`,
    // which the closure does not reach.
    "src/backends/metal/shaders/abi_contract.zig",
    "src/backends/metal/shaders/build_contract.zig",
    "src/backends/metal/shaders/manifest.zig",
    "src/backends/metal/shaders/manifest_test.zig",
    "src/backends/metal/shared_runtime.zig",
    "src/backends/metal/source_contract.zig",
    "src/backends/metal/telemetry.zig",
};

const metal_allowed_prefixes = common_allowed_prefixes ++ .{
    "src/backends/metal/recipes",
    "src/backends/metal/runtime",
};

const shared_named_imports = [_]policy.NamedImport{
    .{ .name = "atomic_file", .source = "src/support/io/atomic_file.zig" },
    .{ .name = "stwo_native_artifact", .source = "src/products/native/artifact/mod.zig" },
    .{ .name = "interop_riscv_artifact", .source = "src/products/riscv/artifact/mod.zig" },
    .{ .name = "stwo_backend_contracts", .source = "src/waist/backend/mod.zig" },
    .{ .name = "stwo_core", .source = "src/waist/core/mod.zig" },
    .{ .name = "stwo_cpu_backend", .source = "src/backends/cpu_scalar/mod.zig" },
    .{ .name = "interop_postcard", .source = "src/waist/recursion_wire/postcard/mod.zig" },
    .{ .name = "stwo_native_examples", .source = "src/products/native/examples/mod.zig" },
    .{ .name = "stwo_proof_wire", .source = "src/waist/proof_wire/mod.zig" },
    .{ .name = "stwo_prover_api", .source = "src/waist/prover_api/mod.zig" },
    .{ .name = "stwo_prover_engine", .source = "src/engine/prover/mod.zig" },
    .{ .name = "stwo_riscv_frontend", .source = "src/frontends/riscv/mod.zig" },
    .{ .name = "stwo_riscv_isa", .source = "src/frontends/riscv/isa/mod.zig" },
    .{ .name = "stwo_riscv_air_lang", .source = "src/frontends/riscv/air_lang/mod.zig" },
    .{ .name = "stwo_riscv_memory", .source = "src/frontends/riscv/memory/mod.zig" },
    .{ .name = "stwo_riscv_recursion_air", .source = "src/frontends/riscv/recursion_air/mod.zig" },
    .{ .name = "stwo_riscv_precompiles", .source = "src/frontends/riscv/precompiles/mod.zig" },
    .{ .name = "stwo_riscv_rv32", .source = "src/frontends/riscv/rv32/mod.zig" },
    .{ .name = "stwo_riscv_rv64", .source = "src/frontends/riscv/rv64/mod.zig" },
    .{ .name = "stwo_riscv_recursion", .source = "src/frontends/riscv/recursion/mod.zig" },
    .{ .name = "stwo_riscv_testing", .source = "src/frontends/riscv/testing/mod.zig" },
    .{ .name = "native_proof_runner", .source = "src/engine/prover/native/runner.zig" },
    .{ .name = "native_resource_admission", .source = "src/engine/prover/native/resource_admission.zig" },
    .{ .name = "native_transaction", .source = "src/integrations/native/transaction.zig" },
    .{ .name = "output_transaction", .source = "src/support/io/output_transaction.zig" },
    .{ .name = "native_product_identity", .source = "src/integrations/native/product_identity.zig" },
    .{ .name = "native_cpu_capabilities", .source = "src/products/native/cpu/capabilities.zig" },
    .{ .name = "riscv_cpu_capabilities", .source = "src/products/riscv/cpu/capabilities.zig" },
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
            "src/products/stwo/tools/prove/main.zig",
            if (metal) metal_facade else cpu_facade,
            "src/engine/prover/native/runner.zig",
        },
        .named_imports = if (metal) &metal_named_imports else &cpu_named_imports,
        // Lexical closure reaches the RISC-V package's compatibility and
        // proposal tests. These fixtures are injected only on the fresh test
        // module; neither aggregate executable constructs or consumes them.
        .generated_imports = &.{
            "aggregate_capabilities",
            "typed_air_artifacts",
            "typed_air_h009_artifacts",
            "typed_air_h010_artifacts",
        },
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

/// Implementation trees the aggregate compatibility CLI must never carry.
/// These are prohibitions, not inventory: an entry naming a path that does not
/// exist yet is the point, because it forbids the tree before someone adds it.
const deferred_trees = [_][]const u8{
    "src/backends/cuda",
    "src/frontends/cairo",
    "src/integrations/cairo_cpu",
    "src/integrations/cairo_metal",
    "src/backends/metal/cairo",
    "src/backends/metal/shaders/cairo",
};

test "aggregate product closures cannot own deferred implementation trees" {
    inline for (.{ cpu_source_closure, metal_source_closure }) |closure| {
        try rejectDeferredOwnership(closure);
    }
}

fn rejectDeferredOwnership(closure: policy.SourceClosure) !void {
    for (deferred_trees) |blocked| {
        for (closure.allowed_prefixes) |allowed| {
            // A prefix above a deferred tree grants the entire tree; a prefix
            // inside one grants part of it. Ownership runs in both directions.
            if (owns(allowed, blocked)) return error.DeferredTreeOwnedByPrefix;
            if (owns(blocked, allowed)) return error.DeferredSubtreeOwnedByPrefix;
        }
        for (closure.allowed_files) |allowed| {
            if (owns(blocked, allowed)) return error.DeferredTreeOwnedByFile;
        }
        // A named import confers ownership too: the closure checker admits a
        // named import's source whether or not any file or prefix names it, so
        // a named import reaching into a deferred tree would carry that tree
        // past a ratchet that only inspected files and prefixes.
        for (closure.named_imports) |named| {
            if (owns(blocked, named.source)) return error.DeferredTreeOwnedByNamedImport;
        }
    }
}

fn owns(container: []const u8, member: []const u8) bool {
    return std.mem.eql(u8, container, member) or
        (std.mem.startsWith(u8, member, container) and member[container.len] == '/');
}

test "every deferred ownership direction is load-bearing" {
    const base = policy.SourceClosure{ .entry_roots = &.{"src/products/stwo/tools/prove/main.zig"} };

    // A prefix standing above a deferred tree.
    var above = base;
    above.allowed_prefixes = &.{"src/frontends"};
    try std.testing.expectError(
        error.DeferredTreeOwnedByPrefix,
        rejectDeferredOwnership(above),
    );

    // The exact grant this ratchet was widened to catch: a shader-tree prefix
    // one level below `src/backends/metal`, standing above a deferred Cairo
    // shader tree. Replacing a blanket prefix with a narrower one does not by
    // itself discharge the rule.
    var shader_prefix = base;
    shader_prefix.allowed_prefixes = &.{"src/backends/metal/shaders"};
    try std.testing.expectError(
        error.DeferredTreeOwnedByPrefix,
        rejectDeferredOwnership(shader_prefix),
    );

    // A prefix reaching down into a deferred tree.
    var inside = base;
    inside.allowed_prefixes = &.{"src/backends/metal/cairo/diagnostics"};
    try std.testing.expectError(
        error.DeferredSubtreeOwnedByPrefix,
        rejectDeferredOwnership(inside),
    );

    // A single file named out of a deferred tree.
    var by_file = base;
    by_file.allowed_files = &.{"src/backends/metal/cairo/diagnostics/transcript_fixture.zig"};
    try std.testing.expectError(
        error.DeferredTreeOwnedByFile,
        rejectDeferredOwnership(by_file),
    );

    // A named import reaching into a deferred tree, which the closure checker
    // would admit without any file or prefix naming it.
    var by_named_import = base;
    by_named_import.named_imports = &.{
        .{ .name = "cairo_metal_shaders", .source = "src/backends/metal/shaders/cairo/mod.zig" },
    };
    try std.testing.expectError(
        error.DeferredTreeOwnedByNamedImport,
        rejectDeferredOwnership(by_named_import),
    );

    // Sibling paths that merely share a textual prefix stay admissible.
    var clean = base;
    clean.allowed_prefixes = &.{ "src/waist/backend", "src/backends/cpu_scalar", "src/waist/core" };
    clean.allowed_files = &.{cpu_facade};
    clean.named_imports = &.{
        .{ .name = "stwo_metal_backend", .source = "src/backends/metal/mod.zig" },
    };
    try rejectDeferredOwnership(clean);
}
