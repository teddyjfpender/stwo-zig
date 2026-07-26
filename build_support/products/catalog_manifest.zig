//! Scope projection and hashed machine-readable product catalog emission.

const std = @import("std");
const construction_observer = @import("../graph/construction_observer.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");
const aggregate = @import("aggregate.zig");
const catalog = @import("catalog.zig");
const specs = @import("product_specs.zig");

pub const Scope = specs.Scope;

pub const ScopeManifest = struct {
    scope: Scope,
    role: catalog.ScopeRole,
    product_ids: []const []const u8,
    module_roots: []const []const u8,
    generated_module_roots: []const []const u8,
    dependency_module_roots: []const []const u8,
    allowed_module_files: []const []const u8,
    allowed_module_prefixes: []const []const u8,
    external_tools: []const []const u8,
    runtime_probes: []const []const u8,
    constructors: []const []const u8,
    constructed_products: []const construction_observer.ProductIdentity,
};

pub fn scopeManifest(b: *std.Build, scope: Scope, aggregate_metal: bool) ScopeManifest {
    if (catalog.configureFor(scope)) |configured| {
        if (configured.inherited_product_scope) |inherited| {
            var manifest = scopeManifest(b, inherited, aggregate_metal);
            manifest.scope = scope;
            manifest.role = configured.role;
            manifest.constructors = configured.constructors;
            return manifest;
        }
        return .{
            .scope = scope,
            .role = configured.role,
            .product_ids = configured.product_ids,
            .module_roots = configured.module_roots,
            .generated_module_roots = configured.generated_module_roots,
            .dependency_module_roots = configured.dependency_module_roots,
            .allowed_module_files = configured.allowed_module_files,
            .allowed_module_prefixes = configured.allowed_module_prefixes,
            .external_tools = configured.external_tools,
            .runtime_probes = configured.runtime_probes,
            .constructors = configured.constructors,
            .constructed_products = configured.constructed_products,
        };
    }
    return productScopeManifest(b, scope, aggregate_metal);
}

fn productScopeManifest(b: *std.Build, scope: Scope, aggregate_metal: bool) ScopeManifest {
    var root_count: usize = 0;
    var tool_count: usize = 0;
    var probe_count: usize = 0;
    var generated_count: usize = 0;
    var dependency_count: usize = 0;
    var allowed_file_count: usize = 0;
    var allowed_prefix_count: usize = 0;
    var constructed_count: usize = 0;
    for (specs.products) |spec| {
        if (spec.scope != scope) continue;
        root_count += spec.descriptor.dependencies.module_roots.len;
        tool_count += spec.configure_tools.len;
        probe_count += spec.runtime_probes.len;
        generated_count += spec.generated_module_roots.len;
        dependency_count += spec.dependency_module_roots.len;
        allowed_file_count += spec.descriptor.dependencies.module_roots.len;
        allowed_file_count += spec.configure_allowed_files.len;
        allowed_prefix_count += spec.configure_allowed_prefixes.len;
        if (spec.descriptor.source_closure) |closure| {
            allowed_file_count += closure.allowed_files.len;
            allowed_prefix_count += closure.allowed_prefixes.len;
        }
        constructed_count += @intFromBool(spec.constructor != .unavailable);
    }
    const product_ids = productIdsForScope(b, scope);
    const roots = allocStrings(b, root_count);
    const tools = allocStrings(b, tool_count);
    const probes = allocStrings(b, probe_count);
    const generated = allocStrings(b, generated_count);
    const dependencies = allocStrings(b, dependency_count);
    const allowed_files = allocStrings(b, allowed_file_count);
    const allowed_prefixes = allocStrings(b, allowed_prefix_count);
    const constructed = b.allocator.alloc(
        construction_observer.ProductIdentity,
        constructed_count,
    ) catch @panic("out of memory");
    var indices = [_]usize{0} ** 8;
    for (specs.products) |spec| {
        if (spec.scope != scope) continue;
        appendStrings(roots, &indices[0], spec.descriptor.dependencies.module_roots);
        appendStrings(tools, &indices[1], spec.configure_tools);
        appendStrings(probes, &indices[2], spec.runtime_probes);
        appendStrings(generated, &indices[3], spec.generated_module_roots);
        appendStrings(dependencies, &indices[4], spec.dependency_module_roots);
        appendStrings(allowed_files, &indices[5], spec.descriptor.dependencies.module_roots);
        if (spec.descriptor.source_closure) |closure| {
            appendStrings(allowed_files, &indices[5], closure.allowed_files);
            appendStrings(allowed_prefixes, &indices[6], closure.allowed_prefixes);
        }
        appendStrings(allowed_files, &indices[5], spec.configure_allowed_files);
        appendStrings(allowed_prefixes, &indices[6], spec.configure_allowed_prefixes);
        if (spec.constructor != .unavailable) {
            const product = if (scope == .aggregate)
                aggregate.product(aggregate_metal)
            else
                spec.descriptor.product;
            constructed[indices[7]] = productIdentity(product);
            indices[7] += 1;
        }
    }
    return .{
        .scope = scope,
        .role = if (scope == .deferred) .unavailable else .product,
        .product_ids = product_ids,
        .module_roots = roots,
        .generated_module_roots = generated,
        .dependency_module_roots = dependencies,
        .allowed_module_files = allowed_files,
        .allowed_module_prefixes = allowed_prefixes,
        .external_tools = tools,
        .runtime_probes = probes,
        .constructors = constructorsFor(b, scope),
        .constructed_products = constructed,
    };
}

fn constructorsFor(b: *std.Build, scope: Scope) []const []const u8 {
    if (scope == .aggregate)
        return &.{ "products/matrix.construct.aggregate", "products/matrix.addIdentity" };
    if (scope == .deferred) return &.{"products/matrix.addDeferredProducts"};
    const spec = specs.findByScope(scope) orelse
        std.debug.panic("scope {s} has no constructible catalog product", .{@tagName(scope)});
    const result = allocStrings(b, 1);
    result[0] = constructorName(spec.constructor);
    return result;
}

pub fn stepsForScope(b: *std.Build, scope: Scope) []const []const u8 {
    var names = std.StringHashMap(void).init(b.allocator);
    const ProductScopes = struct {
        fn add(map: *std.StringHashMap(void), selected: Scope) void {
            for (specs.products) |spec| {
                if (spec.scope != selected) continue;
                map.put(spec.descriptor.build_step, {}) catch @panic("out of memory");
                if (spec.descriptor.test_step) |step| map.put(step, {}) catch @panic("out of memory");
                if (spec.descriptor.benchmark_step) |step| map.put(step, {}) catch @panic("out of memory");
                if (spec.identity_step) |step| map.put(step, {}) catch @panic("out of memory");
            }
        }
    };
    switch (scope) {
        .prover => {
            ProductScopes.add(&names, .core);
            ProductScopes.add(&names, .prover);
        },
        .package => {
            ProductScopes.add(&names, .core);
            ProductScopes.add(&names, .prover);
        },
        .riscv_cpu_compat => ProductScopes.add(&names, .riscv_cpu),
        else => ProductScopes.add(&names, scope),
    }
    const inherited_scope = if (catalog.configureFor(scope)) |configured|
        configured.inherited_product_scope
    else
        null;
    for (catalog.steps) |step| {
        if (step.scope == scope or (inherited_scope != null and step.scope == inherited_scope.?))
            names.put(step.name, {}) catch @panic("out of memory");
    }
    if (scope == .aggregate)
        names.put("product-matrix-identity", {}) catch @panic("out of memory");
    const result = allocStrings(b, names.count());
    var iterator = names.keyIterator();
    var index: usize = 0;
    while (iterator.next()) |name| : (index += 1) result[index] = name.*;
    std.mem.sort([]const u8, result, {}, lessThan);
    return result;
}

pub fn addIdentity(b: *std.Build, aggregate_metal: bool) void {
    var product_records: [specs.descriptors.len]MatrixProduct = undefined;
    inline for (specs.descriptors, 0..) |static_descriptor, index| {
        const descriptor = if (index == 0)
            aggregate.descriptorFor(aggregate_metal)
        else
            static_descriptor;
        product_records[index] = matrixProduct(descriptor, specs.products[index]);
    }
    const scope_values = comptime std.enums.values(Scope);
    var scope_records: [scope_values.len]MatrixScope = undefined;
    inline for (scope_values, 0..) |scope, index| {
        const manifest = scopeManifest(b, scope, aggregate_metal);
        scope_records[index] = .{
            .scope = @tagName(scope),
            .role = @tagName(manifest.role),
            .steps = stepsForScope(b, scope),
            .product_ids = manifest.product_ids,
            .module_roots = manifest.module_roots,
            .generated_module_roots = manifest.generated_module_roots,
            .dependency_module_roots = manifest.dependency_module_roots,
            .allowed_module_files = manifest.allowed_module_files,
            .allowed_module_prefixes = manifest.allowed_module_prefixes,
            .external_tools = manifest.external_tools,
            .runtime_probes = manifest.runtime_probes,
            .constructors = manifest.constructors,
            .constructed_products = manifest.constructed_products,
        };
    }
    const payload = std.json.Stringify.valueAlloc(b.allocator, .{
        .schema = "stwo-product-catalog-v2",
        .products = &product_records,
        .scopes = &scope_records,
    }, .{}) catch @panic("cannot encode product catalog");
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const encoded = std.json.Stringify.valueAlloc(b.allocator, .{
        .schema = "stwo-product-catalog-v2",
        .catalog_sha256 = &hex,
        .products = &product_records,
        .scopes = &scope_records,
    }, .{}) catch @panic("cannot encode product catalog identity");
    const files = b.addWriteFiles();
    const generated = files.add("product-matrix.json", encoded);
    const install = b.addInstallFile(generated, "identity/product-matrix.json");
    b.step("product-matrix-identity", "Emit the hashed authoritative product capability matrix")
        .dependOn(&install.step);
}

fn matrixProduct(descriptor: product_policy.Descriptor, spec: specs.Spec) MatrixProduct {
    const closure = descriptor.source_closure;
    return .{
        .scope = @tagName(spec.scope),
        .descriptor_schema_version = descriptor.schema_version,
        .product_id = descriptor.product.name,
        .frontend = @tagName(descriptor.product.frontend),
        .backend = @tagName(descriptor.product.backend),
        .role = @tagName(descriptor.product.role),
        .protocol_manifest = descriptor.product.protocol_features,
        .state = @tagName(descriptor.state),
        .target_support = @tagName(descriptor.target_support),
        .unsupported_target_reason = descriptor.unsupported_target_reason,
        .unavailable_reason = descriptor.unavailable_reason,
        .build_step = descriptor.build_step,
        .test_step = descriptor.test_step,
        .executable = descriptor.executable,
        .installed_artifacts = descriptor.installed_artifacts,
        .compatibility_aliases = descriptor.compatibility_aliases,
        .release_gates = descriptor.release_gates,
        .benchmark_step = descriptor.benchmark_step,
        .profiler_step = descriptor.profiler_step,
        .module_roots = descriptor.dependencies.module_roots,
        .generated_module_roots = spec.generated_module_roots,
        .dependency_module_roots = spec.dependency_module_roots,
        .external_dependencies = descriptor.dependencies.external_dependencies,
        .source_closure = closure,
        .required_dynamic_dependencies = if (closure) |value| value.required_dynamic_dependencies else &.{},
        .forbidden_dynamic_dependencies = if (closure) |value| value.forbidden_dynamic_dependencies else &.{},
        .allowed_files = if (closure) |value| value.allowed_files else &.{},
        .allowed_prefixes = if (closure) |value| value.allowed_prefixes else &.{},
        .configure_allowed_files = spec.configure_allowed_files,
        .configure_allowed_prefixes = spec.configure_allowed_prefixes,
    };
}

fn productIdsForScope(b: *std.Build, scope: Scope) []const []const u8 {
    var count: usize = 0;
    for (specs.products) |spec| count += @intFromBool(spec.scope == scope);
    const result = allocStrings(b, count);
    var index: usize = 0;
    for (specs.products) |spec| {
        if (spec.scope != scope) continue;
        result[index] = spec.descriptor.product.name;
        index += 1;
    }
    return result;
}

pub fn constructorName(constructor: specs.Constructor) []const u8 {
    return switch (constructor) {
        .aggregate => "products/matrix.construct.aggregate",
        .cairo_cuda => "products/matrix.construct.cairo_cuda",
        .core => "products/matrix.construct.core",
        .prover => "products/matrix.construct.prover",
        .native_cpu => "products/matrix.construct.native_cpu",
        .native_cuda => "products/matrix.construct.native_cuda",
        .native_metal => "products/matrix.construct.native_metal",
        .riscv_cpu => "products/matrix.construct.riscv_cpu",
        .riscv_metal => "products/matrix.construct.riscv_metal",
        .unavailable => "products/matrix.addDeferredProducts",
    };
}

fn productIdentity(product: graph.Product) construction_observer.ProductIdentity {
    return .{
        .product_id = product.name,
        .frontend = @tagName(product.frontend),
        .backend = @tagName(product.backend),
        .role = @tagName(product.role),
        .protocol_manifest = product.protocol_features,
    };
}

fn allocStrings(b: *std.Build, count: usize) [][]const u8 {
    return b.allocator.alloc([]const u8, count) catch @panic("out of memory");
}

fn appendStrings(output: [][]const u8, index: *usize, values: []const []const u8) void {
    for (values) |value| {
        output[index.*] = value;
        index.* += 1;
    }
}

fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.lessThan(u8, lhs, rhs);
}

const MatrixProduct = struct {
    scope: []const u8,
    descriptor_schema_version: u32,
    product_id: []const u8,
    frontend: []const u8,
    backend: []const u8,
    role: []const u8,
    protocol_manifest: []const u8,
    state: []const u8,
    target_support: []const u8,
    unsupported_target_reason: ?[]const u8,
    unavailable_reason: ?[]const u8,
    build_step: []const u8,
    test_step: ?[]const u8,
    executable: ?[]const u8,
    installed_artifacts: []const []const u8,
    compatibility_aliases: []const []const u8,
    release_gates: []const []const u8,
    benchmark_step: ?[]const u8,
    profiler_step: ?[]const u8,
    module_roots: []const []const u8,
    generated_module_roots: []const []const u8,
    dependency_module_roots: []const []const u8,
    external_dependencies: []const []const u8,
    source_closure: ?product_policy.SourceClosure,
    required_dynamic_dependencies: []const []const u8,
    forbidden_dynamic_dependencies: []const []const u8,
    allowed_files: []const []const u8,
    allowed_prefixes: []const []const u8,
    configure_allowed_files: []const []const u8,
    configure_allowed_prefixes: []const []const u8,
};

const MatrixScope = struct {
    scope: []const u8,
    role: []const u8,
    steps: []const []const u8,
    product_ids: []const []const u8,
    module_roots: []const []const u8,
    generated_module_roots: []const []const u8,
    dependency_module_roots: []const []const u8,
    allowed_module_files: []const []const u8,
    allowed_module_prefixes: []const []const u8,
    external_tools: []const []const u8,
    runtime_probes: []const []const u8,
    constructors: []const []const u8,
    constructed_products: []const construction_observer.ProductIdentity,
};
