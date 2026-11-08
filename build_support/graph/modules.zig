//! Typed product declarations and focused Zig module construction.

const std = @import("std");
const package_ownership = @import("package_ownership.zig");
const protocol_modules = @import("protocol_modules.zig");

const product_spec = @import("product_spec.zig");
pub const Frontend = product_spec.Frontend;
pub const Backend = product_spec.Backend;
pub const Role = product_spec.Role;
pub const Product = product_spec.Product;
pub const ModuleSpec = product_spec.ModuleSpec;
pub const coreProduct = product_spec.coreProduct;
pub const proverProduct = product_spec.proverProduct;

pub const ProtocolModules = protocol_modules.ProtocolModules;

pub fn create(b: *std.Build, spec: ModuleSpec) *std.Build.Module {
    spec.product.validate() catch |err| std.debug.panic(
        "invalid build product {s}: {s}",
        .{ spec.product.name, @errorName(err) },
    );
    return b.createModule(.{
        .root_source_file = ownedRootSource(b, spec),
        .target = spec.target,
        .optimize = spec.optimize,
    });
}

pub fn addPublic(b: *std.Build, name: []const u8, spec: ModuleSpec) *std.Build.Module {
    spec.product.validate() catch |err| std.debug.panic(
        "invalid public build product {s}: {s}",
        .{ spec.product.name, @errorName(err) },
    );
    return b.addModule(name, .{
        .root_source_file = ownedRootSource(b, spec),
        .target = spec.target,
        .optimize = spec.optimize,
    });
}

/// Resolves package-owned roots; other roots remain aggregate-relative.
fn ownedRootSource(b: *std.Build, spec: ModuleSpec) std.Build.LazyPath {
    return source(
        b,
        spec.root_source_file,
        spec.target,
        spec.optimize,
    );
}

pub fn source(
    b: *std.Build,
    root_source_file: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) std.Build.LazyPath {
    const owned = package_ownership.resolve(root_source_file) orelse
        return b.path(root_source_file);
    const dependency_options = .{
        .target = target,
        .optimize = optimize,
    };
    const dependency_name = package_ownership.dependencyName(owned.package);
    return b.dependency(dependency_name, dependency_options).path(owned.sub_path);
}

pub fn createProtocolModules(
    b: *std.Build,
    core: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) ProtocolModules {
    const backend_contracts = create(b, .{
        .product = proverProduct(.library),
        .root_source_file = "src/waist/backend/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    backend_contracts.addImport("stwo_core", core);

    const prover_api = create(b, .{
        .product = proverProduct(.library),
        .root_source_file = "src/waist/prover_api/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    prover_api.addImport("stwo_core", core);

    const prover = create(b, .{
        .product = proverProduct(.library),
        .root_source_file = "src/engine/prover/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    prover.addImport("stwo_core", core);
    prover.addImport("stwo_backend_contracts", backend_contracts);
    prover.addImport("stwo_prover_api", prover_api);

    return .{
        .core = core,
        .backend_contracts = backend_contracts,
        .prover_api = prover_api,
        .prover = prover,
    };
}

pub fn createPrivateProtocolModules(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) ProtocolModules {
    const core = create(b, .{
        .product = coreProduct(.library),
        .root_source_file = "src/waist/core/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    return createProtocolModules(b, core, target, optimize);
}

/// Constructs the canonical RISC-V frontend against selected protocol modules.
pub fn createRiscVFrontend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    proof_wire_override: ?*std.Build.Module,
) *std.Build.Module {
    const frontend = create(b, .{
        .product = product,
        .root_source_file = "src/frontends/riscv/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(frontend);
    const proof_wire = proof_wire_override orelse
        createProofWire(b, protocol, product, target, optimize);
    const postcard = create(b, .{
        .product = product,
        .root_source_file = "src/waist/recursion_wire/postcard/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    postcard.addImport("stwo_core", protocol.core);
    postcard.addImport("stwo_proof_wire", proof_wire);
    frontend.addImport("interop_postcard", postcard);
    return frontend;
}

pub fn addRiscVFrontendImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const frontend = createRiscVFrontend(
        b,
        protocol,
        product,
        target,
        optimize,
        consumer.import_table.get("stwo_proof_wire"),
    );
    consumer.addImport("stwo_riscv_frontend", frontend);
    const postcard = frontend.import_table.get("interop_postcard") orelse
        @panic("canonical RISC-V frontend is missing interop_postcard");
    consumer.addImport("interop_postcard", postcard);
    return frontend;
}

/// Constructs the canonical Cairo frontend against a selected protocol set.
pub fn createCairoFrontend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const frontend = create(b, .{
        .product = product,
        .root_source_file = "src/frontends/cairo/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(frontend);
    // The injected interop felt JSON writer behind `proof.cairo_serde`.
    const felt_json = create(b, .{
        .product = product,
        .root_source_file = "src/frontends/cairo/interop/felt_json.zig",
        .target = target,
        .optimize = optimize,
    });
    felt_json.addImport("stwo_core", protocol.core);
    frontend.addImport("interop_felt_json", felt_json);
    // The injected `ProverParameters` (the circuit registry's
    // `cairo_prover_params`, shared with the circuit-recursion wire package)
    // behind `proving.leaf_lane`.
    const prover_parameters = create(b, .{
        .product = product,
        .root_source_file = "src/frontends/cairo/interop/cairo_prover_parameters.zig",
        .target = target,
        .optimize = optimize,
    });
    prover_parameters.addImport("stwo_core", protocol.core);
    frontend.addImport("interop_cairo_prover_parameters", prover_parameters);
    return frontend;
}

/// Constructs the circuit-recursion wire package beside a Cairo frontend.
/// The two share the injected `interop_felt_json` and
/// `interop_cairo_prover_parameters` modules: a file belongs to one module per
/// compilation, so the wire package takes the frontend's instances.
pub fn createCircuitRecursionWire(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cairo_frontend: *std.Build.Module,
) *std.Build.Module {
    const wire = create(b, .{
        .product = product,
        .root_source_file = "src/waist/recursion_wire/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    wire.addImport("stwo_core", protocol.core);
    inline for (.{ "interop_felt_json", "interop_cairo_prover_parameters" }) |name| {
        wire.addImport(name, cairo_frontend.import_table.get(name) orelse
            @panic("Cairo frontend is missing " ++ name));
    }
    return wire;
}

/// Declares a consumer's dependency on the package-owned Cairo API.
pub fn addCairoFrontendImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const frontend = createCairoFrontend(
        b,
        protocol,
        product,
        target,
        optimize,
    );
    consumer.addImport("stwo_cairo_frontend", frontend);
    return frontend;
}

/// Constructs the canonical CPU backend against a selected protocol set.
pub fn createCpuBackend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const backend = create(b, .{
        .product = product,
        .root_source_file = "src/backends/cpu_scalar/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(backend);
    return backend;
}

/// Declares a consumer's dependency on the package-owned CPU backend API.
pub fn addCpuBackendImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const backend = createCpuBackend(
        b,
        protocol,
        product,
        target,
        optimize,
    );
    consumer.addImport("stwo_cpu_backend", backend);
    return backend;
}

/// Constructs the canonical host-independent CUDA backend contract module.
pub fn createCudaBackend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const backend = create(b, .{
        .product = product,
        .root_source_file = "src/backends/cuda/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    backend.addImport("stwo_backend_contracts", protocol.backend_contracts);
    return backend;
}

/// Declares a consumer's dependency on the package-owned CUDA backend API.
pub fn addCudaBackendImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const backend = createCudaBackend(
        b,
        protocol,
        product,
        target,
        optimize,
    );
    consumer.addImport("stwo_cuda_backend", backend);
    return backend;
}

/// Constructs the canonical Metal backend against protocol-owned primitives.
pub fn createMetalBackend(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const backend = create(b, .{
        .product = product,
        .root_source_file = "src/backends/metal/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(backend);
    return backend;
}

/// Declares a consumer's dependency on the package-owned Metal backend API.
pub fn addMetalBackendImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const backend = createMetalBackend(
        b,
        protocol,
        product,
        target,
        optimize,
    );
    consumer.addImport("stwo_metal_backend", backend);
    return backend;
}

/// Constructs the host-neutral persistent typed artifact-store module.
pub fn createArtifactStore(
    b: *std.Build,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return create(b, .{
        .product = product,
        .root_source_file = "src/engine/artifact_store/mod.zig",
        .target = target,
        .optimize = optimize,
    });
}

pub fn addArtifactStoreImport(
    b: *std.Build,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const artifact_store = createArtifactStore(b, product, target, optimize);
    consumer.addImport("stwo_artifact_store", artifact_store);
    return artifact_store;
}

/// Constructs the host-independent persistent Metal-session service module.
pub fn createMetalSession(
    b: *std.Build,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    artifact_store_override: ?*std.Build.Module,
) *std.Build.Module {
    const metal_session = create(b, .{
        .product = product,
        .root_source_file = "src/backends/metal/session/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    const artifact_store = artifact_store_override orelse
        createArtifactStore(b, product, target, optimize);
    metal_session.addImport("stwo_artifact_store", artifact_store);
    return metal_session;
}

/// Declares a consumer's dependency on the package-owned Metal-session API.
pub fn addMetalSessionImport(
    b: *std.Build,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const metal_session = createMetalSession(
        b,
        product,
        target,
        optimize,
        consumer.import_table.get("stwo_artifact_store"),
    );
    consumer.addImport("stwo_metal_session", metal_session);
    return metal_session;
}

/// Constructs the proof interchange codec against the selected protocol core.
pub fn createProofWire(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const proof_wire = create(b, .{
        .product = product,
        .root_source_file = "src/waist/proof_wire/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    proof_wire.addImport("stwo_core", protocol.core);
    return proof_wire;
}

/// Declares a consumer's dependency on the package-owned proof-wire API.
pub fn addProofWireImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const proof_wire = createProofWire(
        b,
        protocol,
        product,
        target,
        optimize,
    );
    consumer.addImport("stwo_proof_wire", proof_wire);
    return proof_wire;
}

/// Constructs Native example AIRs against their explicit dependencies.
pub fn createNativeExamples(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cpu_backend: *std.Build.Module,
    proof_wire: *std.Build.Module,
) *std.Build.Module {
    const examples = create(b, .{
        .product = product,
        .root_source_file = "src/products/native/examples/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    examples.addImport("stwo_core", protocol.core);
    examples.addImport("stwo_prover_api", protocol.prover_api);
    examples.addImport("stwo_prover_engine", protocol.prover);
    examples.addImport("stwo_cpu_backend", cpu_backend);
    examples.addImport("stwo_proof_wire", proof_wire);
    return examples;
}

/// Declares a consumer's dependency on the package-owned Native example API.
pub fn addNativeExamplesImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    cpu_backend: *std.Build.Module,
    proof_wire: *std.Build.Module,
    consumer: *std.Build.Module,
) *std.Build.Module {
    const examples = createNativeExamples(
        b,
        protocol,
        product,
        target,
        optimize,
        cpu_backend,
        proof_wire,
    );
    consumer.addImport("stwo_native_examples", examples);
    return examples;
}

/// Leaf modules owned by `src/support/io`. Each file is its own module, so a
/// compilation never sees one file in two modules: a consumer that already
/// imports a name keeps that instance.
pub const SupportIo = enum {
    atomic_file,
    output_transaction,
    interop_bzip2,

    fn rootSource(self: SupportIo) []const u8 {
        return switch (self) {
            .atomic_file => "src/support/io/atomic_file.zig",
            .output_transaction => "src/support/io/output_transaction.zig",
            .interop_bzip2 => "src/support/io/bzip2.zig",
        };
    }
};

/// Returns the consumer's `name` import, or creates and registers the leaf.
pub fn addSupportIoImport(
    b: *std.Build,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
    leaf: SupportIo,
) *std.Build.Module {
    const name = @tagName(leaf);
    if (consumer.import_table.get(name)) |existing| return existing;
    const module = create(b, .{
        .product = product,
        .root_source_file = leaf.rootSource(),
        .target = target,
        .optimize = optimize,
    });
    // bzip2.zig binds the vendored libbzip2 headers through @cImport.
    if (leaf == .interop_bzip2) module.addIncludePath(b.path("third_party/bzip2"));
    consumer.addImport(name, module);
    return module;
}

/// The RISC-V proof artifact codec (`src/products/riscv/artifact`).
pub fn addRiscVArtifactImport(
    b: *std.Build,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) *std.Build.Module {
    if (consumer.import_table.get("interop_riscv_artifact")) |existing| return existing;
    const artifact = create(b, .{
        .product = product,
        .root_source_file = "src/products/riscv/artifact/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    artifact.addImport(
        "atomic_file",
        addSupportIoImport(b, product, target, optimize, consumer, .atomic_file),
    );
    consumer.addImport("interop_riscv_artifact", artifact);
    return artifact;
}

/// The Native example proof artifact codec (`src/products/native/artifact`).
/// Requires `stwo_proof_wire` and `stwo_native_examples` on the consumer.
pub fn addNativeArtifactImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) ?*std.Build.Module {
    if (consumer.import_table.get("stwo_native_artifact")) |existing| return existing;
    const proof_wire = consumer.import_table.get("stwo_proof_wire") orelse return null;
    const examples = consumer.import_table.get("stwo_native_examples") orelse return null;
    const artifact = create(b, .{
        .product = product,
        .root_source_file = "src/products/native/artifact/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    artifact.addImport("stwo_core", protocol.core);
    artifact.addImport("stwo_proof_wire", proof_wire);
    artifact.addImport("stwo_native_examples", examples);
    artifact.addImport(
        "atomic_file",
        addSupportIoImport(b, product, target, optimize, consumer, .atomic_file),
    );
    if (consumer.import_table.get("interop_postcard")) |postcard|
        artifact.addImport("interop_postcard", postcard);
    consumer.addImport("stwo_native_artifact", artifact);
    return artifact;
}

/// The proof postcard codec (`src/waist/recursion_wire/postcard/mod.zig`).
pub fn addPostcardImport(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    consumer: *std.Build.Module,
) ?*std.Build.Module {
    if (consumer.import_table.get("interop_postcard")) |existing| return existing;
    const proof_wire = consumer.import_table.get("stwo_proof_wire") orelse return null;
    const postcard = create(b, .{
        .product = product,
        .root_source_file = "src/waist/recursion_wire/postcard/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    postcard.addImport("stwo_core", protocol.core);
    postcard.addImport("stwo_proof_wire", proof_wire);
    consumer.addImport("interop_postcard", postcard);
    return postcard;
}

pub const FacadeSupport = struct {
    atomic_file: bool = false,
    output_transaction: bool = false,
    bzip2: bool = false,
    postcard: bool = false,
    native_artifact: bool = false,
    riscv_artifact: bool = false,
    std_shims: bool = false,
    tracing: bool = false,

    /// Everything the `stwo` root's deprecated `interop`, `std_shims` and
    /// `tracing` namespaces forward to.
    pub const root: FacadeSupport = .{
        .atomic_file = true,
        .output_transaction = true,
        .postcard = true,
        .native_artifact = true,
        .riscv_artifact = true,
        .std_shims = true,
        .tracing = true,
    };
};

/// Wires the named support modules a product facade forwards. These were
/// relative files under the old `src/` root; each is now its own module.
pub fn addFacadeSupportImports(
    b: *std.Build,
    protocol: ProtocolModules,
    product: Product,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    facade: *std.Build.Module,
    support: FacadeSupport,
) void {
    if (support.atomic_file)
        _ = addSupportIoImport(b, product, target, optimize, facade, .atomic_file);
    if (support.output_transaction)
        _ = addSupportIoImport(b, product, target, optimize, facade, .output_transaction);
    if (support.bzip2)
        _ = addSupportIoImport(b, product, target, optimize, facade, .interop_bzip2);
    if (support.postcard)
        _ = addPostcardImport(b, protocol, product, target, optimize, facade);
    if (support.native_artifact)
        _ = addNativeArtifactImport(b, protocol, product, target, optimize, facade);
    if (support.riscv_artifact)
        _ = addRiscVArtifactImport(b, product, target, optimize, facade);
    if (support.std_shims) std_shims: {
        if (facade.import_table.get("stwo_std_shims") != null) break :std_shims;
        const proof_wire = facade.import_table.get("stwo_proof_wire") orelse break :std_shims;
        const examples = facade.import_table.get("stwo_native_examples") orelse break :std_shims;
        const shims = create(b, .{
            .product = product,
            .root_source_file = "src/support/shims/mod.zig",
            .target = target,
            .optimize = optimize,
        });
        shims.addImport("stwo_core", protocol.core);
        shims.addImport("stwo_proof_wire", proof_wire);
        shims.addImport("stwo_native_examples", examples);
        facade.addImport("stwo_std_shims", shims);
    }
    if (support.tracing and facade.import_table.get("stwo_tracing") == null) {
        facade.addImport("stwo_tracing", create(b, .{
            .product = product,
            .root_source_file = "src/support/tracing/mod.zig",
            .target = target,
            .optimize = optimize,
        }));
    }
}
