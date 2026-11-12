//! Consumer-owned artifact and support leaves; retain one instance per consumer.
const std = @import("std");
const create = @import("module_construction.zig").create;
const Product = @import("product_spec.zig").Product;
const ProtocolModules = @import("protocol_modules.zig").ProtocolModules;

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
