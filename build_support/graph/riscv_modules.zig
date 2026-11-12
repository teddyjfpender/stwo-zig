//! Canonical RISC-V family construction against the caller-selected protocol.
const std = @import("std");
const create = @import("module_construction.zig").create;
const createProofWire = @import("module_construction.zig").createProofWire;
const Product = @import("product_spec.zig").Product;
const ProtocolModules = @import("protocol_modules.zig").ProtocolModules;

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
    addFamily(b, frontend, protocol, product, target, optimize, postcard);
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

// Exact reviewed family order; dependencies are read from each owned contract,
// never inferred from a name prefix or independently hand-wired here.
const family = [_]struct { name: []const u8, path: []const u8 }{
    .{ .name = "stwo_riscv_isa", .path = "isa" },
    .{ .name = "stwo_riscv_air_lang", .path = "air_lang" },
    .{ .name = "stwo_riscv_memory", .path = "memory" },
    .{ .name = "stwo_riscv_recursion_air", .path = "recursion_air" },
    .{ .name = "stwo_riscv_precompiles", .path = "precompiles" },
    .{ .name = "stwo_riscv_rv32", .path = "rv32" },
    .{ .name = "stwo_riscv_rv64", .path = "rv64" },
    .{ .name = "stwo_riscv_recursion", .path = "recursion" },
    .{ .name = "stwo_riscv_testing", .path = "testing" },
};

fn addFamily(b: *std.Build, frontend: *std.Build.Module, protocol: ProtocolModules, product: Product, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, postcard: *std.Build.Module) void {
    var nodes: [family.len]*std.Build.Module = undefined;
    for (family, 0..) |entry, index| {
        const source = b.fmt("src/frontends/riscv/{s}/mod.zig", .{entry.path});
        const node = create(b, .{ .product = product, .root_source_file = source, .target = target, .optimize = optimize });
        nodes[index] = node;
        const root = node.root_source_file.?.getPath(b);
        const path = std.fs.path.join(b.allocator, &.{ std.fs.path.dirname(root).?, "package.contract.json" }) catch @panic("out of memory");
        const bytes = std.fs.cwd().readFileAlloc(b.allocator, path, 1 << 20) catch @panic("cannot read owned RISC-V contract");
        const contract = std.json.parseFromSliceLeaky(std.json.Value, b.allocator, bytes, .{}) catch @panic("invalid owned RISC-V contract");
        const dependencies = contract.object.get("dependencies").?.object;
        for (dependencies.keys()) |name| {
            const dependency = if (std.mem.eql(u8, name, "stwo_core")) protocol.core else if (std.mem.eql(u8, name, "stwo_prover_api")) protocol.prover_api else if (std.mem.eql(u8, name, "stwo_prover_engine")) protocol.prover else blk: {
                for (family[0..index], nodes[0..index]) |provider, module| {
                    if (std.mem.eql(u8, name, provider.name)) break :blk module;
                }
                std.debug.panic("RISC-V {s} has unavailable/forward dependency {s}", .{ entry.name, name });
            };
            node.addImport(name, dependency);
        }
        for (contract.object.get("injected_modules").?.array.items) |injected| {
            if (!std.mem.eql(u8, injected.string, "interop_postcard"))
                std.debug.panic("unbound RISC-V injection {s}: {s}", .{ entry.name, injected.string });
            node.addImport(injected.string, postcard);
        }
        // This checks the actual constructed graph, not a source-name proxy.
        std.debug.assert(node.import_table.get("stwo_core").? == protocol.core);
        frontend.addImport(entry.name, node);
    }
}
