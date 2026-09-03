//! Deterministic candidate-only Metal source roster for the degree-five
//! Poseidon provider.  The frontend remains the sole polynomial authority;
//! this module asks its typed export for four direct partitions and one LogUp
//! program, then feeds those programs to the ordinary authenticated AOT
//! codegen.  It neither activates the candidate circuit nor source-JITs it.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const metal = @import("stwo_metal_backend");

pub const base_kernel_count: usize = 4;
pub const lookup_kernel_count: usize = 1;
pub const kernel_count: usize = base_kernel_count + lookup_kernel_count;
pub const regenerate_environment = "STWO_ZIG_REGENERATE_D5_PROVIDER_AOT";
pub const generated_path = ".zig-cache/riscv_degree5_provider.generated.metal";

pub fn generateSource(allocator: std.mem.Allocator) ![]u8 {
    const candidate_mod = frontend.air.typed_poseidon2_degree_bounded_candidate;
    const backend = frontend.air.typed_poseidon2_degree5_backend;
    const codegen = metal.riscv_polynomial_codegen;

    var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
    defer candidate.deinit();
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    const writer = source.writer(allocator);
    try writer.writeAll(
        "// Generated candidate degree-five provider kernels; do not hand-edit.\n",
    );
    for (0..backend.DIRECT_PARTITION_COUNT) |partition| {
        var program = try backend.exportDirectProgram(
            allocator,
            &candidate,
            backend.directPartitionRange(partition),
        );
        defer program.deinit();
        const name = try codegen.base.kernelName(allocator, program);
        defer allocator.free(name);
        try codegen.base.emitKernel(allocator, writer, name, program);
    }
    var lookup = try backend.exportLookupProgram(allocator, &candidate);
    defer lookup.deinit();
    const lookup_name = try codegen.lookup.kernelName(allocator, lookup);
    defer allocator.free(lookup_name);
    try codegen.lookup.emitKernel(
        allocator,
        writer,
        lookup_name,
        lookup,
    );
    return source.toOwnedSlice(allocator);
}

pub fn validateSource(source: []const u8) !void {
    if (std.mem.count(u8, source, "kernel void stwo_zig_base_poly_") !=
        base_kernel_count or
        std.mem.count(u8, source, "kernel void stwo_zig_lookup_poly_") !=
            lookup_kernel_count or
        std.mem.count(u8, source, "kernel void ") != kernel_count or
        std.mem.indexOf(u8, source, "u * row_count + row]") != null)
    {
        return error.InvalidStage101Degree5ProviderAotSource;
    }
}

pub fn validateEmbeddedInventory(source: []const u8) !void {
    try validateSource(source);
    const header_end = (std.mem.indexOfScalar(u8, source, '\n') orelse
        return error.InvalidStage101Degree5ProviderAotSource) + 1;
    if (!std.mem.endsWith(u8, metal.riscv_polynomial_codegen.source, source[header_end..]))
        return error.Stage101Degree5ProviderAotSourceMismatch;

    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        const prefix = "kernel void ";
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        const open = std.mem.indexOfScalarPos(u8, line, prefix.len, '(') orelse
            return error.InvalidStage101Degree5ProviderAotSource;
        const name = line[prefix.len..open];
        if (!metal.shaders.manifest.testing.manifestContains(name) or
            std.mem.count(u8, metal.riscv_polynomial_codegen.source, name) != 1 or
            std.mem.count(u8, metal.source_contract.runtime, name) != 1)
        {
            return error.Stage101Degree5ProviderAotInventoryMismatch;
        }
    }
}

test "Stage101 degree-five provider AOT roster is four direct plus one lookup" {
    const first = try generateSource(std.testing.allocator);
    defer std.testing.allocator.free(first);
    const second = try generateSource(std.testing.allocator);
    defer std.testing.allocator.free(second);
    try validateSource(first);
    try std.testing.expectEqualSlices(u8, first, second);
    try validateEmbeddedInventory(first);
    if (std.posix.getenv(regenerate_environment) != null) {
        try std.fs.cwd().writeFile(.{
            .sub_path = generated_path,
            .data = first,
        });
    }
}
