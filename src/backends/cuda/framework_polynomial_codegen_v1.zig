//! Offline CUDA framework kernel source from the original authenticated DAG.
//! Physical column placement stays in admitted invocation metadata; executable
//! identity binds the exact common emitter and CUDA field helper source.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const types = engine.air.component_prover;
const emitter = engine.air.framework_polynomial_emitter_v1;
pub const Program = types.OwnedFrameworkPolynomialProgramV1;
pub const Entry = struct { program: *const Program, tree_column_counts: []const usize };
pub const preamble = @embedFile("native/framework_polynomial_v1.cuh");
pub const MAX_ENTRIES: usize = 64;
pub const ARGUMENT_COUNT: u32 = 11;
pub fn validate(entry: Entry) !void {
    try entry.program.validate(entry.tree_column_counts);
    for (entry.program.inputs) |input| switch (input) {
        .trace_column => |column| if (column.tree_index > 2) return error.UnsupportedFrameworkPolynomialTree,
        .profile_parameter => {},
    };
    for (entry.program.interaction_columns) |column| if (column.tree_index > 2) return error.UnsupportedFrameworkPolynomialTree;
}
pub fn emitKernel(a: std.mem.Allocator, writer: anytype, name: []const u8, entry: Entry) !void {
    try validate(entry);
    try writer.print(
        \\extern "C" __global__ void {s}(
        \\ const uint *tree0, const uint *tree1, const uint *tree2,
        \\ const ulong *column_offsets, const uint *profile_parameters,
        \\ const uint *relation_parameters, const uint *powers, uint *output,
        \\ uint row_count, const uint *denominator_inverses, uint denominator_count) {{
        \\ uint row=blockIdx.x*blockDim.x+threadIdx.x;
        \\ if(row>=row_count) return;
        \\ uint previous_row=riscv_previous_circle_row(row,row_count,denominator_count);
        \\ RiscvQm31 folded={{0u,0u,0u,0u}};
        \\
    , .{name});
    try emitter.emitBody(a, writer, entry.program);
}
pub fn identity(a: std.mem.Allocator, entry: Entry) ![32]u8 {
    var body: std.Io.Writer.Allocating = .init(a);
    defer body.deinit();
    try emitKernel(a, &body.writer, "stwo_framework_canonical", entry);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/cuda/framework-polynomial/v1\x00");
    hash.update(@embedFile("framework_polynomial_codegen_v1.zig"));
    hash.update(&emitter.fingerprint());
    hash.update(preamble);
    hash.update(@embedFile("native/oods/field.cuh"));
    hash.update(body.written());
    return hash.finalResult();
}
pub fn cacheKey(id: [32]u8) u64 {
    const key = std.mem.readInt(u64, id[0..8], .little);
    return if (key == 0) 1 else key;
}
pub fn kernelName(a: std.mem.Allocator, entry: Entry) ![:0]u8 {
    return std.fmt.allocPrintSentinel(a, "stwo_cuda_framework_v1_{s}", .{std.fmt.bytesToHex(try identity(a, entry), .lower)}, 0);
}
pub fn generateLibrary(a: std.mem.Allocator, entries: []const Entry) ![]u8 {
    if (entries.len == 0 or entries.len > MAX_ENTRIES) return error.InvalidFrameworkKernelCatalog;
    var output: std.Io.Writer.Allocating = .init(a);
    defer output.deinit();
    try output.writer.writeAll(preamble);
    var seen: [MAX_ENTRIES][32]u8 = undefined;
    var count: usize = 0;
    for (entries) |entry| {
        const id = try identity(a, entry);
        var duplicate = false;
        for (seen[0..count]) |prior| if (std.mem.eql(u8, &prior, &id)) {
            duplicate = true;
            break;
        };
        if (duplicate) continue;
        seen[count] = id;
        count += 1;
        const name = try kernelName(a, entry);
        defer a.free(name);
        try emitKernel(a, &output.writer, name, entry);
    }
    return a.dupe(u8, output.written());
}
