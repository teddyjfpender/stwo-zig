//! One source-authenticated Metal library for all production RISC-V AIR DAGs.

const std = @import("std");
const base_codegen = @import("base_polynomial_codegen.zig");
const lookup_codegen = @import("lookup_polynomial_codegen.zig");
const lookup_v2_codegen = @import("lookup_polynomial_v2_codegen.zig");

pub fn generateLibrary(
    allocator: std.mem.Allocator,
    base_entries: []const base_codegen.Entry,
    lookup_entries: []const lookup_codegen.Entry,
    lookup_v2_entries: []const lookup_v2_codegen.Entry,
) ![]u8 {
    if (base_entries.len == 0 or lookup_entries.len == 0 or
        lookup_v2_entries.len == 0)
        return error.InvalidRiscvPolynomialLibrary;
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    const writer = source.writer(allocator);
    try writer.writeAll(
        "// Generated from the production RISC-V typed AIR builders.\n" ++
            "// Generator: src/backends/metal/runtime/riscv_polynomial_aot_codegen.zig\n" ++
            "// Regenerate: STWO_ZIG_REGENERATE_RISCV_POLYNOMIAL_AOT=1 zig build test-riscv-metal\n" ++
            "// Do not hand-edit.\n",
    );
    try writer.writeAll(lookup_codegen.preamble);
    for (base_entries) |entry| {
        try entry.program.validate();
        const name = try base_codegen.kernelName(allocator, entry.program);
        defer allocator.free(name);
        try base_codegen.emitKernel(allocator, writer, name, entry.program);
    }
    for (lookup_entries) |entry| {
        try entry.program.validate();
        const name = try lookup_codegen.kernelName(allocator, entry.program);
        defer allocator.free(name);
        try lookup_codegen.emitKernel(allocator, writer, name, entry.program);
    }
    for (lookup_v2_entries) |entry| {
        try entry.program.validateAgainst(&entry.authority);
        const name = try lookup_v2_codegen.kernelName(allocator, &entry.program);
        defer allocator.free(name);
        try lookup_v2_codegen.emitKernel(allocator, writer, name, &entry.program);
    }
    return source.toOwnedSlice(allocator);
}
