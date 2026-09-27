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
            "// Regenerate: python3 scripts/riscv_native_polynomial_aot.py --output PATH --compile-metal --update-source\n" ++
            "// Do not hand-edit.\n",
    );
    try writer.writeAll(lookup_codegen.preamble);
    // Several independently placed/identified components can export the same
    // DAG (notably local-zero recipes without register requests). Validate each
    // entry, but publish its content-addressed executable only once.
    var emitted_base = std.AutoHashMap([16]u8, void).init(allocator);
    defer emitted_base.deinit();
    for (base_entries) |entry| {
        try entry.program.validate();
        if ((try emitted_base.getOrPut(base_codegen.programDigest(entry.program))).found_existing) continue;
        const name = try base_codegen.kernelName(allocator, entry.program);
        defer allocator.free(name);
        try base_codegen.emitKernel(allocator, writer, name, entry.program);
    }
    var emitted_lookup = std.AutoHashMap([16]u8, void).init(allocator);
    defer emitted_lookup.deinit();
    for (lookup_entries) |entry| {
        try entry.program.validate();
        if ((try emitted_lookup.getOrPut(lookup_codegen.programDigest(entry.program))).found_existing) continue;
        const name = try lookup_codegen.kernelName(allocator, entry.program);
        defer allocator.free(name);
        try lookup_codegen.emitKernel(allocator, writer, name, entry.program);
    }
    var emitted_lookup_v2 = std.AutoHashMap([32]u8, void).init(allocator);
    defer emitted_lookup_v2.deinit();
    for (lookup_v2_entries) |entry| {
        try entry.program.validateAgainst(&entry.authority);
        if ((try emitted_lookup_v2.getOrPut(try lookup_v2_codegen.codegenIdentity(&entry.program))).found_existing) continue;
        const name = try lookup_v2_codegen.kernelName(allocator, &entry.program);
        defer allocator.free(name);
        try lookup_v2_codegen.emitKernel(allocator, writer, name, &entry.program);
    }
    return source.toOwnedSlice(allocator);
}
