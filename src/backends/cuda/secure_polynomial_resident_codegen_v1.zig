//! Exact source product for the resident secure DAG and bounded helper kernels.
//! Compilation/embedding is offline; this module never loads an image or JITs.
const std = @import("std");
pub const dag = @import("secure_polynomial_codegen_v1.zig");
/// Compatible offline exporter surface; helper metadata is exported separately.
pub const identity = dag.identity;
pub const kernelName = dag.kernelName;
pub const helpers = @embedFile("native/secure_polynomial_resident_v1.cuh");
pub const Helper = enum { range_inverse, scan_block, scan_carry, totals, mean, word_witness, range_witness };
pub const helper_count = @typeInfo(Helper).@"enum".fields.len;
pub fn name(helper: Helper) [:0]const u8 {
    return switch (helper) {
        .range_inverse => "stwo_cuda_range16_inverse_table_v1",
        .scan_block => "stwo_cuda_secure_scan_block_v1",
        .scan_carry => "stwo_cuda_secure_scan_carry_v1",
        .totals => "stwo_cuda_secure_totals_v1",
        .mean => "stwo_cuda_secure_mean_v1",
        .word_witness => "stwo_cuda_word_memory_witness_v4",
        .range_witness => "stwo_cuda_range16_witness_v4",
    };
}
pub fn helperIdentity(helper: Helper) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo/cuda/secure-resident-helpers/v1\x00");
    h.update(name(helper));
    h.update(dag.preamble);
    h.update(helpers);
    h.update(@embedFile("native/oods/field.cuh"));
    return h.finalResult();
}
pub fn cacheKey(id: [32]u8) u64 {
    const key = std.mem.readInt(u64, id[0..8], .little);
    return if (key == 0) 1 else key;
}
pub fn generateLibrary(a: std.mem.Allocator, programs: []const *const dag.ir.Program) ![]u8 {
    const source = try dag.generateLibrary(a, programs);
    defer a.free(source);
    return std.mem.concat(a, u8, &.{ source, "\n", helpers });
}

/// Offline source manifest entries only: binary length/SHA and SM are supplied
/// by the actual offline compiler/packager, never invented by source export.
pub const SourceEntry = struct {
    kernel: []const u8,
    executable_identity: [64]u8,
    cache_key: u64,
    abi_schema: u32,
    argument_count: u32,
};
pub fn helperEntries() [helper_count]SourceEntry {
    var entries: [helper_count]SourceEntry = undefined;
    inline for (std.meta.tags(Helper), 0..) |helper, index| {
        const id = helperIdentity(helper);
        entries[index] = .{ .kernel = name(helper), .executable_identity = std.fmt.bytesToHex(id, .lower), .cache_key = cacheKey(id), .abi_schema = @intFromEnum(helperSchema(helper)), .argument_count = helperArguments(helper) };
    }
    return entries;
}
pub fn programSchema(kind: dag.ir.Kind) @import("abi/schema.zig").KernelSchema {
    return if (dag.ir.isFraction(kind)) .secure_polynomial_fractions_v1 else .secure_polynomial_equations_v1;
}
pub fn helperSchema(helper: Helper) @import("abi/schema.zig").KernelSchema {
    return switch (helper) {
        .range_inverse => .secure_range_inverse_v1,
        .scan_block, .scan_carry => .secure_scan_v1,
        .totals, .mean => .secure_mean_v1,
        .word_witness => .secure_word_witness_v4,
        .range_witness => .secure_range_witness_v4,
    };
}
pub fn helperArguments(helper: Helper) u32 {
    return switch (helper) {
        .range_inverse => 2,
        .scan_block, .scan_carry => 5,
        .totals, .mean => 4,
        .word_witness => 5,
        .range_witness => 3,
    };
}
