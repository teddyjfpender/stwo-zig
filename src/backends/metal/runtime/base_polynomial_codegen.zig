//! Metal source generation for backend-neutral base-field polynomial DAGs.

const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;

pub const codegen_version: u64 = 1;

pub const Entry = struct {
    program_id: u64,
    program: prover_component.OwnedBasePolynomialProgram,
};

pub fn kernelName(
    allocator: std.mem.Allocator,
    program: prover_component.OwnedBasePolynomialProgram,
) ![]u8 {
    const digest = programDigest(program);
    const encoded = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.allocPrint(
        allocator,
        "stwo_zig_base_poly_{s}",
        .{encoded},
    );
}

pub fn programDigest(program: prover_component.OwnedBasePolynomialProgram) [16]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hashU64(&hasher, program.column_count);
    hashU64(&hasher, program.nodes.len);
    for (program.nodes) |node| {
        hasher.update(&.{@intFromEnum(node.op)});
        hashU32(&hasher, node.lhs);
        hashU32(&hasher, node.rhs);
        hashU32(&hasher, node.value);
    }
    hashU64(&hasher, program.roots.len);
    for (program.roots) |root| hashU32(&hasher, root);
    return hasher.finalResult()[0..16].*;
}

pub fn generateLibrary(allocator: std.mem.Allocator, entries: []const Entry) ![]u8 {
    if (entries.len == 0) return error.InvalidBasePolynomialProgram;
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    const writer = source.writer(allocator);
    try writer.writeAll(preamble);
    for (entries) |entry| {
        try entry.program.validate();
        const name = try kernelName(allocator, entry.program);
        defer allocator.free(name);
        try emitKernel(allocator, writer, name, entry.program);
    }
    return source.toOwnedSlice(allocator);
}

pub fn emitKernel(
    allocator: std.mem.Allocator,
    writer: anytype,
    name: []const u8,
    program: prover_component.OwnedBasePolynomialProgram,
) !void {
    const reachable = try reachableNodes(allocator, program);
    defer allocator.free(reachable);
    const main_column_count = program.column_count - 1;
    try writer.print(
        \\kernel void {s}(
        \\    device const uint *main_columns [[buffer(0)]],
        \\    device const uint *selector [[buffer(1)]],
        \\    device const uint *powers [[buffer(2)]],
        \\    device uint *output [[buffer(3)]],
        \\    constant uint &row_count [[buffer(4)]],
        \\    constant uint2 &denominator_inverses [[buffer(5)]],
        \\    uint row [[thread_position_in_grid]]) {{
        \\    if (row >= row_count) return;
        \\
    , .{name});

    for (program.nodes, 0..) |node, index| {
        if (!reachable[index]) continue;
        switch (node.op) {
            .constant => try writer.print("    uint n{} = {}u;\n", .{ index, node.value }),
            .column => if (node.value == main_column_count)
                try writer.print("    uint n{} = selector[row];\n", .{index})
            else
                try writer.print(
                    "    uint n{} = main_columns[{}u * row_count + row];\n",
                    .{ index, node.value },
                ),
            .add => try writer.print(
                "    uint n{} = riscv_m31_add(n{}, n{});\n",
                .{ index, node.lhs, node.rhs },
            ),
            .sub => try writer.print(
                "    uint n{} = riscv_m31_sub(n{}, n{});\n",
                .{ index, node.lhs, node.rhs },
            ),
            .mul => try writer.print(
                "    uint n{} = riscv_m31_mul(n{}, n{});\n",
                .{ index, node.lhs, node.rhs },
            ),
            .neg => try writer.print("    uint n{} = riscv_m31_neg(n{});\n", .{ index, node.lhs }),
        }
    }

    try writer.writeAll("    RiscvQm31 folded = { 0u, 0u, 0u, 0u };\n");
    for (program.roots, 0..) |root, index| {
        const power_index = program.roots.len - 1 - index;
        try writer.print(
            "    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, {}u), n{}));\n",
            .{ power_index * 4, root },
        );
    }
    try writer.writeAll(
        \\    RiscvQm31 result = riscv_qm_mul_base(folded, denominator_inverses[row >= (row_count >> 1u)]);
        \\    output[row] = riscv_m31_add(output[row], result.a);
        \\    output[row_count + row] = riscv_m31_add(output[row_count + row], result.b);
        \\    output[2u * row_count + row] = riscv_m31_add(output[2u * row_count + row], result.c);
        \\    output[3u * row_count + row] = riscv_m31_add(output[3u * row_count + row], result.d);
        \\}
        \\
    );
}

fn reachableNodes(
    allocator: std.mem.Allocator,
    program: prover_component.OwnedBasePolynomialProgram,
) ![]bool {
    const reachable = try allocator.alloc(bool, program.nodes.len);
    errdefer allocator.free(reachable);
    @memset(reachable, false);
    for (program.roots) |root| reachable[root] = true;
    var cursor = program.nodes.len;
    while (cursor != 0) {
        cursor -= 1;
        if (!reachable[cursor]) continue;
        const node = program.nodes[cursor];
        switch (node.op) {
            .constant, .column => {},
            .add, .sub, .mul => {
                reachable[node.lhs] = true;
                reachable[node.rhs] = true;
            },
            .neg => reachable[node.lhs] = true,
        }
    }
    return reachable;
}

pub const preamble =
    \\#include <metal_stdlib>
    \\using namespace metal;
    \\constant uint RISCV_M31_P = 0x7fffffffu;
    \\struct RiscvQm31 { uint a; uint b; uint c; uint d; };
    \\inline uint riscv_m31_reduce(ulong v) { v = (v & RISCV_M31_P) + (v >> 31); v = (v & RISCV_M31_P) + (v >> 31); return v == RISCV_M31_P ? 0u : uint(v); }
    \\inline uint riscv_m31_add(uint a, uint b) { return riscv_m31_reduce(ulong(a) + b); }
    \\inline uint riscv_m31_sub(uint a, uint b) { return a >= b ? a - b : a + RISCV_M31_P - b; }
    \\inline uint riscv_m31_mul(uint a, uint b) { return riscv_m31_reduce(ulong(a) * b); }
    \\inline uint riscv_m31_neg(uint a) { return a == 0u ? 0u : RISCV_M31_P - a; }
    \\inline RiscvQm31 riscv_qm_add(RiscvQm31 l, RiscvQm31 r) { return { riscv_m31_add(l.a,r.a), riscv_m31_add(l.b,r.b), riscv_m31_add(l.c,r.c), riscv_m31_add(l.d,r.d) }; }
    \\inline RiscvQm31 riscv_qm_mul_base(RiscvQm31 v, uint s) { return { riscv_m31_mul(v.a,s), riscv_m31_mul(v.b,s), riscv_m31_mul(v.c,s), riscv_m31_mul(v.d,s) }; }
    \\inline RiscvQm31 riscv_load_qm31(device const uint *values, uint offset) { return { values[offset], values[offset+1u], values[offset+2u], values[offset+3u] }; }
    \\
;

fn hashU32(hasher: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, value, .little);
    hasher.update(&encoded);
}

fn hashU64(hasher: *std.crypto.hash.sha2.Sha256, value: usize) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .little);
    hasher.update(&encoded);
}

test "base polynomial codegen preserves root and selector order" {
    const nodes = try std.testing.allocator.dupe(prover_component.BasePolynomialNode, &.{
        .{ .op = .column, .value = 0 },
        .{ .op = .column, .value = 1 },
        .{ .op = .mul, .lhs = 0, .rhs = 1 },
        .{ .op = .constant, .value = 7 },
        .{ .op = .sub, .lhs = 2, .rhs = 3 },
    });
    const roots = try std.testing.allocator.dupe(u32, &.{ 4, 2 });
    var program = prover_component.OwnedBasePolynomialProgram{
        .allocator = std.testing.allocator,
        .nodes = nodes,
        .roots = roots,
        .column_count = 2,
    };
    defer program.deinit();
    const source = try generateLibrary(std.testing.allocator, &.{.{
        .program_id = 9,
        .program = program,
    }});
    defer std.testing.allocator.free(source);
    try std.testing.expect(std.mem.indexOf(u8, source, "selector[row]") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "riscv_load_qm31(powers, 4u), n4") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "riscv_load_qm31(powers, 0u), n2") != null);
}

test "base polynomial codegen omits nodes unreachable from constraint roots" {
    const nodes = try std.testing.allocator.dupe(prover_component.BasePolynomialNode, &.{
        .{ .op = .column, .value = 0 },
        .{ .op = .constant, .value = 123456789 },
    });
    const roots = try std.testing.allocator.dupe(u32, &.{0});
    var program = prover_component.OwnedBasePolynomialProgram{
        .allocator = std.testing.allocator,
        .nodes = nodes,
        .roots = roots,
        .column_count = 2,
    };
    defer program.deinit();
    const source = try generateLibrary(std.testing.allocator, &.{.{
        .program_id = 10,
        .program = program,
    }});
    defer std.testing.allocator.free(source);
    try std.testing.expect(std.mem.indexOf(u8, source, "uint n0 = main_columns") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "123456789") == null);
}
