//! Metal source generation for production-exported pairs-batched LogUp DAGs.

const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;

pub const codegen_version: u16 = 3;
pub const identity_domain = "stwo/metal/lookup-polynomial-codegen/v3\x00";

pub const Entry = struct {
    program_id: u64,
    program: prover_component.OwnedLookupPolynomialProgram,
};

pub fn kernelName(
    allocator: std.mem.Allocator,
    program: prover_component.OwnedLookupPolynomialProgram,
) ![]u8 {
    const digest = programDigest(program);
    const encoded = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.allocPrint(
        allocator,
        "stwo_zig_lookup_poly_{s}",
        .{encoded},
    );
}

pub fn programDigest(program: prover_component.OwnedLookupPolynomialProgram) [16]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(identity_domain);
    hashInt(&hasher, u16, codegen_version);
    hashU64(&hasher, program.column_count);
    hashU64(&hasher, program.batch_size);
    hashU64(&hasher, program.nodes.len);
    for (program.nodes) |node| {
        hasher.update(&.{@intFromEnum(node.op)});
        hashU32(&hasher, node.lhs);
        hashU32(&hasher, node.rhs);
        hashU32(&hasher, node.value);
    }
    hashU64(&hasher, program.entries.len);
    for (program.entries) |entry| {
        hashU32(&hasher, entry.numerator);
        hasher.update(&.{entry.arity});
        for (entry.values[0..entry.arity]) |value| hashU32(&hasher, value);
    }
    return hasher.finalResult()[0..16].*;
}

pub fn generateLibrary(allocator: std.mem.Allocator, entries: []const Entry) ![]u8 {
    if (entries.len == 0) return error.InvalidLookupPolynomialProgram;
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
    program: prover_component.OwnedLookupPolynomialProgram,
) !void {
    const reachable = try reachableNodes(allocator, program);
    defer allocator.free(reachable);
    try writer.print(
        \\kernel void {s}(
        \\    device const uint *main_columns [[buffer(0)]],
        \\    device const uint *selector [[buffer(1)]],
        \\    device const uint *interaction_columns [[buffer(2)]],
        \\    device const uint *parameters [[buffer(3)]],
        \\    device const uint *powers [[buffer(4)]],
        \\    device uint *output [[buffer(5)]],
        \\    constant uint &row_count [[buffer(6)]],
        \\    constant uint *denominator_inverses [[buffer(7)]],
        \\    constant uint &denominator_count [[buffer(8)]],
        \\    uint row [[thread_position_in_grid]]) {{
        \\    if (row >= row_count) return;
        \\    uint previous_row = riscv_previous_circle_row(row, row_count, denominator_count);
        \\
    , .{name});

    for (program.nodes, 0..) |node, index| {
        if (!reachable[index]) continue;
        switch (node.op) {
            .constant => try writer.print("    uint n{} = {}u;\n", .{ index, node.value }),
            .column => try writer.print(
                "    uint n{} = main_columns[riscv_column_offset({}u, row_count, row)];\n",
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

    var parameter: usize = 0;
    for (program.entries, 0..) |entry, entry_index| {
        try writer.writeAll("    RiscvQm31 d");
        try writer.print("{} = {{ 0u, 0u, 0u, 0u }};\n", .{entry_index});
        for (entry.values[0..entry.arity], 0..) |root, value_index| {
            try writer.print(
                "    d{} = riscv_qm_add(d{}, riscv_qm_mul_base(riscv_load_qm31(parameters, {}u), n{}));\n",
                .{ entry_index, entry_index, (parameter + 1 + value_index) * 4, root },
            );
        }
        try writer.print(
            "    d{} = riscv_qm_sub(d{}, riscv_load_qm31(parameters, {}u));\n",
            .{ entry_index, entry_index, parameter * 4 },
        );
        parameter += 1 + entry.arity;
    }

    try writer.writeAll("    RiscvQm31 folded = { 0u, 0u, 0u, 0u };\n");
    for (0..program.batchCount()) |batch| {
        const first = batch * program.batch_size;
        const has_second = first + 1 < program.entries.len and program.batch_size == 2;
        const first_entry = program.entries[first];
        try writer.print(
            "    RiscvQm31 s{} = riscv_load_secure_column(interaction_columns, {}u, row_count, row);\n" ++
                "    RiscvQm31 p{} = riscv_load_secure_column(interaction_columns, {}u, row_count, previous_row);\n" ++
                "    RiscvQm31 delta{} = riscv_qm_add(riscv_qm_sub(s{}, p{}), riscv_qm_mul_base(riscv_load_qm31(parameters, {}u), selector[row]));\n",
            .{ batch, batch * 4, batch, batch * 4, batch, batch, batch, (parameter + batch) * 4 },
        );
        if (has_second) {
            const second_entry = program.entries[first + 1];
            try writer.print(
                "    RiscvQm31 c{} = riscv_qm_sub(riscv_qm_sub(riscv_qm_mul(riscv_qm_mul(delta{}, d{}), d{}), riscv_qm_mul_base(d{}, n{})), riscv_qm_mul_base(d{}, n{}));\n",
                .{ batch, batch, first, first + 1, first + 1, first_entry.numerator, first, second_entry.numerator },
            );
        } else {
            try writer.print(
                "    RiscvQm31 c{} = riscv_qm_sub(riscv_qm_mul(delta{}, d{}), RiscvQm31{{ n{}, 0u, 0u, 0u }});\n",
                .{ batch, batch, first, first_entry.numerator },
            );
        }
        try writer.print(
            "    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, {}u), c{}));\n",
            .{ (program.batchCount() - 1 - batch) * 4, batch },
        );
    }
    try writer.writeAll(
        \\    uint denominator_index = row / (row_count / denominator_count);
        \\    RiscvQm31 result = riscv_qm_mul_base(folded, denominator_inverses[denominator_index]);
        \\    output[riscv_column_offset(0u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(0u, row_count, row)], result.a);
        \\    output[riscv_column_offset(1u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(1u, row_count, row)], result.b);
        \\    output[riscv_column_offset(2u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(2u, row_count, row)], result.c);
        \\    output[riscv_column_offset(3u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(3u, row_count, row)], result.d);
        \\}
        \\
    );
}

fn reachableNodes(
    allocator: std.mem.Allocator,
    program: prover_component.OwnedLookupPolynomialProgram,
) ![]bool {
    const reachable = try allocator.alloc(bool, program.nodes.len);
    errdefer allocator.free(reachable);
    @memset(reachable, false);
    for (program.entries) |entry| {
        reachable[entry.numerator] = true;
        for (entry.values[0..entry.arity]) |value| reachable[value] = true;
    }
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
    \\inline uint riscv_m31_add(uint a, uint b) { uint s = a + b; return s >= RISCV_M31_P ? s - RISCV_M31_P : s; }
    \\inline uint riscv_m31_sub(uint a, uint b) { return a >= b ? a - b : a + RISCV_M31_P - b; }
    \\inline uint riscv_m31_mul(uint a, uint b) { ulong p = ulong(a) * b; uint f = uint((p & RISCV_M31_P) + (p >> 31)); return f >= RISCV_M31_P ? f - RISCV_M31_P : f; }
    \\inline uint riscv_m31_neg(uint a) { return a == 0u ? 0u : RISCV_M31_P - a; }
    \\inline ulong riscv_column_offset(uint column, uint rows, uint row) { return ulong(column) * ulong(rows) + ulong(row); }
    \\inline RiscvQm31 riscv_qm_add(RiscvQm31 l, RiscvQm31 r) { return { riscv_m31_add(l.a,r.a), riscv_m31_add(l.b,r.b), riscv_m31_add(l.c,r.c), riscv_m31_add(l.d,r.d) }; }
    \\inline RiscvQm31 riscv_qm_sub(RiscvQm31 l, RiscvQm31 r) { return { riscv_m31_sub(l.a,r.a), riscv_m31_sub(l.b,r.b), riscv_m31_sub(l.c,r.c), riscv_m31_sub(l.d,r.d) }; }
    \\inline RiscvQm31 riscv_qm_mul_base(RiscvQm31 v, uint s) { return { riscv_m31_mul(v.a,s), riscv_m31_mul(v.b,s), riscv_m31_mul(v.c,s), riscv_m31_mul(v.d,s) }; }
    \\inline RiscvQm31 riscv_qm_mul(RiscvQm31 l, RiscvQm31 r) {
    \\    uint x0=riscv_m31_sub(riscv_m31_mul(l.a,r.a),riscv_m31_mul(l.b,r.b)), x1=riscv_m31_add(riscv_m31_mul(l.a,r.b),riscv_m31_mul(l.b,r.a));
    \\    uint y0=riscv_m31_sub(riscv_m31_mul(l.c,r.c),riscv_m31_mul(l.d,r.d)), y1=riscv_m31_add(riscv_m31_mul(l.c,r.d),riscv_m31_mul(l.d,r.c));
    \\    uint c0=riscv_m31_sub(riscv_m31_mul(l.a,r.c),riscv_m31_mul(l.b,r.d)), c1=riscv_m31_add(riscv_m31_mul(l.a,r.d),riscv_m31_mul(l.b,r.c));
    \\    uint c2=riscv_m31_sub(riscv_m31_mul(l.c,r.a),riscv_m31_mul(l.d,r.b)), c3=riscv_m31_add(riscv_m31_mul(l.c,r.b),riscv_m31_mul(l.d,r.a));
    \\    return { riscv_m31_add(x0,riscv_m31_sub(riscv_m31_add(y0,y0),y1)), riscv_m31_add(x1,riscv_m31_add(y0,riscv_m31_add(y1,y1))), riscv_m31_add(c0,c2), riscv_m31_add(c1,c3) };
    \\}
    \\inline RiscvQm31 riscv_load_qm31(device const uint *values, uint offset) { return { values[offset], values[offset+1u], values[offset+2u], values[offset+3u] }; }
    \\inline RiscvQm31 riscv_load_secure_column(device const uint *columns, uint first, uint rows, uint row) { return { columns[riscv_column_offset(first+0u,rows,row)], columns[riscv_column_offset(first+1u,rows,row)], columns[riscv_column_offset(first+2u,rows,row)], columns[riscv_column_offset(first+3u,rows,row)] }; }
    \\inline uint riscv_bit_reverse(uint value, uint bits) { return bits == 0u ? value : reverse_bits(value) >> (32u-bits); }
    \\inline uint riscv_previous_circle_row(uint row, uint rows, uint denominator_count) {
    \\    uint log_rows = ctz(rows), natural = riscv_bit_reverse(row, log_rows), half_rows = rows >> 1u, step = denominator_count >> 1u;
    \\    natural = natural < half_rows ? (natural + half_rows - step) % half_rows : ((natural - half_rows + step) % half_rows) + half_rows;
    \\    return riscv_bit_reverse(natural, log_rows);
    \\}
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

fn hashInt(
    hasher: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}

test "lookup polynomial codegen emits paired transition arithmetic" {
    const nodes = try std.testing.allocator.dupe(prover_component.BasePolynomialNode, &.{
        .{ .op = .column, .value = 0 },
        .{ .op = .constant, .value = 1 },
    });
    const entries = try std.testing.allocator.dupe(prover_component.LookupPolynomialEntry, &.{
        .{ .numerator = 1, .arity = 1, .values = blk: {
            var values: [32]u32 = undefined;
            values[0] = 0;
            break :blk values;
        } },
        .{ .numerator = 0, .arity = 1, .values = blk: {
            var values: [32]u32 = undefined;
            values[0] = 1;
            break :blk values;
        } },
    });
    var program = prover_component.OwnedLookupPolynomialProgram{
        .allocator = std.testing.allocator,
        .nodes = nodes,
        .entries = entries,
        .column_count = 1,
        .batch_size = 2,
    };
    defer program.deinit();
    const source = try generateLibrary(std.testing.allocator, &.{.{
        .program_id = 4,
        .program = program,
    }});
    defer std.testing.allocator.free(source);
    try std.testing.expect(std.mem.indexOf(u8, source, "riscv_previous_circle_row") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "step = denominator_count >> 1u") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "row_count / denominator_count") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "riscv_qm_mul(riscv_qm_mul(delta0, d0), d1)") != null);
}

test "lookup polynomial codegen widens main and secure-column offsets" {
    const nodes = try std.testing.allocator.dupe(prover_component.BasePolynomialNode, &.{
        .{ .op = .column, .value = 444 },
        .{ .op = .constant, .value = 1 },
    });
    const entries = try std.testing.allocator.dupe(prover_component.LookupPolynomialEntry, &.{
        .{ .numerator = 1, .arity = 1, .values = blk: {
            var values: [32]u32 = undefined;
            values[0] = 0;
            break :blk values;
        } },
    });
    var program = prover_component.OwnedLookupPolynomialProgram{
        .allocator = std.testing.allocator,
        .nodes = nodes,
        .entries = entries,
        .column_count = 445,
        .batch_size = 1,
    };
    defer program.deinit();
    const source = try generateLibrary(std.testing.allocator, &.{.{
        .program_id = 0x400000001,
        .program = program,
    }});
    defer std.testing.allocator.free(source);

    try std.testing.expect(std.mem.indexOf(
        u8,
        source,
        "main_columns[riscv_column_offset(444u, row_count, row)]",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        source,
        "columns[riscv_column_offset(first+3u,rows,row)]",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "444u * row_count + row") == null);
    try std.testing.expect(std.mem.indexOf(u8, source, "(first+3u)*rows+row") == null);
}
