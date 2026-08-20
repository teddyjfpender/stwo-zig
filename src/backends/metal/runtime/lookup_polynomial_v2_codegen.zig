//! Metal source generation for authenticated variable-batch LogUp programs.
//!
//! V2 is deliberately separate from the uniform V1 generator. Kernel identity
//! binds the V2 program seal and this generator version, so an AOT cache cannot
//! satisfy a V2 request with a coincidentally similar V1 partition.

const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const v1_codegen = @import("lookup_polynomial_codegen.zig");

pub const codegen_version: u16 = 1;
pub const identity_domain = "stwo/metal/lookup-polynomial-v2-codegen/v1\x00";
pub const Identity = [32]u8;

pub const Entry = struct {
    authority: prover_component.LookupPolynomialAuthorityV2,
    program: prover_component.OwnedLookupPolynomialProgramV2,
};

pub fn codegenIdentity(
    program: *const prover_component.OwnedLookupPolynomialProgramV2,
) !Identity {
    try program.validate();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(identity_domain);
    hashInt(&hasher, u16, codegen_version);
    hasher.update(&program.layout.component_identity);
    hasher.update(&program.layout.partition_identity);
    hasher.update(&program.layout.layout_identity);
    hasher.update(&program.program_identity);
    return hasher.finalResult();
}

pub fn kernelName(
    allocator: std.mem.Allocator,
    program: *const prover_component.OwnedLookupPolynomialProgramV2,
) ![]u8 {
    const digest = try codegenIdentity(program);
    const encoded = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.allocPrint(
        allocator,
        "stwo_zig_lookup_poly_v2_{s}",
        .{encoded},
    );
}

pub fn generateLibrary(allocator: std.mem.Allocator, entries: []const Entry) ![]u8 {
    if (entries.len == 0) return error.InvalidLookupPolynomialProgram;
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    const writer = source.writer(allocator);
    try writer.writeAll(v1_codegen.preamble);
    for (entries) |entry| {
        try entry.program.validateAgainst(&entry.authority);
        const name = try kernelName(allocator, &entry.program);
        defer allocator.free(name);
        try emitKernel(allocator, writer, name, &entry.program);
    }
    return source.toOwnedSlice(allocator);
}

pub fn emitKernel(
    allocator: std.mem.Allocator,
    writer: anytype,
    name: []const u8,
    program: *const prover_component.OwnedLookupPolynomialProgramV2,
) !void {
    try program.validate();
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
        \\    constant uint2 &denominator_inverses [[buffer(7)]],
        \\    uint row [[thread_position_in_grid]]) {{
        \\    if (row >= row_count) return;
        \\    uint previous_row = riscv_previous_circle_row(row, row_count);
        \\
    , .{name});

    for (program.nodes, 0..) |node, index| {
        if (!reachable[index]) continue;
        switch (node.op) {
            .constant => try writer.print("    uint n{} = {}u;\n", .{ index, node.value }),
            .column => try writer.print(
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

    var parameter: usize = 0;
    for (program.entries, 0..) |entry, entry_index| {
        try writer.print(
            "    RiscvQm31 d{} = {{ 0u, 0u, 0u, 0u }};\n",
            .{entry_index},
        );
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
    for (program.batches, 0..) |batch, batch_index| {
        const first: usize = @intCast(batch.first_entry);
        const first_entry = program.entries[first];
        try writer.print(
            "    RiscvQm31 s{} = riscv_load_secure_column(interaction_columns, {}u, row_count, row);\n" ++
                "    RiscvQm31 p{} = riscv_load_secure_column(interaction_columns, {}u, row_count, previous_row);\n" ++
                "    RiscvQm31 delta{} = riscv_qm_add(riscv_qm_sub(s{}, p{}), riscv_qm_mul_base(riscv_load_qm31(parameters, {}u), selector[row]));\n",
            .{ batch_index, batch_index * 4, batch_index, batch_index * 4, batch_index, batch_index, batch_index, (parameter + batch_index) * 4 },
        );
        switch (batch.entry_count) {
            1 => try writer.print(
                "    RiscvQm31 c{} = riscv_qm_sub(riscv_qm_mul(delta{}, d{}), RiscvQm31{{ n{}, 0u, 0u, 0u }});\n",
                .{ batch_index, batch_index, first, first_entry.numerator },
            ),
            2 => {
                const second = first + 1;
                const second_entry = program.entries[second];
                try writer.print(
                    "    RiscvQm31 c{} = riscv_qm_sub(riscv_qm_sub(riscv_qm_mul(riscv_qm_mul(delta{}, d{}), d{}), riscv_qm_mul_base(d{}, n{})), riscv_qm_mul_base(d{}, n{}));\n",
                    .{ batch_index, batch_index, first, second, second, first_entry.numerator, first, second_entry.numerator },
                );
            },
            else => return error.InvalidLookupPolynomialProgram,
        }
        try writer.print(
            "    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, {}u), c{}));\n",
            .{ (program.batchCount() - 1 - batch_index) * 4, batch_index },
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
    program: *const prover_component.OwnedLookupPolynomialProgramV2,
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

fn hashInt(
    hasher: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}
