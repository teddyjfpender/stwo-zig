//! Deterministic CUDA writer for authenticated Cairo witness bytecode.

const std = @import("std");
const model = @import("cairo_witness_model");
const schedule_mod = @import("schedule.zig");

const support_files = [_][]const u8{
    "fp256_storage.cuh",
    "ptx.cuh",
    "fp256_host_math.cuh",
    "fp256_carry_chain.cuh",
    "fp256_config.cuh",
    "fp256_dispatch_st.cuh",
    "ec_ops.cuh",
    "poseidon_witness_round_keys.cuh",
    "stwo_wit_deduce.cuh",
};

pub fn emit(
    allocator: std.mem.Allocator,
    output: *std.Io.Writer,
    program: model.Program,
    support_directory: std.fs.Dir,
) !void {
    var schedule = try schedule_mod.build(allocator, program);
    defer schedule.deinit();
    try emitPreamble(output);

    var kinds = [_]bool{false} ** 12;
    for (program.insts) |inst| {
        if (inst.op != .deduce_call) continue;
        const kind = std.meta.intToEnum(
            model.DeduceKind,
            inst.imm,
        ) catch return error.InvalidDeduce;
        kinds[@intFromEnum(kind)] = true;
    }
    var needs_fp256 = false;
    var needs_pedersen = false;
    for (kinds, 0..) |used, raw| {
        if (!used) continue;
        const kind: model.DeduceKind = @enumFromInt(raw);
        needs_fp256 = needs_fp256 or kind.needsFp256();
        needs_pedersen = needs_pedersen or kind.needsPedersenModule();
    }
    if (needs_fp256) {
        if (needs_pedersen)
            try output.writeAll("#define STWO_WIT_NEEDS_PEDERSEN 1\n");
        try emitFp256Support(allocator, output, support_directory);
    }
    if (kinds[@intFromEnum(model.DeduceKind.blake_g)])
        try emitBlakeG(output);
    if (kinds[@intFromEnum(model.DeduceKind.blake_round_sigma)])
        try emitBlakeSigma(output);
    try emitKernelPreamble(output, program.semantic_hash);
    try emitBody(output, program, schedule);
    try output.writeAll("}\n");
}

fn emitBody(
    output: *std.Io.Writer,
    program: model.Program,
    schedule: schedule_mod.Schedule,
) !void {
    var deduce_args: std.ArrayList(u32) = .empty;
    defer deduce_args.deinit(std.heap.smp_allocator);
    var deduce_sequence: usize = 0;
    for (program.insts, 0..) |inst, instruction| {
        switch (inst.op) {
            .col_write, .lookup_word, .sub_word => continue,
            .mult_push => {
                try output.print(
                    "    atomicAdd(&mult_counts[{}u][r{}], 1u);\n",
                    .{ inst.imm, inst.a },
                );
                try emitOutputs(
                    output,
                    schedule.after_instruction[instruction].items,
                );
                continue;
            },
            .deduce_arg => {
                try deduce_args.append(std.heap.smp_allocator, inst.a);
                try emitOutputs(
                    output,
                    schedule.after_instruction[instruction].items,
                );
                continue;
            },
            .deduce_call => {
                const kind = std.meta.intToEnum(
                    model.DeduceKind,
                    inst.imm,
                ) catch return error.InvalidDeduce;
                const shape = kind.shape();
                if (deduce_args.items.len != shape.args)
                    return error.InvalidDeduce;
                const sequence = deduce_sequence;
                deduce_sequence += 1;
                try output.print(
                    "    const unsigned dargs{}[{}] = {{ ",
                    .{ sequence, shape.args },
                );
                for (deduce_args.items, 0..) |register, index| {
                    if (index != 0) try output.writeAll(", ");
                    try output.print("r{}", .{register});
                }
                try output.print(
                    " }};\n    unsigned douts{}[{}];\n",
                    .{ sequence, shape.outputs },
                );
                try emitOutputs(
                    output,
                    schedule.after_deduce_arguments[instruction].items,
                );
                try emitDeduceCall(output, kind, sequence);
                const base: usize = inst.dst;
                for (0..shape.outputs) |offset| {
                    const register = base + offset;
                    try output.print(
                        "    unsigned r{} = douts{}[{}];\n",
                        .{ register, sequence, offset },
                    );
                    try emitOutputs(
                        output,
                        schedule.after_deduce_register[register].items,
                    );
                }
                deduce_args.clearRetainingCapacity();
                try emitOutputs(
                    output,
                    schedule.after_instruction[instruction].items,
                );
                continue;
            },
            else => {},
        }
        try output.print("    unsigned r{} = ", .{inst.dst});
        try emitExpression(output, inst);
        try output.writeAll(";\n");
        try emitOutputs(
            output,
            schedule.after_instruction[instruction].items,
        );
    }
}

fn emitExpression(output: *std.Io.Writer, inst: model.Inst) !void {
    switch (inst.op) {
        .input => try output.print("input_cols[{}u][row]", .{inst.a}),
        .constant => try output.print("{}u", .{inst.imm}),
        .m31_add => try binary(output, "stwo_m31_add", inst),
        .m31_sub => try binary(output, "stwo_m31_sub", inst),
        .m31_mul => try binary(output, "stwo_m31_mul", inst),
        .m31_neg => try output.print("stwo_m31_neg(r{})", .{inst.a}),
        .u16_add => try output.print(
            "((r{} + r{}) & 0xFFFFu)",
            .{ inst.a, inst.b },
        ),
        .u16_shl => try output.print(
            "((r{} << {}u) & 0xFFFFu)",
            .{ inst.a, inst.imm },
        ),
        .u16_shr => try output.print(
            "((r{} & 0xFFFFu) >> {}u)",
            .{ inst.a, inst.imm },
        ),
        .u16_and, .u32_and => try output.print(
            "(r{} & {}u)",
            .{ inst.a, inst.imm },
        ),
        .u32_add => try output.print("(r{} + r{})", .{ inst.a, inst.b }),
        .u32_sub => try output.print("(r{} - r{})", .{ inst.a, inst.b }),
        .u32_mul => try output.print("(r{} * r{})", .{ inst.a, inst.b }),
        .u32_shl => try output.print("(r{} << {}u)", .{ inst.a, inst.imm }),
        .u32_shr => try output.print("(r{} >> {}u)", .{ inst.a, inst.imm }),
        .u32_xor => try output.print("(r{} ^ r{})", .{ inst.a, inst.b }),
        .as_m31 => try output.print("(r{} % STWO_M31_P)", .{inst.a}),
        .trunc16 => try output.print("(r{} & 0xFFFFu)", .{inst.a}),
        .table_limb => switch (inst.b) {
            0 => try output.print(
                "(r{} < table_strides[0u] ? table_bases[0u][r{}] : 0u)",
                .{ inst.a, inst.a },
            ),
            1 => try output.print(
                "stwo_wit_deduce_limb(table_bases, table_strides, r{}, {}u)",
                .{ inst.a, inst.imm },
            ),
            else => return error.InvalidTable,
        },
        .m31_inverse => try output.print("stwo_m31_inverse(r{})", .{inst.a}),
        .m31_eq => try output.print(
            "(r{} == r{} ? 1u : 0u)",
            .{ inst.a, inst.b },
        ),
        else => return error.InvalidExpression,
    }
}

fn binary(
    output: *std.Io.Writer,
    name: []const u8,
    inst: model.Inst,
) !void {
    try output.print("{s}(r{}, r{})", .{ name, inst.a, inst.b });
}

fn emitDeduceCall(
    output: *std.Io.Writer,
    kind: model.DeduceKind,
    sequence: usize,
) !void {
    const name = switch (kind) {
        .blake_g => "stwo_wit_blake_g",
        .partial_ec_mul_w18 => "stwo_wit_deduce_partial_ec_mul_w18",
        .pedersen_points_table_w18 => "stwo_wit_deduce_pedersen_points_w18",
        .felt_add => "stwo_wit_deduce_felt_add",
        .felt_sub => "stwo_wit_deduce_felt_sub",
        .felt_mul => "stwo_wit_deduce_felt_mul",
        .felt_div => "stwo_wit_deduce_felt_div",
        .poseidon_round_keys => "stwo_wit_deduce_poseidon_round_keys",
        .cube_252 => "stwo_wit_deduce_cube_252",
        .poseidon_full_round_chain => "stwo_wit_deduce_poseidon_full_round_chain",
        .poseidon_3_partial_rounds_chain => "stwo_wit_deduce_poseidon_3_partial_rounds_chain",
        .blake_round_sigma => {
            try output.print(
                "    for (int i = 0; i < 16; ++i) {{ douts{}[i] = STWO_WIT_BLAKE_SIGMA[dargs{}[0]][i]; }}\n",
                .{ sequence, sequence },
            );
            return;
        },
    };
    try output.print(
        "    {s}(dargs{}, douts{});\n",
        .{ name, sequence, sequence },
    );
}

fn emitOutputs(
    output: *std.Io.Writer,
    outputs: []const schedule_mod.Output,
) !void {
    for (outputs) |value| switch (value.op) {
        .col_write => try output.print(
            "    out_cols[{}u][row] = r{};\n",
            .{ value.ordinal, value.register },
        ),
        .lookup_word => try output.print(
            "    lookup_words[{}u * row_count + row] = r{};\n",
            .{ value.ordinal, value.register },
        ),
        .sub_word => try output.print(
            "    sub_words[{}u * row_count + row] = r{};\n",
            .{ value.ordinal, value.register },
        ),
        else => return error.InvalidOutput,
    };
}

fn emitFp256Support(
    allocator: std.mem.Allocator,
    output: *std.Io.Writer,
    directory: std.fs.Dir,
) !void {
    try output.writeAll(
        \\// ---- fp256/EC embed prelude (self-contained TU: no headers resolved) ----
        \\#define STWO_WIT_EMBED 1
        \\namespace std {}
        \\typedef unsigned int uint32_t;
        \\typedef unsigned long long uint64_t;
        \\typedef unsigned int m31;
        \\#define UINT32_MAX 0xFFFFFFFFu
        \\#if !defined(__align__)
        \\#define __align__(n) alignas(n)
        \\#endif
        \\// NVRTC compiles device code ONLY and its JIT mode hard-errors on any function
        \\// carrying __host__ (alone). HOST_* therefore lower to plain __device__ here:
        \\// host-only chain functions become dead device functions and are discarded,
        \\// while literal `__host__` sites in the chain sit behind !__CUDACC_RTC__ guards.
        \\#define HOST_INLINE __device__ __forceinline__
        \\#define DEVICE_INLINE __device__ __forceinline__
        \\#define HOST_DEVICE_INLINE __device__ __forceinline__
        \\extern "C" __device__ int printf(const char*, ...);
        \\
    );
    try output.writeByte('\n');
    for (support_files) |name| {
        const source = try directory.readFileAlloc(allocator, name, 2 << 20);
        defer allocator.free(source);
        const body = if (source.len != 0 and source[source.len - 1] == '\n')
            source[0 .. source.len - 1]
        else
            source;
        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trimLeft(u8, line, " \t");
            if (std.mem.startsWith(u8, trimmed, "#include") or
                std.mem.startsWith(u8, trimmed, "#pragma once"))
                continue;
            try output.writeAll(line);
            try output.writeByte('\n');
        }
    }
    try output.writeByte('\n');
}

fn emitBlakeG(output: *std.Io.Writer) !void {
    try output.writeAll(
        \\static __device__ __forceinline__ unsigned stwo_wit_rotr(unsigned x, unsigned n) {
        \\    return (x >> n) | (x << (32u - n));
        \\}
        \\static __device__ __forceinline__ void stwo_wit_blake_g(
        \\    const unsigned *in, unsigned *out) {
        \\    unsigned a = in[0], b = in[1], c = in[2], d = in[3];
        \\    const unsigned m0 = in[4], m1 = in[5];
        \\    a = a + b + m0; d ^= a; d = stwo_wit_rotr(d, 16u);
        \\    c += d; b ^= c; b = stwo_wit_rotr(b, 12u);
        \\    a = a + b + m1; d ^= a; d = stwo_wit_rotr(d, 8u);
        \\    c += d; b ^= c; b = stwo_wit_rotr(b, 7u);
        \\    out[0] = a; out[1] = b; out[2] = c; out[3] = d;
        \\}
        \\
    );
    try output.writeByte('\n');
}

fn emitBlakeSigma(output: *std.Io.Writer) !void {
    try output.writeAll(
        \\static __device__ const unsigned STWO_WIT_BLAKE_SIGMA[10][16] = {
        \\    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        \\    {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
        \\    {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
        \\    {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
        \\    {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
        \\    {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
        \\    {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
        \\    {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
        \\    {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
        \\    {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0}
        \\};
        \\
    );
    try output.writeByte('\n');
}

fn emitKernelPreamble(output: *std.Io.Writer, semantic_hash: u64) !void {
    try output.writeAll(
        \\static __device__ __forceinline__ unsigned stwo_m31_inverse(unsigned a) {
        \\    unsigned result = a;                 // consumes exponent bit 30
        \\    for (int bit = 29; bit >= 0; --bit) {
        \\        result = stwo_m31_mul(result, result);
        \\        if (bit != 1) { result = stwo_m31_mul(result, a); }
        \\    }
        \\    return result;
        \\}
        \\
        \\static __device__ __forceinline__ unsigned stwo_wit_deduce_limb(
        \\    const unsigned *const *tb, const unsigned *ts, unsigned id, unsigned limb) {
        \\    unsigned tag = id >> 30u;
        \\    unsigned val = id & 0x3FFFFFFFu;
        \\    if (tag == 1u) { return val < ts[1] ? tb[1u + limb][val] : 0u; }
        \\    return (limb < 8u && val < ts[2]) ? tb[29u + limb][val] : 0u;
        \\}
        \\
    );
    try output.writeByte('\n');
    try output.print(
        \\extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_{x:0>16}(
        \\    const unsigned *const *input_cols,   // [n_inputs][row]
        \\    const unsigned *const *table_bases,  // deduce_output LUTs, per table
        \\    const unsigned *table_strides,       // words per key, per table
        \\    unsigned *const *out_cols,           // [n_cols][row]
        \\    unsigned *const *mult_counts,        // atomic count tables, per mult table
        \\    unsigned *lookup_words,              // [k * row_count + row] (word-major)
        \\    unsigned *sub_words,                 // [k * row_count + row] (word-major)
        \\    unsigned row_count
        \\) {{
        \\    unsigned row = blockIdx.x * blockDim.x + threadIdx.x;
        \\    if (row >= row_count) {{ return; }}
        \\
    , .{semantic_hash});
    try output.writeByte('\n');
}

fn emitPreamble(output: *std.Io.Writer) !void {
    try output.writeAll(
        \\typedef unsigned long long u64;
        \\
        \\#define STWO_M31_P 2147483647u
        \\
        \\#ifndef STWO_M31_FAST32_GLOBAL
        \\#define STWO_M31_FAST32_GLOBAL 0
        \\#endif
        \\#if STWO_M31_FAST32_GLOBAL != 0 && STWO_M31_FAST32_GLOBAL != 1
        \\#error "STWO_M31_FAST32_GLOBAL must be 0 or 1"
        \\#endif
        \\
        \\__device__ __forceinline__ unsigned stwo_m31_add(unsigned lhs, unsigned rhs) {
        \\    unsigned sum = lhs + rhs;
        \\    return sum >= STWO_M31_P ? sum - STWO_M31_P : sum;
        \\}
        \\
        \\__device__ __forceinline__ unsigned stwo_m31_sub(unsigned lhs, unsigned rhs) {
        \\    return lhs >= rhs ? lhs - rhs : lhs + STWO_M31_P - rhs;
        \\}
        \\
        \\__device__ __forceinline__ unsigned stwo_m31_neg(unsigned value) {
        \\    unsigned negated = STWO_M31_P - value;
        \\    return negated == STWO_M31_P ? 0u : negated;
        \\}
        \\
        \\__device__ __forceinline__ unsigned stwo_m31_mul(unsigned lhs, unsigned rhs) {
        \\#if STWO_M31_FAST32_GLOBAL
        \\    unsigned lo = lhs * rhs;
        \\    unsigned hi = __umulhi(lhs, rhs);
        \\    unsigned quotient = (hi << 1) | (lo >> 31);
        \\    unsigned reduced = (lo & STWO_M31_P) + quotient;
        \\    reduced = (reduced & STWO_M31_P) + (reduced >> 31);
        \\    return reduced == STWO_M31_P ? 0u : reduced;
        \\#else
        \\    u64 product = (u64)lhs * (u64)rhs;
        \\    u64 reduced = (((((product >> 31) + product + 1u) >> 31) + product) & (u64)STWO_M31_P);
        \\    return (unsigned)reduced;
        \\#endif
        \\}
        \\
    );
    try output.writeByte('\n');
}
