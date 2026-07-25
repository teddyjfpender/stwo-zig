//! CUDA C emission for one unfused Cairo evaluation-program body.
//!
//! The product AOT catalog owns placement-specific identities. This emitter
//! remains body-only so identical programs can share one cubin while the
//! shared frontend walker owns semantic instruction and coefficient order.

const std = @import("std");
const eval = @import("../../frontends/cairo/witness/eval_program.zig");
const shared = @import("../../frontends/cairo/codegen/eval_program.zig");

pub const codegen_version: u64 = 1;
pub const product_identity_domain =
    "stwo-zig/cairo-cuda-eval-product/v1\x00";

pub fn cacheKey(semantic_hash: u64) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    hashInt(&hash, semantic_hash);
    hashInt(&hash, codegen_version);
    return hash;
}

pub fn kernelName(
    allocator: std.mem.Allocator,
    semantic_hash: u64,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "stwo_cairo_cuda_eval_v1_{x:0>16}",
        .{cacheKey(semantic_hash)},
    );
}

pub fn sourceIdentity(source: []const u8) [32]u8 {
    var identity: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &identity, .{});
    return identity;
}

/// SHA-256 over the exact backend-neutral program semantics. This is stronger
/// than the compact FNV semantic hash used in imported program headers.
pub fn programIdentity(program: eval.Program) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo-zig/cairo-eval-program/v1\x00");
    hashUnsigned(&hasher, u64, codegen_version);
    hashUnsigned(&hasher, u32, program.header.flags);
    hashUnsigned(&hasher, u64, program.header.semantic_hash);
    hashUnsigned(&hasher, u64, program.header.capability_bits);
    hashUnsigned(&hasher, u32, program.header.n_interactions);
    hashUnsigned(&hasher, u32, program.header.n_base_params);
    hashUnsigned(&hasher, u32, program.header.n_ext_params);
    hashUnsigned(&hasher, u32, program.header.n_constraints);
    hashUnsigned(&hasher, u32, program.header.max_base_regs);
    hashUnsigned(&hasher, u32, program.header.max_ext_regs);
    hashUnsigned(&hasher, u32, program.header.domain_log_size);

    hashLength(&hasher, program.base_consts.len);
    for (program.base_consts) |value| hashUnsigned(&hasher, u32, value);
    hashLength(&hasher, program.ext_consts.len);
    for (program.ext_consts) |value| {
        for (value) |coordinate| hashUnsigned(&hasher, u32, coordinate);
    }
    hashLength(&hasher, program.base_insts.len);
    for (program.base_insts) |instruction| {
        hashUnsigned(&hasher, u8, @intFromEnum(instruction.op));
        hashUnsigned(&hasher, u8, instruction.interaction);
        hashUnsigned(&hasher, u16, instruction.dst);
        hashUnsigned(&hasher, u32, instruction.a);
        hashUnsigned(&hasher, u32, instruction.b);
        hashUnsigned(
            &hasher,
            u32,
            @bitCast(instruction.imm),
        );
    }
    hashLength(&hasher, program.ext_insts.len);
    for (program.ext_insts) |instruction| {
        hashUnsigned(&hasher, u8, @intFromEnum(instruction.op));
        hashUnsigned(&hasher, u16, instruction.dst);
        hashUnsigned(&hasher, u32, instruction.a);
        hashUnsigned(&hasher, u32, instruction.b);
        hashUnsigned(&hasher, u32, instruction.c);
        hashUnsigned(&hasher, u32, instruction.d);
    }
    hashLength(&hasher, program.constraint_roots.len);
    for (program.constraint_roots) |root| hashUnsigned(&hasher, u32, root);

    var identity: [32]u8 = undefined;
    hasher.final(&identity);
    return identity;
}

/// Lookup identity for one authenticated body plus every SN2 placement that
/// is permitted to invoke it. The kernel symbol remains body-derived.
pub fn productCacheKey(
    program_identity: [32]u8,
    source_identity: [32]u8,
    catalog_identity: [32]u8,
) u64 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(product_identity_domain);
    hasher.update(&program_identity);
    hasher.update(&source_identity);
    hasher.update(&catalog_identity);
    hashUnsigned(&hasher, u64, codegen_version);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.mem.readInt(u64, digest[0..8], .big);
}

pub fn generate(
    allocator: std.mem.Allocator,
    program: eval.Program,
) ![]u8 {
    try program.validate();
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    const writer = source.writer(allocator);
    try writer.writeAll(preamble);
    const name = try kernelName(
        allocator,
        program.header.semantic_hash,
    );
    defer allocator.free(name);
    try writer.print(
        \\extern "C" __global__ void __launch_bounds__(256)
        \\{s}(
        \\    unsigned *arena,
        \\    u64 arena_words,
        \\    const StwoCairoEvalArgs *args) {{
        \\    const unsigned row =
        \\        blockIdx.x * blockDim.x + threadIdx.x;
        \\    if (arena == nullptr || args == nullptr ||
        \\        row >= args->row_count) return;
        \\
    , .{name});

    var emitter = CudaProgramEmitter(@TypeOf(writer)){
        .writer = writer,
    };
    try shared.walk(allocator, program, 0, &emitter);
    try writer.writeAll(
        \\    StwoCairoQm31 result = stwo_qm31_mul_base(
        \\        part_acc,
        \\        arena[args->denom_inv +
        \\            (row >> args->trace_log_size)]);
        \\    StwoCairoQm31 cumulative = {
        \\        arena[args->coord_0 + row],
        \\        arena[args->coord_1 + row],
        \\        arena[args->coord_2 + row],
        \\        arena[args->coord_3 + row]
        \\    };
        \\    cumulative = stwo_qm31_add(cumulative, result);
        \\    arena[args->coord_0 + row] = cumulative.a;
        \\    arena[args->coord_1 + row] = cumulative.b;
        \\    arena[args->coord_2 + row] = cumulative.c;
        \\    arena[args->coord_3 + row] = cumulative.d;
        \\    (void)arena_words;
        \\}
        \\
    );
    return source.toOwnedSlice(allocator);
}

fn CudaProgramEmitter(comptime Writer: type) type {
    return struct {
        writer: Writer,

        pub fn base(self: *@This(), step: shared.BaseStep) !void {
            const inst = step.instruction;
            const decl = if (step.declare) "unsigned " else "";
            switch (inst.op) {
                .trace_col, .preprocessed_col => try self.writer.print(
                    "    {s}b{} = stwo_trace_value(arena, *args, {}u, {}u, row, {});\n",
                    .{
                        decl,
                        inst.dst,
                        inst.interaction,
                        inst.a,
                        inst.imm,
                    },
                ),
                .param => try self.writer.print(
                    "    {s}b{} = arena[args->base_params + {}u];\n",
                    .{ decl, inst.dst, inst.a },
                ),
                .constant => try self.writer.print(
                    "    {s}b{} = {}u;\n",
                    .{ decl, inst.dst, inst.a },
                ),
                .add => try self.writer.print(
                    "    {s}b{} = stwo_m31_add(b{}, b{});\n",
                    .{ decl, inst.dst, inst.a, inst.b },
                ),
                .sub => try self.writer.print(
                    "    {s}b{} = stwo_m31_sub(b{}, b{});\n",
                    .{ decl, inst.dst, inst.a, inst.b },
                ),
                .mul => try self.writer.print(
                    "    {s}b{} = stwo_m31_mul(b{}, b{});\n",
                    .{ decl, inst.dst, inst.a, inst.b },
                ),
                .neg => try self.writer.print(
                    "    {s}b{} = stwo_m31_neg(b{});\n",
                    .{ decl, inst.dst, inst.a },
                ),
                .inv => try self.writer.print(
                    "    {s}b{} = stwo_m31_inv(b{});\n",
                    .{ decl, inst.dst, inst.a },
                ),
            }
        }

        pub fn extended(self: *@This(), step: shared.ExtStep) !void {
            const inst = step.instruction;
            const decl = if (step.declare)
                "StwoCairoQm31 "
            else
                "";
            switch (inst.op) {
                .secure_col => try self.writer.print(
                    "    {s}e{} = {{ b{}, b{}, b{}, b{} }};\n",
                    .{
                        decl,
                        inst.dst,
                        inst.a,
                        inst.b,
                        inst.c,
                        inst.d,
                    },
                ),
                .param => try self.writer.print(
                    "    {s}e{} = stwo_load_qm31(arena, args->ext_params + {}u * 4u);\n",
                    .{ decl, inst.dst, inst.a },
                ),
                .constant => try self.writer.print(
                    "    {s}e{} = {{ {}u, {}u, {}u, {}u }};\n",
                    .{
                        decl,
                        inst.dst,
                        inst.a,
                        inst.b,
                        inst.c,
                        inst.d,
                    },
                ),
                .add => try self.writer.print(
                    "    {s}e{} = stwo_qm31_add(e{}, e{});\n",
                    .{ decl, inst.dst, inst.a, inst.b },
                ),
                .sub => try self.writer.print(
                    "    {s}e{} = stwo_qm31_sub(e{}, e{});\n",
                    .{ decl, inst.dst, inst.a, inst.b },
                ),
                .mul => try self.writer.print(
                    "    {s}e{} = stwo_qm31_mul(e{}, e{});\n",
                    .{ decl, inst.dst, inst.a, inst.b },
                ),
                .neg => try self.writer.print(
                    "    {s}e{} = stwo_qm31_neg(e{});\n",
                    .{ decl, inst.dst, inst.a },
                ),
            }
        }

        pub fn beginConstraints(self: *@This()) !void {
            try self.writer.writeAll(
                "    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };\n",
            );
        }

        pub fn constraint(
            self: *@This(),
            step: shared.ConstraintStep,
        ) !void {
            try self.writer.print(
                "    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e{}, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + {}u) * 4u)));\n",
                .{ step.root, step.random_coefficient_offset },
            );
        }
    };
}

fn hashInt(hash: *u64, value: u64) void {
    for (0..@sizeOf(u64)) |index| {
        hash.* ^= @as(u8, @truncate(value >> @intCast(index * 8)));
        hash.* *%= 0x100000001b3;
    }
}

fn hashLength(
    hasher: *std.crypto.hash.sha2.Sha256,
    value: usize,
) void {
    hashUnsigned(hasher, u64, @intCast(value));
}

fn hashUnsigned(
    hasher: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}

const preamble =
    \\// stwo-zig Cairo CUDA evaluation codegen v1.
    \\typedef unsigned long long u64;
    \\#define STWO_M31_P 2147483647u
    \\struct StwoCairoQm31 { unsigned a, b, c, d; };
    \\struct StwoCairoEvalArgs {
    \\    u64 trace_offsets;
    \\    u64 interaction_offsets;
    \\    u64 base_params;
    \\    u64 ext_params;
    \\    u64 random_coeffs;
    \\    u64 denom_inv;
    \\    u64 coord_0;
    \\    u64 coord_1;
    \\    u64 coord_2;
    \\    u64 coord_3;
    \\    unsigned row_count;
    \\    unsigned trace_log_size;
    \\    unsigned domain_log_size;
    \\    unsigned rc_base;
    \\};
    \\__device__ __forceinline__ unsigned stwo_m31_reduce(u64 value) {
    \\    value = (value & STWO_M31_P) + (value >> 31u);
    \\    value = (value & STWO_M31_P) + (value >> 31u);
    \\    return value == STWO_M31_P ? 0u : (unsigned)value;
    \\}
    \\__device__ __forceinline__ unsigned stwo_m31_add(
    \\    unsigned lhs, unsigned rhs) {
    \\    return stwo_m31_reduce((u64)lhs + rhs);
    \\}
    \\__device__ __forceinline__ unsigned stwo_m31_sub(
    \\    unsigned lhs, unsigned rhs) {
    \\    return lhs >= rhs ? lhs - rhs : lhs + STWO_M31_P - rhs;
    \\}
    \\__device__ __forceinline__ unsigned stwo_m31_mul(
    \\    unsigned lhs, unsigned rhs) {
    \\    return stwo_m31_reduce((u64)lhs * rhs);
    \\}
    \\__device__ __forceinline__ unsigned stwo_m31_neg(unsigned value) {
    \\    return value == 0u ? 0u : STWO_M31_P - value;
    \\}
    \\__device__ __forceinline__ unsigned stwo_m31_inv(unsigned value) {
    \\    unsigned result = 1u, base = value, exponent = STWO_M31_P - 2u;
    \\    while (exponent != 0u) {
    \\        if ((exponent & 1u) != 0u)
    \\            result = stwo_m31_mul(result, base);
    \\        base = stwo_m31_mul(base, base);
    \\        exponent >>= 1u;
    \\    }
    \\    return result;
    \\}
    \\__device__ __forceinline__ StwoCairoQm31 stwo_qm31_add(
    \\    StwoCairoQm31 lhs, StwoCairoQm31 rhs) {
    \\    return {
    \\        stwo_m31_add(lhs.a, rhs.a), stwo_m31_add(lhs.b, rhs.b),
    \\        stwo_m31_add(lhs.c, rhs.c), stwo_m31_add(lhs.d, rhs.d)
    \\    };
    \\}
    \\__device__ __forceinline__ StwoCairoQm31 stwo_qm31_sub(
    \\    StwoCairoQm31 lhs, StwoCairoQm31 rhs) {
    \\    return {
    \\        stwo_m31_sub(lhs.a, rhs.a), stwo_m31_sub(lhs.b, rhs.b),
    \\        stwo_m31_sub(lhs.c, rhs.c), stwo_m31_sub(lhs.d, rhs.d)
    \\    };
    \\}
    \\__device__ __forceinline__ StwoCairoQm31 stwo_qm31_neg(
    \\    StwoCairoQm31 value) {
    \\    return {
    \\        stwo_m31_neg(value.a), stwo_m31_neg(value.b),
    \\        stwo_m31_neg(value.c), stwo_m31_neg(value.d)
    \\    };
    \\}
    \\__device__ __forceinline__ StwoCairoQm31 stwo_qm31_mul_base(
    \\    StwoCairoQm31 value, unsigned scalar) {
    \\    return {
    \\        stwo_m31_mul(value.a, scalar), stwo_m31_mul(value.b, scalar),
    \\        stwo_m31_mul(value.c, scalar), stwo_m31_mul(value.d, scalar)
    \\    };
    \\}
    \\__device__ __forceinline__ StwoCairoQm31 stwo_qm31_mul(
    \\    StwoCairoQm31 lhs, StwoCairoQm31 rhs) {
    \\    unsigned x0 = stwo_m31_sub(
    \\        stwo_m31_mul(lhs.a, rhs.a), stwo_m31_mul(lhs.b, rhs.b));
    \\    unsigned x1 = stwo_m31_add(
    \\        stwo_m31_mul(lhs.a, rhs.b), stwo_m31_mul(lhs.b, rhs.a));
    \\    unsigned y0 = stwo_m31_sub(
    \\        stwo_m31_mul(lhs.c, rhs.c), stwo_m31_mul(lhs.d, rhs.d));
    \\    unsigned y1 = stwo_m31_add(
    \\        stwo_m31_mul(lhs.c, rhs.d), stwo_m31_mul(lhs.d, rhs.c));
    \\    unsigned c0 = stwo_m31_sub(
    \\        stwo_m31_mul(lhs.a, rhs.c), stwo_m31_mul(lhs.b, rhs.d));
    \\    unsigned c1 = stwo_m31_add(
    \\        stwo_m31_mul(lhs.a, rhs.d), stwo_m31_mul(lhs.b, rhs.c));
    \\    unsigned c2 = stwo_m31_sub(
    \\        stwo_m31_mul(lhs.c, rhs.a), stwo_m31_mul(lhs.d, rhs.b));
    \\    unsigned c3 = stwo_m31_add(
    \\        stwo_m31_mul(lhs.c, rhs.b), stwo_m31_mul(lhs.d, rhs.a));
    \\    return {
    \\        stwo_m31_add(x0, stwo_m31_sub(stwo_m31_add(y0, y0), y1)),
    \\        stwo_m31_add(x1, stwo_m31_add(y0, stwo_m31_add(y1, y1))),
    \\        stwo_m31_add(c0, c2), stwo_m31_add(c1, c3)
    \\    };
    \\}
    \\__device__ __forceinline__ StwoCairoQm31 stwo_load_qm31(
    \\    const unsigned *arena, u64 offset) {
    \\    return {
    \\        arena[offset], arena[offset + 1u],
    \\        arena[offset + 2u], arena[offset + 3u]
    \\    };
    \\}
    \\__device__ __forceinline__ unsigned stwo_bit_reverse(
    \\    unsigned value, unsigned bits) {
    \\    return bits == 0u ? 0u : __brev(value) >> (32u - bits);
    \\}
    \\__device__ __forceinline__ unsigned stwo_offset_circle(
    \\    unsigned row, unsigned domain_log, unsigned evaluation_log,
    \\    int offset) {
    \\    unsigned previous = stwo_bit_reverse(row, evaluation_log);
    \\    unsigned half_size = 1u << (evaluation_log - 1u);
    \\    int step = offset * (int)(1u <<
    \\        (evaluation_log - domain_log - 1u));
    \\    if (previous < half_size) {
    \\        int position = ((int)previous + step) % (int)half_size;
    \\        if (position < 0) position += (int)half_size;
    \\        previous = (unsigned)position;
    \\    } else {
    \\        int position = ((int)previous - step) % (int)half_size;
    \\        if (position < 0) position += (int)half_size;
    \\        previous = (unsigned)position + half_size;
    \\    }
    \\    return stwo_bit_reverse(previous, evaluation_log);
    \\}
    \\__device__ __forceinline__ unsigned stwo_trace_value(
    \\    const unsigned *arena, const StwoCairoEvalArgs &args,
    \\    unsigned interaction, unsigned column, unsigned row, int offset) {
    \\    const unsigned evaluation_log =
    \\        31u - (unsigned)__clz(args.row_count);
    \\    const unsigned target = offset == 0 ? row : stwo_offset_circle(
    \\        row, args.domain_log_size, evaluation_log, offset);
    \\    const u64 global =
    \\        (u64)arena[args.interaction_offsets + interaction] + column;
    \\    return arena[(u64)arena[args.trace_offsets + global] + target];
    \\}
    \\
;

test "CUDA Cairo eval codegen is deterministic and binds resident semantics" {
    var base = [_]eval.BaseInst{
        .{ .op = .trace_col, .interaction = 1, .dst = 0, .a = 3, .b = 0, .imm = -1 },
        .{ .op = .preprocessed_col, .interaction = 0, .dst = 1, .a = 5, .b = 0, .imm = 0 },
        .{ .op = .param, .interaction = 0, .dst = 2, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .constant, .interaction = 0, .dst = 3, .a = 7, .b = 0, .imm = 0 },
        .{ .op = .add, .interaction = 0, .dst = 4, .a = 0, .b = 1, .imm = 0 },
        .{ .op = .mul, .interaction = 0, .dst = 5, .a = 4, .b = 2, .imm = 0 },
        .{ .op = .inv, .interaction = 0, .dst = 6, .a = 3, .b = 0, .imm = 0 },
    };
    var extended = [_]eval.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 5, .b = 1, .c = 0, .d = 3 },
        .{ .op = .param, .dst = 1, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .constant, .dst = 2, .a = 11, .b = 13, .c = 17, .d = 19 },
        .{ .op = .mul, .dst = 3, .a = 0, .b = 1, .c = 0, .d = 0 },
        .{ .op = .add, .dst = 4, .a = 3, .b = 2, .c = 0, .d = 0 },
    };
    var roots = [_]u32{ 3, 4 };
    const program = eval.Program{
        .allocator = std.testing.allocator,
        .header = .{
            .flags = eval.Flag.prefinalized_logup,
            .semantic_hash = 0x1020304050607080,
            .capability_bits = eval.Capability.prefinalized_logup |
                eval.Capability.base_inv |
                eval.Capability.ext_mul,
            .n_interactions = 2,
            .n_base_params = 1,
            .n_ext_params = 1,
            .n_constraints = 2,
            .max_base_regs = 7,
            .max_ext_regs = 5,
            .domain_log_size = 20,
        },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &extended,
        .constraint_roots = &roots,
    };
    const first = try generate(std.testing.allocator, program);
    defer std.testing.allocator.free(first);
    const second = try generate(std.testing.allocator, program);
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualStrings(first, second);
    const name = try kernelName(
        std.testing.allocator,
        program.header.semantic_hash,
    );
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings(
        "stwo_cairo_cuda_eval_v1_ac1391b1c5adf7c4",
        name,
    );
    const first_identity = sourceIdentity(first);
    const second_identity = sourceIdentity(second);
    try std.testing.expectEqualSlices(
        u8,
        &first_identity,
        &second_identity,
    );
    const changed = try std.testing.allocator.dupe(u8, first);
    defer std.testing.allocator.free(changed);
    changed[changed.len - 1] ^= 1;
    const changed_identity = sourceIdentity(changed);
    try std.testing.expect(!std.mem.eql(
        u8,
        &first_identity,
        &changed_identity,
    ));
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            first,
            "stwo_trace_value(arena, *args, 1u, 3u, row, -1)",
        ) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            first,
            "stwo_trace_value(arena, *args, 0u, 5u, row, 0)",
        ) != null,
    );
    const first_coefficient = std.mem.indexOf(
        u8,
        first,
        "args->rc_base + 0u",
    ).?;
    const second_coefficient = std.mem.indexOf(
        u8,
        first,
        "args->rc_base + 1u",
    ).?;
    try std.testing.expect(first_coefficient < second_coefficient);
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            first,
            "arena[args->denom_inv +",
        ) != null,
    );
    inline for (0..4) |coordinate| {
        const needle = try std.fmt.allocPrint(
            std.testing.allocator,
            "arena[args->coord_{} + row] = cumulative.",
            .{coordinate},
        );
        defer std.testing.allocator.free(needle);
        try std.testing.expect(std.mem.indexOf(u8, first, needle) != null);
    }
}
