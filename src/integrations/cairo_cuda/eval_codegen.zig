//! CUDA C emission for one unfused Cairo evaluation-program body.
//!
//! The product AOT catalog owns placement-specific identities. This emitter
//! remains body-only so identical programs can share one cubin while the
//! shared frontend walker owns semantic instruction and coefficient order.

const std = @import("std");
const shapes = @import("stwo_cairo_frontend").codegen.field_shapes;
const eval = @import("stwo_cairo_frontend").witness.eval_program;
const shared = @import("stwo_cairo_frontend").codegen.eval_program;

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
    return generateBody(allocator, program, false, &.{});
}

/// Geometry-independent body. Constants are supplied by the authenticated
/// live AIR template binding in `base_params`; they are never proof inputs.
pub fn generateParametric(allocator: std.mem.Allocator, normalized: eval.Program, dynamic_constants: []const bool) ![]u8 {
    return generateBodyMode(allocator, normalized, true, dynamic_constants, shared.instructionCount(normalized) > 8192);
}

pub fn generateMaterializedParity(allocator: std.mem.Allocator, program: eval.Program, dynamic_constants: []const bool) ![]u8 {
    return generateBodyMode(allocator, program, true, dynamic_constants, true);
}

fn generateBody(allocator: std.mem.Allocator, program: eval.Program, parametric: bool, dynamic_constants: []const bool) ![]u8 {
    return generateBodyMode(allocator, program, parametric, dynamic_constants, false);
}

fn generateBodyMode(allocator: std.mem.Allocator, program: eval.Program, parametric: bool, dynamic_constants: []const bool, materialized: bool) ![]u8 {
    try program.validate();
    if (parametric) {
        var constants: usize = 0;
        for (program.base_insts) |inst| if (inst.op == .constant) {
            constants += 1;
        };
        if (dynamic_constants.len != constants) return error.AirConstantExtentMismatch;
    }
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    const writer = source.writer(allocator);
    if (parametric) {
        // The translated provider has no libdevice __nv_brev. Keep NVIDIA's
        // native instruction and supply exact u32 reversal for local checks.
        const portable = try std.mem.replaceOwned(u8, allocator, preamble, "return bits == 0u ? 0u : __brev(value) >> (32u - bits);", portable_bit_reverse);
        defer allocator.free(portable);
        try writer.writeAll(portable);
    } else try writer.writeAll(preamble);
    if (materialized) try writer.writeAll(local_bank_support);
    const name = if (parametric)
        try std.fmt.allocPrint(allocator, "stwo_cairo_cuda_eval_v3_{x:0>16}", .{program.header.semantic_hash})
    else
        try kernelName(allocator, program.header.semantic_hash);
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
    if (materialized) try writer.print("    volatile unsigned base_bank[{}];\n    volatile StwoCairoQm31 ext_bank[{}];\n", .{ @max(program.header.max_base_regs, 1), @max(program.header.max_ext_regs, 1) });

    const facts = if (parametric) try shapes.Facts.init(allocator, program) else null;
    defer if (facts) |value| value.deinit(allocator);
    const last_writes = try allocator.alloc(usize, if (parametric) program.header.max_ext_regs else 0);
    defer allocator.free(last_writes);
    @memset(last_writes, 0);
    if (parametric) {
        for (program.ext_insts, 0..) |inst, index| last_writes[inst.dst] = index;
        try writer.writeAll("    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };\n");
    }
    var emitter = CudaProgramEmitter(@TypeOf(writer)){
        .writer = writer,
        .parametric = parametric,
        .materialized = materialized,
        .dynamic_constants = dynamic_constants,
        .facts = facts,
        .last_writes = last_writes,
        .roots = program.constraint_roots,
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
        parametric: bool = false,
        materialized: bool = false,
        base_constant_cursor: u32 = 0,
        dynamic_constants: []const bool = &.{},
        facts: ?shapes.Facts = null,
        last_writes: []const usize = &.{},
        roots: []const u32 = &.{},
        extension_cursor: usize = 0,
        root_cursor: usize = 0,

        fn baseRef(self: *@This(), register: u32, buffer: *[96]u8, read: bool) ![]const u8 {
            if (self.materialized and read) {
                if (self.facts.?.base[register]) |value|
                    return std.fmt.bufPrint(buffer, "{}u", .{value});
            }
            return if (self.materialized) std.fmt.bufPrint(buffer, "base_bank[{}]", .{register}) else std.fmt.bufPrint(buffer, "b{}", .{register});
        }

        fn extRef(self: *@This(), register: u32, buffer: *[96]u8, scalar: bool) ![]const u8 {
            if (self.materialized) return if (scalar)
                std.fmt.bufPrint(buffer, "ext_bank[{}].a", .{register})
            else
                std.fmt.bufPrint(buffer, "stwo_local_load(ext_bank[{}])", .{register});
            return if (scalar) std.fmt.bufPrint(buffer, "e{}.a", .{register}) else std.fmt.bufPrint(buffer, "e{}", .{register});
        }

        pub fn base(self: *@This(), step: shared.BaseStep) !void {
            const inst = step.instruction;
            const decl = if (step.declare and !self.materialized) "unsigned " else "";
            const known: ?u32 = if (self.parametric and inst.op == .constant and self.dynamic_constants[self.base_constant_cursor])
                null
            else if (self.facts) |facts| facts.baseValue(inst) else null;
            if (self.materialized and known != null) {
                // Every read of a known base value is emitted as its literal.
                // Avoid private-memory stores for compile-time constants.
                self.facts.?.base[inst.dst] = known;
                if (inst.op == .constant) self.base_constant_cursor += 1;
                return;
            }
            var destination: [96]u8 = undefined;
            var left: [96]u8 = undefined;
            var right: [96]u8 = undefined;
            const dst = try self.baseRef(inst.dst, &destination, false);
            const a = if (inst.op == .add or inst.op == .sub or inst.op == .mul or inst.op == .neg or inst.op == .inv)
                try self.baseRef(inst.a, &left, true)
            else
                "";
            const b = if (inst.op == .add or inst.op == .sub or inst.op == .mul)
                try self.baseRef(inst.b, &right, true)
            else
                "";
            switch (inst.op) {
                .trace_col, .preprocessed_col => try self.writer.print(
                    "    {s}{s} = stwo_trace_value(arena, *args, {}u, {}u, row, {});\n",
                    .{
                        decl,
                        dst,
                        inst.interaction,
                        inst.a,
                        inst.imm,
                    },
                ),
                .param => try self.writer.print(
                    "    {s}{s} = arena[args->base_params + {}u];\n",
                    .{ decl, dst, inst.a },
                ),
                .constant => {
                    if (self.parametric and self.dynamic_constants[self.base_constant_cursor]) {
                        try self.writer.print("    {s}{s} = arena[args->base_params + {}u];\n", .{ decl, dst, self.base_constant_cursor });
                    } else try self.writer.print("    {s}{s} = {}u;\n", .{ decl, dst, inst.a });
                    if (self.parametric) self.base_constant_cursor += 1;
                },
                .add => try self.writer.print(
                    "    {s}{s} = stwo_m31_add({s}, {s});\n",
                    .{ decl, dst, a, b },
                ),
                .sub => try self.writer.print(
                    "    {s}{s} = stwo_m31_sub({s}, {s});\n",
                    .{ decl, dst, a, b },
                ),
                .mul => try self.writer.print(
                    "    {s}{s} = stwo_m31_mul({s}, {s});\n",
                    .{ decl, dst, a, b },
                ),
                .neg => try self.writer.print(
                    "    {s}{s} = stwo_m31_neg({s});\n",
                    .{ decl, dst, a },
                ),
                .inv => try self.writer.print(
                    "    {s}{s} = stwo_m31_inv({s});\n",
                    .{ decl, dst, a },
                ),
            }
            if (self.facts) |facts| facts.base[inst.dst] = known;
        }

        pub fn extended(self: *@This(), step: shared.ExtStep) !void {
            if (self.parametric) return self.extendedParametric(step);
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
                .constant => try self.writer.print("    {s}e{} = {{ {}u, {}u, {}u, {}u }};\n", .{ decl, inst.dst, inst.a, inst.b, inst.c, inst.d }),
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

        fn extendedParametric(self: *@This(), step: shared.ExtStep) !void {
            const i = step.instruction;
            const facts = self.facts.?;
            const kind = facts.extensionKind(i);
            var left: [96]u8 = undefined;
            var right: [96]u8 = undefined;
            var left_scalar: [96]u8 = undefined;
            var right_scalar: [96]u8 = undefined;
            const a = try self.extRef(i.a, &left, false);
            const b = try self.extRef(i.b, &right, false);
            const a_scalar = try self.extRef(i.a, &left_scalar, true);
            const b_scalar = try self.extRef(i.b, &right_scalar, true);
            if (self.materialized) try self.writer.writeAll("    {\n    StwoCairoQm31 value = ") else try self.writer.print("    {s}e{} = ", .{ if (step.declare) "StwoCairoQm31 " else "", i.dst });
            if (kind == .zero) {
                try self.writer.writeAll("{ 0u, 0u, 0u, 0u }");
            } else switch (i.op) {
                .secure_col => {
                    var ba: [96]u8 = undefined;
                    var bb: [96]u8 = undefined;
                    var bc: [96]u8 = undefined;
                    var bd: [96]u8 = undefined;
                    try self.writer.print("{{ {s}, {s}, {s}, {s} }}", .{
                        try self.baseRef(i.a, &ba, true), try self.baseRef(i.b, &bb, true),
                        try self.baseRef(i.c, &bc, true), try self.baseRef(i.d, &bd, true),
                    });
                },
                .param => try self.writer.print("stwo_load_qm31(arena, args->ext_params + {}u * 4u)", .{i.a}),
                .constant => try self.writer.print("{{ {}u, {}u, {}u, {}u }}", .{ i.a, i.b, i.c, i.d }),
                .add, .sub, .mul => {
                    const lhs = facts.extended[i.a];
                    const rhs = facts.extended[i.b];
                    if ((i.op == .add or i.op == .sub) and rhs == .zero) {
                        try self.writer.writeAll(a);
                    } else if ((i.op == .add and lhs == .zero) or (i.op == .mul and lhs == .one)) {
                        try self.writer.writeAll(b);
                    } else if (i.op == .mul and rhs == .one) {
                        try self.writer.writeAll(a);
                    } else if (i.op == .mul and lhs != .secure) {
                        try self.writer.print("stwo_qm31_mul_base({s}, {s})", .{ b, a_scalar });
                    } else if (i.op == .mul and rhs != .secure) {
                        try self.writer.print("stwo_qm31_mul_base({s}, {s})", .{ a, b_scalar });
                    } else try self.writer.print("{s}({s}, {s})", .{ switch (i.op) {
                        .add => "stwo_qm31_add",
                        .sub => "stwo_qm31_sub",
                        else => "stwo_qm31_mul",
                    }, a, b });
                },
                .neg => try self.writer.print("stwo_qm31_neg({s})", .{a}),
            }
            try self.writer.writeAll(";\n");
            if (self.materialized) try self.writer.print("    stwo_local_store(ext_bank[{}], value);\n    }}\n", .{i.dst});
            facts.extended[i.dst] = kind;
            self.extension_cursor += 1;
            // Keep canonical root/coefficient order and wait for the FINAL
            // register write. This supports imperative register reuse while
            // consuming completed constraints before the entire AIR finishes.
            while (self.root_cursor < self.roots.len and self.last_writes[self.roots[self.root_cursor]] < self.extension_cursor) {
                try self.emitParametricConstraint(self.roots[self.root_cursor], self.root_cursor);
                self.root_cursor += 1;
            }
        }

        fn emitParametricConstraint(self: *@This(), root: u32, offset: usize) !void {
            var reference: [96]u8 = undefined;
            var scalar: [96]u8 = undefined;
            const e = try self.extRef(root, &reference, false);
            const scalar_value = try self.extRef(root, &scalar, true);
            switch (self.facts.?.extended[root]) {
                .zero => {},
                .one => try self.writer.print("    part_acc = stwo_qm31_add(part_acc, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + {}u) * 4u));\n", .{offset}),
                .base => try self.writer.print("    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul_base(stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + {}u) * 4u), {s}));\n", .{ offset, scalar_value }),
                .secure => try self.writer.print("    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul({s}, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + {}u) * 4u)));\n", .{ e, offset }),
            }
        }

        pub fn beginConstraints(self: *@This()) !void {
            if (self.parametric) {
                if (self.root_cursor != self.roots.len) return error.UnemittedConstraint;
                return;
            }
            try self.writer.writeAll(
                "    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };\n",
            );
        }

        pub fn constraint(
            self: *@This(),
            step: shared.ConstraintStep,
        ) !void {
            if (self.parametric) return;
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

// Large programs materialize registers explicitly. Volatile accesses prevent
// scalar replacement from rebuilding an enormous register interference graph.
// These are thread-private banks, not host transfers or shared proof state.
const local_bank_support =
    \\__device__ __forceinline__ StwoCairoQm31 stwo_local_load(
    \\    const volatile StwoCairoQm31 &value) {
    \\    return {value.a, value.b, value.c, value.d};
    \\}
    \\__device__ __forceinline__ void stwo_local_store(
    \\    volatile StwoCairoQm31 &destination, StwoCairoQm31 value) {
    \\    destination.a=value.a; destination.b=value.b;
    \\    destination.c=value.c; destination.d=value.d;
    \\}
    \\
;

const portable_bit_reverse =
    \\#if defined(STWO_CUMETAL)
    \\    value = ((value >> 1u) & 0x55555555u) | ((value & 0x55555555u) << 1u);
    \\    value = ((value >> 2u) & 0x33333333u) | ((value & 0x33333333u) << 2u);
    \\    value = ((value >> 4u) & 0x0f0f0f0fu) | ((value & 0x0f0f0f0fu) << 4u);
    \\    value = ((value >> 8u) & 0x00ff00ffu) | ((value & 0x00ff00ffu) << 8u);
    \\    value = (value >> 16u) | (value << 16u);
    \\    return bits == 0u ? 0u : value >> (32u - bits);
    \\#else
    \\    return bits == 0u ? 0u : __brev(value) >> (32u - bits);
    \\#endif
;

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
