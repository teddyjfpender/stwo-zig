//! codegen contract cases for eval_codegen.
const std = @import("std");
const eval = @import("stwo_cairo_frontend").witness.eval_program;

const Owner = @import("eval_codegen.zig");
const FusedPart = Owner.FusedPart;
const fusedKernelName = Owner.fusedKernelName;
const generate = Owner.generate;
const preambleSourceFor = Owner.preambleSourceFor;
const generateKernel = Owner.generateKernel;
const generateKernelFor = Owner.generateKernelFor;
const generateFusedKernel = Owner.generateFusedKernel;
const preamble = Owner.preamble;

test "Metal evaluation codegen: emits fused arena kernel" {
    var base = [_]eval.BaseInst{
        .{ .op = .trace_col, .interaction = 0, .dst = 0, .a = 2, .b = 0, .imm = -1 },
        .{ .op = .constant, .interaction = 0, .dst = 1, .a = 7, .b = 0, .imm = 0 },
        .{ .op = .mul, .interaction = 0, .dst = 2, .a = 0, .b = 1, .imm = 0 },
    };
    var ext = [_]eval.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 2, .b = 1, .c = 0, .d = 1 },
        .{ .op = .param, .dst = 1, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 2, .a = 0, .b = 1, .c = 0, .d = 0 },
    };
    var roots = [_]u32{2};
    const program = eval.Program{
        .allocator = std.testing.allocator,
        .header = .{ .flags = eval.Flag.prefinalized_logup, .semantic_hash = 0x1234, .capability_bits = eval.Capability.prefinalized_logup | eval.Capability.ext_mul, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 1, .n_constraints = 1, .max_base_regs = 3, .max_ext_regs = 3, .domain_log_size = 8 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &ext,
        .constraint_roots = &roots,
    };
    const source = try generate(std.testing.allocator, program);
    defer std.testing.allocator.free(source);
    try std.testing.expect(std.mem.indexOf(u8, source, "b2 = m31_mul(b0, b1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "qm_mul(e0, e1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, source, "args.coord_3 + coordinate_row") != null);

    const kernel_only = try generateKernel(
        std.testing.allocator,
        program,
        false,
    );
    defer std.testing.allocator.free(kernel_only);
    try std.testing.expectEqualStrings(
        \\kernel void stwo_zig_eval_0000000000001234(
        \\    device uint *arena [[buffer(0)]],
        \\    constant EvalArgs &args [[buffer(1)]],
        \\    uint row [[thread_position_in_grid]]) {
        \\    if (row >= args.row_count) return;
        \\    uint coordinate_row = row;
        \\    uint b0 = trace_value(arena, args, 0u, 2u, row, -1);
        \\    uint b1 = 7u;
        \\    uint b2 = m31_mul(b0, b1);
        \\    Qm31 e0 = { b2, b1, b0, b1 };
        \\    Qm31 e1 = load_qm31(arena, args.ext_params + 0u * 4u);
        \\    Qm31 e2 = qm_mul(e0, e1);
        \\    Qm31 part_acc = { 0u, 0u, 0u, 0u };
        \\    part_acc = qm_add(part_acc, qm_mul(e2, load_qm31(arena, args.random_coeffs + (args.rc_base + 0u) * 4u)));
        \\    Qm31 result = qm_mul_base(part_acc, arena[args.denom_inv + (row >> args.trace_log_size)]);
        \\    arena[args.coord_0 + coordinate_row] = m31_add(arena[args.coord_0 + coordinate_row], result.a);
        \\    arena[args.coord_1 + coordinate_row] = m31_add(arena[args.coord_1 + coordinate_row], result.b);
        \\    arena[args.coord_2 + coordinate_row] = m31_add(arena[args.coord_2 + coordinate_row], result.c);
        \\    arena[args.coord_3 + coordinate_row] = m31_add(arena[args.coord_3 + coordinate_row], result.d);
        \\}
        \\
    ,
        kernel_only,
    );
}

test "Metal evaluation codegen: option B reads the stored column at its own shift" {
    var base = [_]eval.BaseInst{
        .{ .op = .trace_col, .interaction = 0, .dst = 0, .a = 2, .b = 0, .imm = -1 },
        .{ .op = .param, .interaction = 0, .dst = 1, .a = 0, .b = 0, .imm = 0 },
        .{ .op = .mul, .interaction = 0, .dst = 2, .a = 0, .b = 1, .imm = 0 },
    };
    var ext = [_]eval.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 2, .b = 1, .c = 0, .d = 1 },
    };
    var roots = [_]u32{0};
    const program = eval.Program{
        .allocator = std.testing.allocator,
        .header = .{ .flags = eval.Flag.prefinalized_logup, .semantic_hash = 0x1234, .capability_bits = eval.Capability.prefinalized_logup, .n_interactions = 1, .n_base_params = 1, .n_ext_params = 0, .n_constraints = 1, .max_base_regs = 3, .max_ext_regs = 1, .domain_log_size = 8 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &ext,
        .constraint_roots = &roots,
    };

    const tiled = try generateKernelFor(std.testing.allocator, program, true, .tiled_domain);
    defer std.testing.allocator.free(tiled);
    try std.testing.expect(std.mem.indexOf(u8, tiled, "stwo_zig_eval_td3_0000000000001234") != null);
    try std.testing.expect(std.mem.indexOf(u8, tiled, "row += arena[args.trace_offsets];") != null);
    try std.testing.expect(std.mem.indexOf(u8, tiled, "trace_value_tiled_fast(arena, args, 0u, 2u, row, 1u)") != null);
    try std.testing.expect(std.mem.indexOf(u8, tiled, "args.coord_0 + coordinate_row") != null);
    try std.testing.expect(std.mem.indexOf(u8, tiled, "args.denom_inv + (row >> args.trace_log_size)") != null);

    const stored = try generateKernelFor(std.testing.allocator, program, false, .stored_domain);
    defer std.testing.allocator.free(stored);
    // The kernel is named apart from its eval-domain twin, the parameter read is
    // untouched, and the shift table is addressed past this program's own params.
    try std.testing.expect(std.mem.indexOf(u8, stored, "stwo_zig_eval_sd_0000000000001234") != null);
    try std.testing.expect(std.mem.indexOf(u8, stored, "b1 = arena[args.base_params + 0u];") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        stored,
        "b0 = trace_value_stored(arena, args, 0u, 2u, row, -1, args.base_params + 1u);",
    ) != null);

    // Additive: the default emission is byte-identical, and the default preamble
    // is a strict prefix of option B's — nothing the pending eval-domain mint
    // compiles from moves.
    const default = try generateKernelFor(std.testing.allocator, program, false, .eval_domain);
    defer std.testing.allocator.free(default);
    const inherited = try generateKernel(std.testing.allocator, program, false);
    defer std.testing.allocator.free(inherited);
    try std.testing.expectEqualStrings(default, inherited);
    try std.testing.expect(std.mem.indexOf(u8, default, "trace_value_stored") == null);
    try std.testing.expect(std.mem.startsWith(
        u8,
        preambleSourceFor(.stored_domain),
        preambleSourceFor(.eval_domain),
    ));
    try std.testing.expectEqualStrings(preamble, preambleSourceFor(.eval_domain));
}

test "Metal evaluation codegen: fuses adjacent parts with one accumulator store" {
    var base = [_]eval.BaseInst{
        .{ .op = .trace_col, .interaction = 0, .dst = 0, .a = 0, .b = 0, .imm = 0 },
    };
    var ext = [_]eval.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 0, .b = 0, .c = 0, .d = 0 },
    };
    var roots = [_]u32{0};
    const first = eval.Program{
        .allocator = std.testing.allocator,
        .header = .{ .flags = eval.Flag.prefinalized_logup, .semantic_hash = 0x1111, .capability_bits = eval.Capability.prefinalized_logup, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 1, .max_base_regs = 1, .max_ext_regs = 1, .domain_log_size = 8 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &ext,
        .constraint_roots = &roots,
    };
    var second = first;
    second.header.semantic_hash = 0x2222;
    const parts = [_]FusedPart{
        .{ .program = first, .rc_base = 0 },
        .{ .program = second, .rc_base = 1 },
    };
    const source = try generateFusedKernel(std.testing.allocator, &parts, true);
    defer std.testing.allocator.free(source);
    const name = try fusedKernelName(std.testing.allocator, &parts);
    defer std.testing.allocator.free(name);
    try std.testing.expect(std.mem.indexOf(u8, source, name) != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, source, "arena[args.coord_0 + coordinate_row] ="));
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, source, "Qm31 part_result"));
    try std.testing.expect(std.mem.indexOf(u8, source, "args.rc_base + 1u") != null);
}

test "Metal evaluation codegen: rejects a noncontiguous fusion group" {
    var base = [_]eval.BaseInst{
        .{ .op = .constant, .interaction = 0, .dst = 0, .a = 1, .b = 0, .imm = 0 },
    };
    var ext = [_]eval.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 0, .b = 0, .c = 0, .d = 0 },
    };
    var roots = [_]u32{0};
    const program = eval.Program{
        .allocator = std.testing.allocator,
        .header = .{ .flags = eval.Flag.prefinalized_logup, .semantic_hash = 0x3333, .capability_bits = eval.Capability.prefinalized_logup, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 1, .max_base_regs = 1, .max_ext_regs = 1, .domain_log_size = 8 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &ext,
        .constraint_roots = &roots,
    };
    const parts = [_]FusedPart{
        .{ .program = program, .rc_base = 0 },
        .{ .program = program, .rc_base = 2 },
    };
    try std.testing.expectError(
        error.InvalidFusionGroup,
        generateFusedKernel(std.testing.allocator, &parts, false),
    );
}
