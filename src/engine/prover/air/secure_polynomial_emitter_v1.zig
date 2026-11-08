//! Shared secure DAG instruction lowering; field primitives keep exact QM31 ABI.
const std = @import("std");
const ir = @import("secure_polynomial_program_v1.zig");
pub fn fingerprint() [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(@embedFile("secure_polynomial_emitter_v1.zig"), &digest, .{});
    return digest;
}
/// Shared instruction lowering also used by CUDA with the same field ABI.
pub fn emitNodes(w: anytype, program: *const ir.Program) !void {
    try program.validate();
    const fractions = ir.isFraction(program.kind);
    for (program.nodes, 0..) |node, index| {
        switch (node.op) {
            .constant => try w.print(" RiscvQm31 v{} = {{ {}u,{}u,{}u,{}u }};\n", .{ index, node.words[0], node.words[1], node.words[2], node.words[3] }),
            .input => {
                const input = program.inputs[node.value];
                if (fractions) try w.print(" if(tree{}[column_offsets[{}u]+{s}]>=RISCV_M31_P) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);\n", .{ input.tree, node.value, if (input.previous) "previous_row" else "row" });
                try w.print(" RiscvQm31 v{} = {{ tree{}[column_offsets[{}u]+{s}],0u,0u,0u }};\n", .{ index, input.tree, node.value, if (input.previous) "previous_row" else "row" });
            },
            .parameter => try w.print(" RiscvQm31 v{} = riscv_load_qm31(profile_parameters,{}u);\n", .{ index, 4 * node.value }),
            .add, .sub, .mul => try w.print(" RiscvQm31 v{} = riscv_qm_{s}(v{},v{});\n", .{ index, @tagName(node.op), node.lhs, node.rhs }),
            .neg => try w.print(" RiscvQm31 v{} = riscv_qm_sub(RiscvQm31{{0u,0u,0u,0u}},v{});\n", .{ index, node.lhs }),
            .fraction => try w.print(
                \\ RiscvQm31 v{0} = {{0u,0u,0u,0u}};
                \\ if ((v{1}.a|v{1}.b|v{1}.c|v{1}.d)!=0u) {{
                \\   if ((v{2}.a|v{2}.b|v{2}.c|v{2}.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
                \\   else v{0}=riscv_qm_mul(v{1},framework_interaction_inverse(v{2}));
                \\ }}
                \\
            , .{ index, node.lhs, node.rhs }),
            .range_fraction => try w.print(
                \\ RiscvQm31 v{0}={{0u,0u,0u,0u}};
                \\ if((v{1}.a|v{1}.b|v{1}.c|v{1}.d)!=0u) {{
                \\   if((v{2}.b|v{2}.c|v{2}.d)!=0u || v{2}.a>=65536u) atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
                \\   else if(range_inverses[262144u+v{2}.a]!=0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
                \\   else v{0}=riscv_qm_mul(v{1},riscv_load_qm31(range_inverses,4u*v{2}.a));
                \\ }}
                \\
            , .{ index, node.lhs, node.rhs }),
        }
    }
}
