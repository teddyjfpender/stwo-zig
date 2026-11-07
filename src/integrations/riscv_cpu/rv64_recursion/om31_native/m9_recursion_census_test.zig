//! M9 recursion-arch: exact per-child verifier rows by phase, production
//! profile pinned to the unmodified `V.verify`, plus what-if PCS variants.
//! Prints one `M9_RECURSION_CENSUS {json}` line per (child, variant).
//! Run: zig build test-riscv64-m9-recursion-census (cwd = repo root).
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const K = @import("m9_recursion_census.zig");
const Summary = @import("node_summary_v3.zig");
const Fin = circuit.common.finalize;

/// Padded component sizes of the two child classes a 4-ary fold verifies
/// (RECURSION_NODE_SHAPE rows of the D2 receipts, rounded up):
/// a CPU leaf (raw 179,654 / 5,533,212 / 337,632 / 875,134 / 3,376,320) and
/// a 4-ary fold of log-23 children (4 x 14,261 / 1,750,349 / 194,178 /
/// 358,416 / 1,941,780).
const cpu_leaf = Fin.ComponentSizes{ .eq = 1 << 18, .qm31_ops = 1 << 23, .triple_xor = 1 << 19, .m31_to_u32 = 1 << 20, .blake_g_gate = 1 << 22 };
const fold4 = Fin.ComponentSizes{ .eq = 1 << 16, .qm31_ops = 1 << 23, .triple_xor = 1 << 20, .m31_to_u32 = 1 << 21, .blake_g_gate = 1 << 23 };
/// A pair leaf (k-leaf fan-in) reaches a 2^24 qm31_ops column.
const pair_leaf = Fin.ComponentSizes{ .eq = 1 << 19, .qm31_ops = 1 << 24, .triple_xor = 1 << 20, .m31_to_u32 = 1 << 21, .blake_g_gate = 1 << 23 };

const Case = struct { name: []const u8, v: K.Variant, check: bool = false, all_children: bool = false };
const production = K.Variant{};
/// Combined outer-profile candidate without batching: q102/P26 (2*... see doc),
/// Blake3 commitments, whole-coset FRI leaves.
const combo = K.Variant{ .n_queries = 102, .pow_bits = 26, .hash = .blake3, .fri_coset_leaf = true };
const cases = [_]Case{
    .{ .name = "prod_b2_q108_p20_f4_cap3", .v = production, .check = true, .all_children = true },
    .{ .name = "b2_q108_p20_f4_cap0", .v = .{ .cap_log = 0 }, .check = true },
    .{ .name = "b2_q108_p20_f4_cap4", .v = .{ .cap_log = 4 }, .check = true },
    .{ .name = "b2_q108_p20_f4_cap5", .v = .{ .cap_log = 5 }, .check = true },
    .{ .name = "b2_q108_p20_f4_cap7", .v = .{ .cap_log = 7 } },
    .{ .name = "b2_q108_p20_f3_cap3", .v = .{ .fold_step = 3 } },
    .{ .name = "b2_q108_p20_f4_cap3_ll2", .v = .{ .log_last_layer = 2 } },
    .{ .name = "b2_q108_p20_f4_cap3_ll4", .v = .{ .log_last_layer = 4 } },
    .{ .name = "b2_q108_p20_f4_cap3_ll6", .v = .{ .log_last_layer = 6 } },
    .{ .name = "b2_q108_p20_f4_cap3_ll8", .v = .{ .log_last_layer = 8 } },
    .{ .name = "b2_q102_p26_f4_cap3", .v = .{ .n_queries = 102, .pow_bits = 26 }, .all_children = true },
    .{ .name = "b2_q100_p28_f4_cap3", .v = .{ .n_queries = 100, .pow_bits = 28 } },
    .{ .name = "b4_q54_p20_f4_cap3", .v = .{ .log_blowup = 2, .n_queries = 54 } },
    .{ .name = "b8_q36_p20_f4_cap3", .v = .{ .log_blowup = 3, .n_queries = 36 } },
    .{ .name = "blake3_cap3", .v = .{ .hash = .blake3 }, .all_children = true },
    .{ .name = "cosetleaf_cap3", .v = .{ .fri_coset_leaf = true }, .all_children = true },
    .{ .name = "blake3_cosetleaf_cap3", .v = .{ .hash = .blake3, .fri_coset_leaf = true } },
    .{ .name = "combo_q102_p26_blake3_coset", .v = combo, .all_children = true },
    .{ .name = "combo_q102_p26_blake3_coset_ll4", .v = .{ .n_queries = 102, .pow_bits = 26, .hash = .blake3, .fri_coset_leaf = true, .log_last_layer = 4 }, .all_children = true },
    .{ .name = "blake3_q102_p26_cap3", .v = .{ .n_queries = 102, .pow_bits = 26, .hash = .blake3 } },
    .{ .name = "cosetleaf_ll4_cap3", .v = .{ .fri_coset_leaf = true, .log_last_layer = 4 } },
    .{ .name = "batch2_cap3", .v = .{ .batch = 2 } },
    .{ .name = "batch4_cap3", .v = .{ .batch = 4 }, .all_children = true },
    .{ .name = "batch3_cap3", .v = .{ .batch = 3 } },
    .{ .name = "batch2_combo_ll4", .v = .{ .batch = 2, .n_queries = 102, .pow_bits = 26, .hash = .blake3, .fri_coset_leaf = true, .log_last_layer = 4 }, .all_children = true },
    .{ .name = "batch3_combo_ll4", .v = .{ .batch = 3, .n_queries = 102, .pow_bits = 26, .hash = .blake3, .fri_coset_leaf = true, .log_last_layer = 4 } },
    .{ .name = "batch4_combo_ll4", .v = .{ .batch = 4, .n_queries = 102, .pow_bits = 26, .hash = .blake3, .fri_coset_leaf = true, .log_last_layer = 4 }, .all_children = true },
    .{ .name = "combo_q102_p26_blake3_coset_ll8", .v = .{ .n_queries = 102, .pow_bits = 26, .hash = .blake3, .fri_coset_leaf = true, .log_last_layer = 8 } },
    .{ .name = "batch4_q102_p26_cosetleaf", .v = .{ .batch = 4, .n_queries = 102, .pow_bits = 26, .fri_coset_leaf = true } },
    .{ .name = "batch4_combo", .v = .{ .batch = 4, .n_queries = 102, .pow_bits = 26, .hash = .blake3, .fri_coset_leaf = true }, .all_children = true },
};

fn emit(child: []const u8, case: Case, r: K.Result, prod: ?K.Rows) void {
    const names = [_][]const u8{ "ingress", "transcript", "composition", "trace_leaf", "trace_path", "deep", "fri_leaf", "fri_path", "fri_fold" };
    std.debug.print("M9_RECURSION_CENSUS {{\"child\":\"{s}\",\"variant\":\"{s}\",\"log_blowup\":{},\"queries\":{},\"pow\":{},\"fold_step\":{},\"last_layer_log\":{},\"cap_log\":{},\"hash\":\"{s}\",\"fri_coset_leaf\":{},\"batch\":{},\"lifting_log\":{},\"fri_layers\":{},", .{ child, case.name, case.v.log_blowup, case.v.n_queries, case.v.pow_bits, case.v.fold_step, case.v.log_last_layer, case.v.cap_log, @tagName(case.v.hash), case.v.fri_coset_leaf, case.v.batch, r.census.lifting_log, r.census.n_fri_layers });
    std.debug.print("\"hash_calls\":{{\"trace_leaf\":{},\"trace_path\":{},\"fri_leaf\":{},\"fri_path\":{}}},", .{ r.census.trace_leaf_hashes, r.census.trace_path_nodes, r.census.fri_leaf_hashes, r.census.fri_path_nodes });
    std.debug.print("\"phases\":{{", .{});
    for (r.census.phases, names, 0..) |p, n, i| std.debug.print("{s}\"{s}\":[{},{},{},{},{},{}]", .{ if (i == 0) "" else ",", n, p.eq, p.qm31_ops, p.triple_xor, p.m31_to_u32, p.blake_g_gate, p.cells() });
    const t = r.total;
    std.debug.print("}},\"total\":[{},{},{},{},{},{}]", .{ t.eq, t.qm31_ops, t.triple_xor, t.m31_to_u32, t.blake_g_gate, t.cells() });
    if (prod) |p| std.debug.print(",\"production_verify\":[{},{},{},{},{},{}],\"production_match\":{}", .{ p.eq, p.qm31_ops, p.triple_xor, p.m31_to_u32, p.blake_g_gate, p.cells(), std.meta.eql(p, t) });
    std.debug.print("}}\n", .{});
}

test "M9 recursion census: per-child verifier rows by phase and PCS variant" {
    const a = std.heap.page_allocator;
    const g = try K.gRowsPerCompression(a);
    const node = try K.nodeRows(a);
    const n3 = try K.nodeRowsFor(a, .blake3);
    std.debug.print("M9_RECURSION_CENSUS {{\"g_rows_per_compression\":{},\"merkle_node_rows_blake2s\":[{},{},{},{},{},{}],\"node_rows_blake3\":[{},{},{},{},{},{}]}}\n", .{ g, node.eq, node.qm31_ops, node.triple_xor, node.m31_to_u32, node.blake_g_gate, node.cells(), n3.eq, n3.qm31_ops, n3.triple_xor, n3.m31_to_u32, n3.blake_g_gate, n3.cells() });
    const only = std.posix.getenv("STWO_RV64_M9_RECURSION_CENSUS_ONLY");
    const children = [_]struct { name: []const u8, sizes: Fin.ComponentSizes }{ .{ .name = "fold4_log23", .sizes = fold4 }, .{ .name = "cpu_leaf_log23", .sizes = cpu_leaf }, .{ .name = "pair_leaf_log24", .sizes = pair_leaf } };
    for (children, 0..) |child, ci| for (cases) |case| {
        // Full variant sweep on the fold child; production-only on the others.
        if (ci != 0 and !case.all_children) continue;
        if (only) |o| if (std.mem.indexOf(u8, case.name, o) == null) continue;
        var prod: K.Rows = undefined;
        const r = try K.measureChild(a, child.sizes, Summary.N_WORDS, case.v, if (case.check) &prod else null);
        emit(child.name, case, r, if (case.check) prod else null);
        if (case.check) try std.testing.expect(std.meta.eql(prod, r.total));
    };
}
